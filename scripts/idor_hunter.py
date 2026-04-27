#!/usr/bin/env python3
"""
idor_hunter.py — IDOR / Broken Access Control Scanner
Tests API endpoints for:
  - Auth removal: strip Authorization header, check if data still accessible
  - ID manipulation: increment/decrement path params, test 0/1/max_int
  - Horizontal access: swap user tokens (--token-a / --token-b)
  - Method switching: GET→POST→PUT→DELETE→PATCH on each endpoint

Usage:
  python3 idor_hunter.py -i api_urls.txt -o findings.txt -t 20
  python3 idor_hunter.py -i api_urls.txt -o /dev/stdout --token-a "Bearer ey..." --token-b "Bearer ey..."
  python3 idor_hunter.py -i api_urls.txt -o /dev/stdout --dry-run
"""

import argparse
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {"User-Agent": "noleak"}
TIMEOUT = 10
MAX_BODY_PREVIEW = 200

# Patterns for ID segments in URLs
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
NUMERIC_RE = re.compile(r"^[0-9]+$")

# Methods to test
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# ID manipulation values
ID_REPLACEMENTS_NUMERIC = ["0", "1", "2", "99999", "2147483647", "-1"]
ID_REPLACEMENTS_UUID = [
    "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000001",
]


def safe_request(method, url, headers=None, timeout=TIMEOUT):
    """Make an HTTP request with error handling."""
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.request(
            method, url, headers=hdrs, allow_redirects=False,
            timeout=timeout, verify=False
        )
        return resp.status_code, len(resp.text), resp.text[:MAX_BODY_PREVIEW]
    except requests.RequestException:
        return None, 0, ""


def get_baseline(url, token=None):
    """Get baseline response for a URL with auth."""
    headers = {}
    if token:
        if token.lower().startswith("bearer "):
            headers["Authorization"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
    status, size, body = safe_request("GET", url, headers)
    return status, size, body


def is_meaningful_response(status, size, baseline_status=None):
    """Check if response indicates actual data access."""
    if status is None:
        return False
    if status in (200, 201) and size > 50:
        return True
    if baseline_status and status != baseline_status and status in (200, 201):
        return True
    return False


def test_auth_removal(url, token):
    """Test: remove auth header entirely."""
    findings = []
    if not token:
        return findings

    # Baseline with auth
    auth_status, auth_size, _ = get_baseline(url, token)

    # Request without auth
    noauth_status, noauth_size, noauth_body = safe_request("GET", url)

    if noauth_status and noauth_status in (200, 201) and noauth_size > 50:
        # Compare: if unauthed response is similar to authed, it's an IDOR
        if auth_status in (200, 201):
            # Both succeed — check if responses are similar (shared data)
            size_ratio = min(auth_size, noauth_size) / max(auth_size, noauth_size, 1)
            if size_ratio > 0.5:
                findings.append(
                    f"[P1:IDOR:HIGH] AUTH_REMOVAL {url} | "
                    f"authed={auth_status}/{auth_size}B unauthed={noauth_status}/{noauth_size}B | "
                    f"Data accessible without authentication"
                )
        else:
            # Auth returns error but unauthed returns data — very suspicious
            findings.append(
                f"[P1:IDOR:HIGH] AUTH_REMOVAL {url} | "
                f"authed={auth_status} unauthed={noauth_status}/{noauth_size}B | "
                f"Unauthed returns data while authed fails"
            )

    return findings


def test_id_manipulation(url):
    """Test: modify numeric/UUID segments in the URL path."""
    findings = []
    parsed = urlparse(url)
    path_parts = parsed.path.strip("/").split("/")

    for i, part in enumerate(path_parts):
        replacements = []
        original_type = None

        if NUMERIC_RE.match(part):
            original_type = "numeric"
            replacements = [r for r in ID_REPLACEMENTS_NUMERIC if r != part]
        elif UUID_RE.match(part):
            original_type = "uuid"
            replacements = [r for r in ID_REPLACEMENTS_UUID if r.lower() != part.lower()]
        else:
            continue

        # Get baseline for original URL
        orig_status, orig_size, _ = safe_request("GET", url)

        for replacement in replacements:
            new_parts = list(path_parts)
            new_parts[i] = replacement
            new_path = "/" + "/".join(new_parts)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment
            ))

            mod_status, mod_size, mod_body = safe_request("GET", new_url)

            if mod_status in (200, 201) and mod_size > 50:
                # Check if it returns different data (true IDOR)
                if orig_status in (200, 201) and mod_size != orig_size:
                    findings.append(
                        f"[P1:IDOR:HIGH] ID_MANIPULATION {new_url} | "
                        f"original={part} replaced={replacement} | "
                        f"orig_size={orig_size}B mod_size={mod_size}B | "
                        f"Different data returned for different ID"
                    )
                elif orig_status in (200, 201):
                    findings.append(
                        f"[P2:IDOR:MED] ID_MANIPULATION {new_url} | "
                        f"original={part} replaced={replacement} | "
                        f"Both return {mod_status} ({mod_size}B) — verify manually"
                    )

    return findings


def test_horizontal_access(url, token_a, token_b):
    """Test: swap user tokens to check horizontal privilege escalation."""
    findings = []
    if not token_a or not token_b:
        return findings

    def make_auth_header(token):
        if token.lower().startswith("bearer "):
            return {"Authorization": token}
        return {"Authorization": f"Bearer {token}"}

    # Request with token A
    a_status, a_size, a_body = safe_request("GET", url, make_auth_header(token_a))
    # Request with token B
    b_status, b_size, b_body = safe_request("GET", url, make_auth_header(token_b))

    if a_status in (200, 201) and b_status in (200, 201):
        if a_size > 50 and b_size > 50:
            # Both users can access — check if data differs
            if a_body != b_body:
                findings.append(
                    f"[P1:IDOR:HIGH] HORIZONTAL_ACCESS {url} | "
                    f"tokenA={a_status}/{a_size}B tokenB={b_status}/{b_size}B | "
                    f"Different data per user — cross-user data access"
                )
            else:
                findings.append(
                    f"[P3:IDOR:LOW] HORIZONTAL_ACCESS {url} | "
                    f"Both tokens return identical {a_status}/{a_size}B — likely shared resource"
                )

    return findings


def test_method_switching(url):
    """Test: try different HTTP methods on the endpoint."""
    findings = []

    # Baseline GET
    get_status, get_size, _ = safe_request("GET", url)

    for method in ["POST", "PUT", "DELETE", "PATCH"]:
        m_status, m_size, m_body = safe_request(method, url)

        if m_status is None:
            continue

        # DELETE returning 200/204 on a resource is significant
        if method == "DELETE" and m_status in (200, 204):
            findings.append(
                f"[P1:IDOR:HIGH] METHOD_SWITCH {url} | "
                f"DELETE returned {m_status} — potential unauthorized deletion"
            )
        # PUT/PATCH returning 200 could mean unauthorized modification
        elif method in ("PUT", "PATCH") and m_status in (200, 201):
            if get_status in (200, 201) and m_size > 50:
                findings.append(
                    f"[P2:IDOR:MED] METHOD_SWITCH {url} | "
                    f"GET={get_status} {method}={m_status}/{m_size}B — "
                    f"potential unauthorized modification"
                )
        # POST on a GET endpoint returning data
        elif method == "POST" and m_status in (200, 201) and m_size > 50:
            if get_status and get_status >= 400:
                findings.append(
                    f"[P2:IDOR:MED] METHOD_SWITCH {url} | "
                    f"GET={get_status} POST={m_status}/{m_size}B — "
                    f"POST bypasses GET restriction"
                )

    return findings


def test_endpoint(url, token_a=None, token_b=None):
    """Run all IDOR tests on a single endpoint."""
    all_findings = []

    # 1. Auth removal
    all_findings.extend(test_auth_removal(url, token_a or token_b))

    # 2. ID manipulation
    all_findings.extend(test_id_manipulation(url))

    # 3. Horizontal access
    all_findings.extend(test_horizontal_access(url, token_a, token_b))

    # 4. Method switching
    all_findings.extend(test_method_switching(url))

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="IDOR / Broken Access Control Scanner"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Input file with API URLs (one per line)"
    )
    parser.add_argument(
        "-o", "--output", required=False,
        help="Output file for findings (optional)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=20,
        help="Number of threads (default: 20)"
    )
    parser.add_argument(
        "--token-a", default="",
        help="Auth token for user A"
    )
    parser.add_argument(
        "--token-b", default="",
        help="Auth token for user B"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show URLs without testing"
    )
    args = parser.parse_args()

    # Load URLs
    try:
        with open(args.input, "r") as f:
            urls = [line.strip() for line in f if line.strip() and line.strip().startswith("http")]
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("[*] No URLs to test")
        return

    print(f"[*] Loaded {len(urls)} API endpoint(s)")
    if args.token_a:
        print(f"[*] Token A: {args.token_a[:30]}...")
    if args.token_b:
        print(f"[*] Token B: {args.token_b[:30]}...")

    if args.dry_run:
        for url in urls:
            print(f"[DRY-RUN] {url}")
        return

    # Test endpoints
    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_url(url):
        findings = test_endpoint(url, args.token_a, args.token_b)
        with lock:
            completed[0] += 1
            if completed[0] % 50 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(urls)} endpoints tested")
            for f in findings:
                print(f"  {f}")
                all_findings.append(f)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_url, url): url for url in urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"  [ERROR] {futures[future]}: {e}")

    # Write output
    if args.output and all_findings:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    # Summary
    p1 = sum(1 for f in all_findings if "[P1:" in f)
    p2 = sum(1 for f in all_findings if "[P2:" in f)
    print(f"\n[*] Scan complete: {len(urls)} endpoints, "
          f"{len(all_findings)} findings ({p1} P1, {p2} P2)")


if __name__ == "__main__":
    main()
