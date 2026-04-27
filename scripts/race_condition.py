#!/usr/bin/env python3
"""
race_condition.py — Race Condition / TOCTOU Tester
Fires N concurrent identical requests to detect race conditions.

Detection logic:
  - All-200 when only one should succeed (duplicate redemptions)
  - Duplicate side effects (multiple credits, votes, etc.)
  - Timing anomalies (response time variance suggesting lock contention)
  - Different response bodies suggesting state changes mid-race

Uses aiohttp + asyncio.gather for true concurrent requests.

Usage:
  python3 race_condition.py -i targets.txt -o findings.txt -t 20
  python3 race_condition.py -i targets.txt -o /dev/stdout --dry-run
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from collections import Counter

try:
    import aiohttp
except ImportError:
    print("[ERROR] aiohttp required: pip install aiohttp", file=sys.stderr)
    sys.exit(1)

DEFAULT_HEADERS = {
    "User-Agent": "noleak",
    "Accept": "application/json, text/html, */*",
}
TIMEOUT = 15


async def fire_concurrent(url, method, n_requests, headers=None, json_data=None):
    """Fire N truly concurrent requests and collect responses."""
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)

    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    connector = aiohttp.TCPConnector(ssl=False, limit=n_requests)

    results = []

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=hdrs
    ) as session:
        async def single_request(idx):
            start = time.monotonic()
            try:
                kwargs = {}
                if json_data:
                    kwargs["json"] = json_data

                async with session.request(method, url, **kwargs) as resp:
                    body = await resp.text()
                    elapsed = time.monotonic() - start
                    return {
                        "idx": idx,
                        "status": resp.status,
                        "size": len(body),
                        "body_hash": hash(body[:500]),
                        "elapsed": round(elapsed, 3),
                        "headers": dict(resp.headers),
                    }
            except Exception as e:
                elapsed = time.monotonic() - start
                return {
                    "idx": idx,
                    "status": 0,
                    "size": 0,
                    "body_hash": 0,
                    "elapsed": round(elapsed, 3),
                    "error": str(e),
                }

        # Fire all requests simultaneously using gather
        tasks = [single_request(i) for i in range(n_requests)]
        results = await asyncio.gather(*tasks)

    return list(results)


def analyze_race_results(url, results, n_requests):
    """Analyze concurrent request results for race conditions."""
    findings = []

    # Filter out errors
    valid = [r for r in results if r["status"] > 0]
    errors = [r for r in results if r["status"] == 0]

    if not valid:
        return findings

    # Count status codes
    status_counts = Counter(r["status"] for r in valid)
    success_count = sum(1 for r in valid if r["status"] in (200, 201, 204))
    body_hashes = Counter(r["body_hash"] for r in valid)
    unique_bodies = len(body_hashes)

    # Timing analysis
    times = [r["elapsed"] for r in valid]
    avg_time = statistics.mean(times)
    time_stdev = statistics.stdev(times) if len(times) > 1 else 0

    # ── Detection: All requests succeed (should be idempotent) ──
    if success_count == len(valid) and success_count >= n_requests * 0.8:
        if unique_bodies == 1:
            # All same response — might be idempotent, lower confidence
            findings.append(
                f"[P3:RACE:MED] ALL_SUCCESS {url} | "
                f"{success_count}/{len(valid)} returned 200 (identical responses) | "
                f"avg_time={avg_time:.3f}s | Verify if side effects duplicated"
            )
        else:
            # Different responses — strong race signal
            findings.append(
                f"[P2:RACE:HIGH] ALL_SUCCESS_DIFFERENT {url} | "
                f"{success_count}/{len(valid)} returned 200 with {unique_bodies} unique responses | "
                f"avg_time={avg_time:.3f}s | State changed during concurrent requests"
            )

    # ── Detection: Mixed status codes (some succeed, some fail) ──
    if len(status_counts) > 1 and success_count > 1:
        status_str = " ".join(f"{s}:{c}" for s, c in sorted(status_counts.items()))
        if success_count > 1 and any(
            r["status"] in (409, 429, 403, 422) for r in valid
        ):
            findings.append(
                f"[P2:RACE:HIGH] PARTIAL_SUCCESS {url} | "
                f"Mixed results: {status_str} | "
                f"{success_count} succeeded (expected max 1) | "
                f"Race window: stdev={time_stdev:.3f}s"
            )

    # ── Detection: Timing anomaly (lock contention) ──
    if time_stdev > 1.0 and success_count > 0:
        # High variance suggests some requests waited for locks
        fastest = min(times)
        slowest = max(times)
        findings.append(
            f"[P3:RACE:MED] TIMING_ANOMALY {url} | "
            f"Response time variance: {fastest:.3f}s-{slowest:.3f}s (stdev={time_stdev:.3f}s) | "
            f"Possible lock contention — investigate for TOCTOU"
        )

    # ── Detection: 200 responses with different sizes ──
    success_results = [r for r in valid if r["status"] in (200, 201)]
    if len(success_results) > 1:
        sizes = [r["size"] for r in success_results]
        if len(set(sizes)) > 1:
            min_size = min(sizes)
            max_size = max(sizes)
            if max_size > min_size * 1.5 and max_size - min_size > 100:
                findings.append(
                    f"[P2:RACE:HIGH] SIZE_VARIANCE {url} | "
                    f"Success response sizes vary: {min_size}B-{max_size}B | "
                    f"Data changed during concurrent access"
                )

    return findings


async def test_endpoint(url, n_requests):
    """Test a single endpoint for race conditions."""
    all_findings = []

    # Test GET race
    results = await fire_concurrent(url, "GET", n_requests)
    all_findings.extend(analyze_race_results(url, results, n_requests))

    # Test POST race (with empty body — generic action trigger)
    results_post = await fire_concurrent(url, "POST", n_requests, json_data={})
    all_findings.extend(analyze_race_results(url, results_post, n_requests))

    return all_findings


async def run_all(urls, n_requests):
    """Run race condition tests on all URLs."""
    all_findings = []
    total = len(urls)

    for i, url in enumerate(urls, 1):
        if i % 5 == 0 or i == 1:
            print(f"[*] Progress: {i}/{total} endpoints")

        try:
            findings = await test_endpoint(url, n_requests)
            for f in findings:
                print(f"  {f}")
                all_findings.append(f)
        except Exception as e:
            print(f"  [ERROR] {url}: {e}")

        # Small delay between endpoints to avoid overwhelming targets
        if i < total:
            await asyncio.sleep(0.5)

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Race Condition / TOCTOU Tester"
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
        help="Number of concurrent requests per test (default: 20)"
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

    print(f"[*] Loaded {len(urls)} race-prone endpoint(s)")
    print(f"[*] Concurrent requests per test: {args.threads}")

    if args.dry_run:
        for url in urls:
            print(f"[DRY-RUN] {url}")
        return

    # Run async race tests
    all_findings = asyncio.run(run_all(urls, args.threads))

    # Write output
    if args.output and all_findings:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    p2 = sum(1 for f in all_findings if "[P2:" in f)
    print(f"\n[*] Scan complete: {len(urls)} endpoints, "
          f"{len(all_findings)} findings ({p2} high-confidence)")


if __name__ == "__main__":
    main()
