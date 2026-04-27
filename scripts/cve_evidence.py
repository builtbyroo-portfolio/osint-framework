#!/usr/bin/env python3
"""Phase 6 helper: Capture evidence — screenshots, curl output, response headers."""
import argparse
import json
import subprocess
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def capture_screenshot_selenium(url, output_path, width=1920, height=1080):
    """Capture screenshot using Selenium (Firefox headless)."""
    try:
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.service import Service

        options = Options()
        options.add_argument('--headless')
        options.add_argument(f'--width={width}')
        options.add_argument(f'--height={height}')

        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(15)

        try:
            driver.get(url)
            time.sleep(2)  # Let JS render
            driver.save_screenshot(str(output_path))
            return True
        except Exception as e:
            print(f"  Screenshot error for {url}: {e}", file=sys.stderr)
            return False
        finally:
            driver.quit()
    except ImportError:
        print("  Selenium not available, skipping screenshot", file=sys.stderr)
        return False


def capture_screenshot_chromium(url, output_path):
    """Capture screenshot using headless Chromium."""
    try:
        result = subprocess.run([
            'chromium', '--headless', '--disable-gpu', '--no-sandbox',
            '--window-size=1920,1080',
            f'--screenshot={output_path}',
            url
        ], capture_output=True, timeout=20)
        return result.returncode == 0 and Path(output_path).exists()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def capture_curl_evidence(url, output_path, extra_headers=None):
    """Capture full curl response with headers."""
    cmd = ['curl', '-sk', '-D-', '-o', '-', '--max-time', '10']
    if extra_headers:
        for k, v in extra_headers.items():
            cmd.extend(['-H', f'{k}: {v}'])
    cmd.append(url)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        with open(output_path, 'w') as f:
            f.write(f"# curl command: {' '.join(cmd)}\n")
            f.write(f"# captured: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
            f.write(result.stdout[:50000])
        return True
    except (subprocess.TimeoutExpired, Exception) as e:
        print(f"  Curl error for {url}: {e}", file=sys.stderr)
        return False


def capture_nmap_evidence(host, port, output_path):
    """Run targeted nmap service scan for version evidence."""
    try:
        result = subprocess.run([
            'nmap', '-sV', '-sC', '-p', str(port),
            '--script', 'banner,http-server-header,http-title',
            '-oN', str(output_path),
            host
        ], capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validated', required=True, help='Validated CVEs JSON from Phase 5')
    parser.add_argument('--screenshot-dir', required=True, help='Screenshot output directory')
    parser.add_argument('--evidence-dir', required=True, help='Evidence output directory')
    parser.add_argument('--method', default='selenium', choices=['selenium', 'chromium'],
                        help='Screenshot method')
    args = parser.parse_args()

    validated_path = Path(args.validated)
    if not validated_path.exists():
        print("Validated CVEs file not found")
        return

    ss_dir = Path(args.screenshot_dir)
    ev_dir = Path(args.evidence_dir)
    ss_dir.mkdir(parents=True, exist_ok=True)
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / 'curl_responses').mkdir(exist_ok=True)

    with open(validated_path) as f:
        validated = json.load(f)

    # Only capture evidence for validated or high-value CVEs
    to_capture = [
        v for v in validated
        if v.get('validation', {}).get('validated')
        or v.get('in_kev')
        or v.get('cvss_score', 0) >= 9.0
    ]

    print(f"Capturing evidence for {len(to_capture)} CVEs...")

    screenshot_fn = capture_screenshot_selenium if args.method == 'selenium' else capture_screenshot_chromium

    evidence_manifest = []

    for entry in to_capture:
        cve_id = entry['cve_id']
        tech = entry.get('technology', 'unknown')
        hosts = entry.get('hosts', [])
        safe_cve = cve_id.replace('-', '_')

        print(f"  {cve_id} ({tech})...")

        cve_evidence = {
            'cve_id': cve_id,
            'technology': tech,
            'screenshots': [],
            'curl_files': [],
            'nmap_files': [],
        }

        for i, host in enumerate(hosts[:2]):
            # Normalize to URL
            if not host.startswith('http'):
                base_url = f"https://{host}"
            else:
                base_url = host.rstrip('/')

            # Screenshot
            ss_file = ss_dir / f"{safe_cve}_{i}.png"
            if screenshot_fn(base_url, str(ss_file)):
                cve_evidence['screenshots'].append(str(ss_file))
                print(f"    Screenshot: {ss_file.name}")

            # Curl evidence (full response with headers)
            curl_file = ev_dir / 'curl_responses' / f"{safe_cve}_{i}_response.txt"
            if capture_curl_evidence(base_url, str(curl_file)):
                cve_evidence['curl_files'].append(str(curl_file))

            # If validation found specific paths, capture those too
            validation = entry.get('validation', {})
            for check in validation.get('checks_run', []):
                if check.get('validated'):
                    check_url = check.get('url', '')
                    if check_url and check_url != base_url:
                        curl_path_file = ev_dir / 'curl_responses' / f"{safe_cve}_{i}_path.txt"
                        capture_curl_evidence(check_url, str(curl_path_file))
                        cve_evidence['curl_files'].append(str(curl_path_file))

                        # Screenshot the specific vulnerable path
                        ss_path_file = ss_dir / f"{safe_cve}_{i}_path.png"
                        screenshot_fn(check_url, str(ss_path_file))
                        cve_evidence['screenshots'].append(str(ss_path_file))

            # Extract host:port for nmap
            import re
            m = re.match(r'https?://([^:/]+)(?::(\d+))?', base_url)
            if m:
                nmap_host = m.group(1)
                nmap_port = m.group(2) or ('443' if base_url.startswith('https') else '80')
                nmap_file = ev_dir / f"{safe_cve}_{i}_nmap.txt"
                if capture_nmap_evidence(nmap_host, nmap_port, str(nmap_file)):
                    cve_evidence['nmap_files'].append(str(nmap_file))

        evidence_manifest.append(cve_evidence)

    # Save evidence manifest
    manifest_file = ev_dir / 'evidence_manifest.json'
    with open(manifest_file, 'w') as f:
        json.dump(evidence_manifest, f, indent=2)

    total_ss = sum(len(e['screenshots']) for e in evidence_manifest)
    total_curl = sum(len(e['curl_files']) for e in evidence_manifest)
    print(f"\nEvidence captured: {total_ss} screenshots, {total_curl} curl responses")


if __name__ == '__main__':
    main()
