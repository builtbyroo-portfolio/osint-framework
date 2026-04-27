#!/usr/bin/env python3
"""Phase 3 helper: Query NVD API and CISA KEV for CVEs matching discovered versions."""
import argparse
import json
import time
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote
from urllib.error import HTTPError, URLError

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Rate limits: 5 req/30s without key, 50 req/30s with key
RATE_LIMIT_DELAY = 6.5  # seconds between requests (no key)
RATE_LIMIT_DELAY_KEY = 0.6  # seconds with API key


def fetch_json(url, headers=None, timeout=30):
    """Fetch JSON from URL with error handling."""
    req = Request(url, headers=headers or {})
    req.add_header('User-Agent', 'cve-hunter/1.0')
    try:
        resp = urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode('utf-8'))
    except HTTPError as e:
        if e.code == 403:
            print(f"  Rate limited, waiting 30s...", file=sys.stderr)
            time.sleep(30)
            resp = urlopen(req, timeout=timeout)
            return json.loads(resp.read().decode('utf-8'))
        raise
    except (URLError, TimeoutError) as e:
        print(f"  Fetch error: {e}", file=sys.stderr)
        return None


def fetch_cisa_kev():
    """Download CISA Known Exploited Vulnerabilities catalog."""
    print("Fetching CISA KEV catalog...")
    data = fetch_json(CISA_KEV_URL, timeout=60)
    if data and 'vulnerabilities' in data:
        # Index by CVE ID
        return {v['cveID']: v for v in data['vulnerabilities']}
    return {}


def query_nvd_by_cpe(cpe_string, api_key=None):
    """Query NVD API for CVEs matching a CPE string."""
    params = {
        'cpeName': cpe_string,
        'resultsPerPage': 50,
    }
    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    url = f"{NVD_API}?{urlencode(params)}"
    return fetch_json(url, headers=headers)


def query_nvd_by_keyword(keyword, api_key=None):
    """Query NVD API by keyword search."""
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 50,
    }
    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    url = f"{NVD_API}?{urlencode(params)}"
    return fetch_json(url, headers=headers)


def extract_cve_info(vuln_item):
    """Extract relevant info from NVD vulnerability item."""
    cve = vuln_item.get('cve', {})
    cve_id = cve.get('id', '')
    descriptions = cve.get('descriptions', [])
    desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

    # Extract CVSS scores
    metrics = cve.get('metrics', {})
    cvss31 = None
    cvss_score = 0
    severity = 'UNKNOWN'

    # Try CVSS 3.1 first, then 3.0, then 2.0
    for metric_key in ['cvssMetricV31', 'cvssMetricV30']:
        if metric_key in metrics and metrics[metric_key]:
            m = metrics[metric_key][0]
            cvss_data = m.get('cvssData', {})
            cvss_score = cvss_data.get('baseScore', 0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            cvss31 = cvss_data.get('vectorString', '')
            break

    if not cvss31 and 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        m = metrics['cvssMetricV2'][0]
        cvss_data = m.get('cvssData', {})
        cvss_score = cvss_data.get('baseScore', 0)
        severity = m.get('baseSeverity', 'UNKNOWN')

    # Extract affected CPE configurations
    affected_cpes = []
    configs = cve.get('configurations', [])
    for config in configs:
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable'):
                    affected_cpes.append({
                        'cpe': match.get('criteria', ''),
                        'versionStartIncluding': match.get('versionStartIncluding'),
                        'versionEndExcluding': match.get('versionEndExcluding'),
                        'versionEndIncluding': match.get('versionEndIncluding'),
                    })

    # Extract references
    refs = cve.get('references', [])
    ref_urls = [r.get('url', '') for r in refs[:5]]

    # Check for known exploit tags
    has_exploit = any(
        'Exploit' in (r.get('tags', []) if isinstance(r.get('tags'), list) else [])
        for r in refs
    )

    return {
        'cve_id': cve_id,
        'description': desc[:500],
        'cvss_score': cvss_score,
        'severity': severity,
        'cvss_vector': cvss31 or '',
        'affected_cpes': affected_cpes,
        'references': ref_urls,
        'has_exploit_ref': has_exploit,
        'published': cve.get('published', ''),
        'modified': cve.get('lastModified', ''),
    }


def version_in_range(version, cpe_match):
    """Check if a version falls within an affected range."""
    from packaging.version import Version, InvalidVersion

    try:
        v = Version(version)
    except (InvalidVersion, Exception):
        return True  # Can't parse — assume possibly affected

    start = cpe_match.get('versionStartIncluding')
    end_excl = cpe_match.get('versionEndExcluding')
    end_incl = cpe_match.get('versionEndIncluding')

    try:
        if start and v < Version(start):
            return False
        if end_excl and v >= Version(end_excl):
            return False
        if end_incl and v > Version(end_incl):
            return False
    except (InvalidVersion, Exception):
        return True

    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version-map', required=True, help='Version map JSON from Phase 2')
    parser.add_argument('--output', required=True, help='Output CVE matches JSON')
    parser.add_argument('--kev-output', required=True, help='Output KEV matches JSON')
    parser.add_argument('--nvd-key', default='', help='NVD API key for higher rate limit')
    args = parser.parse_args()

    version_map_path = Path(args.version_map)
    if not version_map_path.exists():
        print("Version map not found")
        for out in [args.output, args.kev_output]:
            with open(out, 'w') as f:
                json.dump([], f)
        return

    with open(version_map_path) as f:
        version_map = json.load(f)

    # Fetch CISA KEV
    kev_catalog = fetch_cisa_kev()
    print(f"CISA KEV: {len(kev_catalog)} known exploited vulnerabilities loaded")

    delay = RATE_LIMIT_DELAY_KEY if args.nvd_key else RATE_LIMIT_DELAY
    all_cves = []
    kev_matches = []
    seen_cves = set()

    for entry in version_map:
        if not entry.get('mapped') or not entry.get('cpe_queries'):
            continue

        tech = entry['technology']
        print(f"Querying NVD for: {tech}")

        for query in entry['cpe_queries']:
            version = query.get('version', '*')
            cpe = query.get('cpe', '')
            keyword = query.get('keyword', '')

            # Try CPE match first, fall back to keyword
            result = None
            if cpe and version != '*':
                result = query_nvd_by_cpe(cpe, api_key=args.nvd_key or None)
                time.sleep(delay)

            if not result or result.get('totalResults', 0) == 0:
                if keyword:
                    result = query_nvd_by_keyword(keyword, api_key=args.nvd_key or None)
                    time.sleep(delay)

            if not result:
                continue

            vulns = result.get('vulnerabilities', [])
            print(f"  {tech} {version}: {len(vulns)} CVEs")

            for vuln_item in vulns:
                cve_info = extract_cve_info(vuln_item)
                cve_id = cve_info['cve_id']

                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                # Skip low-severity unless it's in KEV
                if cve_info['cvss_score'] < 4.0 and cve_id not in kev_catalog:
                    continue

                cve_info['technology'] = tech
                cve_info['detected_version'] = version
                cve_info['hosts'] = entry.get('hosts', [])[:5]
                cve_info['in_kev'] = cve_id in kev_catalog

                if cve_info['in_kev']:
                    kev_data = kev_catalog[cve_id]
                    cve_info['kev_data'] = {
                        'vendor': kev_data.get('vendorProject', ''),
                        'product': kev_data.get('product', ''),
                        'action': kev_data.get('requiredAction', ''),
                        'due_date': kev_data.get('dueDate', ''),
                        'known_ransomware': kev_data.get('knownRansomwareCampaignUse', ''),
                    }
                    kev_matches.append(cve_info)

                all_cves.append(cve_info)

    # Sort by CVSS score descending, KEV first
    all_cves.sort(key=lambda x: (0 if x.get('in_kev') else 1, -x['cvss_score']))

    with open(args.output, 'w') as f:
        json.dump(all_cves, f, indent=2)

    with open(args.kev_output, 'w') as f:
        json.dump(kev_matches, f, indent=2)

    high = sum(1 for c in all_cves if c['cvss_score'] >= 7.0)
    crit = sum(1 for c in all_cves if c['cvss_score'] >= 9.0)
    print(f"\nTotal: {len(all_cves)} CVEs ({crit} critical, {high} high, {len(kev_matches)} in CISA KEV)")


if __name__ == '__main__':
    main()
