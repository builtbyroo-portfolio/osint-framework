#!/usr/bin/env python3
"""Impact gate filter — kills findings that match known-rejected patterns.

Based on 25 Bugcrowd submissions, ~19 doomed, 1 confirmed OOS (2026-03-10).
Filters findings BEFORE report generation to prevent wasting time on doomed submissions.

Usage:
  # Filter validated findings JSON (cve.sh pipeline)
  python3 impact_gate.py --input validated_cves.json --output gated_cves.json

  # Filter text findings (hunt.sh pipeline)
  python3 impact_gate.py --input validated_findings.txt --output gated_findings.txt

  # Strict mode: only pass findings with demonstrated exploitation
  python3 impact_gate.py --input findings.json --output gated.json --strict

  # Check against burned programs list
  python3 impact_gate.py --input findings.txt --output gated.txt --program "Indeed"
"""
import argparse
import json
import re
import sys
from pathlib import Path


# ============================================================================
# REJECTION PATTERNS — learned from 25 Bugcrowd submissions (~19 doomed)
# Updated 2026-03-10: 11 source map subs, 5 CORS, 3 takeovers, 3 API docs
# Each pattern has: name, match function, reason, rejection count
# ============================================================================

# Programs where we have burned signal — auto-kill ANY finding for these
BURNED_PROGRAMS = [
    'indeed', 'linktree', 'latitude', 'seek', 'atlassian',
    'okta', 'auth0', 'chime', 'pinterest', 'the trade desk',
    'trade desk', 'tesla', 't-mobile', 'fis', 'comcast',
]

REJECTION_PATTERNS = [
    {
        'name': 'CORS without data theft PoC',
        'rejections': 5,
        'programs': 'Chime, SEEK, Indeed (x2), The Trade Desk',
        'reason': 'CORS only valid with HTML PoC stealing sensitive data from logged-in victim. Ad-tech CORS is by design.',
        'keywords': ['cors', 'cross-origin', 'access-control-allow-origin', 'origin reflection',
                     'cookie-matching', 'ad id linkage'],
        'unless': ['steal', 'exfiltrate', 'session', 'pii', 'token_theft', 'poc.html',
                   'poc_stealing', 'sensitive_data_extracted'],
    },
    {
        'name': 'Source maps / source code exposure',
        'rejections': 11,
        'programs': 'Indeed, Linktree, Latitude (x4), Okta (CONFIRMED OOS -1pt), T-Mobile (x2), Atlassian',
        'reason': 'Source maps NEVER reportable — 11 submissions, 0 accepted, 1 confirmed OOS with -1 signal. '
                  'Self-rating P1 does NOT override VRT. Programs treat deployed JS/maps as public.',
        'keywords': ['source map', 'sourcemap', '.js.map', 'source code expos',
                     'source_map', 'full source', 'application source',
                     'internal api architecture', 'auth logic', 'source code reveal',
                     'backstage', 'admin panel source', 'employer portal source',
                     'fraud detection config'],
        'unless': ['api_key_works', 'credential_valid', 'secret_verified',
                   'remote code execution', 'rce_confirmed', 'account_takeover_confirmed'],
    },
    {
        'name': 'Theoretical subdomain takeover',
        'rejections': 3,
        'programs': 'Tesla (AWS ELB), Latitude Financial (CloudFront x3)',
        'reason': 'Must actually claim subdomain and host proof page. CloudFront takeovers nearly impossible.',
        'keywords': ['subdomain takeover', 'dangling cname', 'dangling dns', 'nxdomain',
                     'dangling heroku', 'dangling elb', 'dangling cloudfront'],
        'unless': ['claimed', 'hosted', 'proof_of_control', 'takeover_confirmed',
                   'proof_page_live'],
    },
    {
        'name': 'Header / IP info disclosure',
        'rejections': 2,
        'programs': 'Tesla, T-Mobile',
        'reason': 'IPs, headers, versions, tech stack = zero impact alone',
        'keywords': ['origin ip', 'internal ip', 'server header', 'x-powered-by',
                     'banner disclosure', 'fingerprint', 'version disclosure',
                     'infrastructure info', 'internal header disclosure'],
        'unless': ['waf_bypass', 'direct_access', 'rce_confirmed', 'remote code execution',
                   'ssrf_internal'],
    },
    {
        'name': 'Clickjacking / CSP injection without sensitive action',
        'rejections': 2,
        'programs': 'Okta (frame-ancestors via OAuth, CSP injection)',
        'reason': 'Needs full PoC performing sensitive action (disable 2FA, delete account). CSP injection via redirect_uri = theoretical.',
        'keywords': ['clickjack', 'x-frame-options', 'frame-ancestors', 'frameable',
                     'csp injection', 'frame-ancestors injection'],
        'unless': ['sensitive_action', 'disable_2fa', 'delete_account', 'transfer_funds',
                   'poc_sensitive'],
    },
    {
        'name': 'Unauth access to public content / Sanity CMS',
        'rejections': 3,
        'programs': 'Indeed, Linktree, Pinterest (Sanity CMS)',
        'reason': 'Unauth access only reportable if data is clearly private. Public content via API = not a vuln. '
                  'Sanity CMS public read access to non-sensitive data = by design.',
        'keywords': ['unauth', 'unauthenticated api', 'public api', 'exposed portal',
                     'developer portal', 'api documentation', 'sanity cms', 'sanity admin',
                     'unauthenticated read access', 'public content api'],
        'unless': ['pii', 'private_data', 'admin_access', 'write_access', 'delete',
                   'user_data', 'credentials', 'payment_data', 'ssn', 'email_list'],
    },
    {
        'name': 'Outdated software without exploitation',
        'rejections': 1,
        'programs': 'T-Mobile (Concrete CMS P4)',
        'reason': 'P5 VRT — must demonstrate exploitation. Version + CVE list + debug mode = P4 at best without actual exploitation.',
        'keywords': ['outdated', 'eol', 'end of life', 'unsupported version',
                     'debug mode enabled'],
        'unless': ['cve_exploited', 'rce_confirmed', 'validated', 'exploit_confirmed',
                   'file_read_confirmed'],
    },
    {
        'name': 'GraphQL introspection without data access',
        'rejections': 1,
        'programs': 'Atlassian (23,726 types, 1,030 mutations — still rejected)',
        'reason': 'P5 VRT — must chain to actual data access or mutation. Even massive schemas = no impact.',
        'keywords': ['graphql introspection', '__schema', '__type', 'introspection exposes',
                     'introspection enabled'],
        'unless': ['data_access', 'mutation_executed', 'pii', 'admin', 'auth_bypass',
                   'sensitive_data_returned'],
    },
    {
        'name': 'Missing security headers',
        'rejections': 0,
        'programs': 'Universal (P5 VRT)',
        'reason': 'P5 VRT — always rejected',
        'keywords': ['missing hsts', 'missing csp', 'missing x-frame',
                     'missing x-content-type', 'lack of security header',
                     'missing sri', 'subresource integrity'],
        'unless': [],  # Never reportable alone
    },
    {
        'name': 'Splunk HEC / ingest-only endpoints',
        'rejections': 1,
        'programs': 'T-Mobile',
        'reason': 'Write-only services — no data theft, CORS irrelevant. Token brute-force = theoretical.',
        'keywords': ['splunk hec', 'http event collector', 'ingest endpoint',
                     'collector/health', 'splunk-ingest', 'token brute-force'],
        'unless': ['read_access', 'search_api', 'admin_access'],
    },
    {
        'name': 'Client-side config/analytics keys',
        'rejections': 1,
        'programs': 'T-Mobile (Auth0, LaunchDarkly, Datadog, Sentry DSN, MUI)',
        'reason': 'Client-side keys are public by design — Amplitude, Datadog RUM, Sentry DSN, LaunchDarkly client IDs, MUI license keys',
        'keywords': ['sentry dsn', 'amplitude', 'datadog rum', 'launchdarkly client',
                     'segment write key', 'google analytics', 'gtag', 'posthog api',
                     'readme api key', 'mui license', 'app insights',
                     'azure app insights', 'instrumentation key'],
        'unless': ['write_access', 'admin_api', 'server_key', 'secret_key'],
    },
    {
        'name': 'Spring Boot Actuator health/info only',
        'rejections': 1,
        'programs': 'T-Mobile',
        'reason': 'Health and info endpoints are informational — need /env, /heapdump, /configprops with secrets',
        'keywords': ['actuator/health', 'actuator/info', '/health endpoint',
                     'spring boot health'],
        'unless': ['actuator/env', 'actuator/heapdump', 'actuator/configprops',
                   'actuator/mappings', 'secret', 'credential', 'password'],
    },
    {
        'name': 'Open redirect without chain',
        'rejections': 0,
        'programs': 'Universal (most programs)',
        'reason': 'Open redirect alone = social engineering = OOS. Must chain to token theft, OAuth hijack, or SSRF',
        'keywords': ['open redirect', 'redirect_found', 'url redirect'],
        'unless': ['token_theft', 'oauth_hijack', 'ssrf', 'chain', 'session_fixation'],
    },
    {
        'name': 'CVE listing without exploitation proof',
        'rejections': 1,
        'programs': 'T-Mobile Concrete CMS (P4, heading P5)',
        'reason': 'Version + CVE list + "attack surface exists" = P5 without exploitation. Must demonstrate the CVE being exploited.',
        'keywords': ['additional cves', 'cve chain', 'known vulnerabilities',
                     'cve-20', 'multiple cves', 'outdated version with',
                     'insecure directory permissions'],
        'unless': ['exploited', 'rce_confirmed', 'file_read_confirmed', 'data_extracted',
                   'command_executed', 'shell_obtained', 'account_created'],
    },
    {
        'name': 'Swagger/API docs without sensitive action',
        'rejections': 3,
        'programs': 'Indeed, Linktree (Backstage + Shopify), T-Mobile (Credentials Proxy)',
        'reason': 'Exposed Swagger/API docs NOT a vulnerability unless you perform sensitive actions. '
                  'Backstage dev portals are intentionally public. Shopify commerce apps behind auth = expected.',
        'keywords': ['swagger ui', 'swagger-ui', 'api-docs', 'swagger exposed',
                     'openapi spec', 'api documentation exposed', 'backstage developer portal',
                     'dev portal', 'commerce app'],
        'unless': ['private_data', 'admin_access', 'write_access', 'rce_confirmed',
                   'credential_valid', 'account_takeover', 'sensitive_action_performed',
                   'data_extracted', 'unauthorized_mutation'],
    },
    {
        'name': 'SPA auth config disclosure (Cognito/Auth0/OAuth in client JS)',
        'rejections': 1,
        'programs': 'T-Mobile (AWS Cognito in source maps)',
        'reason': 'Cognito user pool IDs, Auth0 client IDs, OAuth config in frontend JS is by design for SPA auth flows.',
        'keywords': ['cognito user pool', 'cognito client id', 'auth0 client',
                     'oauth config', 'cognito credentials in source',
                     'aws cognito credentials'],
        'unless': ['account_created', 'self_signup_confirmed', 'unauthorized_access',
                   'admin_pool', 'restricted_pool'],
    },
    {
        'name': 'Ad-tech / cookie-matching CORS',
        'rejections': 1,
        'programs': 'The Trade Desk',
        'reason': 'Ad-tech cookie-matching subdomains use permissive CORS by design for the ad ecosystem to function. '
                  'Cross-platform ad ID linkage is the intended purpose, not a vulnerability.',
        'keywords': ['cookie-matching', 'cookie matching', 'ad id linkage', 'adsrvr',
                     'ad exchange cors', 'pixel sync', 'cookie sync'],
        'unless': ['pii_theft', 'session_hijack', 'account_takeover'],
    },
    {
        'name': 'Captive portal / network infrastructure endpoints',
        'rejections': 1,
        'programs': 'NETGEAR (captive.netgear.com — claimed, still rejected)',
        'reason': 'Captive portal subdomains often serve redirect-only pages. Even claimed takeovers rejected if no real impact.',
        'keywords': ['captive portal', 'captive.'],
        'unless': ['credential_harvest_confirmed', 'phishing_poc_with_victims'],
    },
    {
        'name': 'Config exposure without unauthorized actions',
        'rejections': 2,
        'programs': 'Comcast (LAPS P1 rejected, WPITX P1 rejected)',
        'reason': 'Downloading source code, reading config files, seeing Azure AD/KeyVault settings = NOT broken access control. '
                  'Must demonstrate UNAUTHORIZED ACTIONS using the exposed config (create admin accounts, escalate, access other users).',
        'keywords': ['configuration exposure', 'downloadable source code', 'azure keyvault',
                     'azure ad credential', 'bitlocker', 'intune', 'admin tool',
                     'it administration portal', 'laps'],
        'unless': ['unauthorized_action', 'admin_account_created', 'privilege_escalation',
                   'data_exfiltrated', 'cross_account', 'other_user_data'],
    },
    {
        'name': 'Same-account admin actions (working as designed)',
        'rejections': 1,
        'programs': 'Fivetran (connector SDK — admin modifying own account)',
        'reason': 'Performing admin actions in your own account with admin creds = working as designed. '
                  'Must demonstrate CROSS-ACCOUNT access (accessing another tenant/user data).',
        'keywords': ['own account', 'admin credential', 'administrator permission',
                     'within their account', 'sandbox escape', 'connector sdk'],
        'unless': ['cross_account', 'cross_tenant', 'other_user_data', 'other_account',
                   'unauthorized_account', 'tenant_isolation_bypass'],
    },
]


def check_burned_program(program_name):
    """Check if a program is on the burned list.

    Returns (pass, reason) tuple.
    """
    if not program_name:
        return True, None
    name_lower = program_name.lower()
    for burned in BURNED_PROGRAMS:
        if burned in name_lower:
            return False, (f'BURNED PROGRAM: {program_name} — signal already damaged, '
                          f'any submission will further hurt signal score. '
                          f'Burned programs: {", ".join(BURNED_PROGRAMS)}')
    return True, None


def check_text_finding(line, program=None):
    """Check a text-format finding line against rejection patterns.

    Returns (pass, pattern_name, reason) tuple.
    """
    # Check burned program first
    if program:
        ok, reason = check_burned_program(program)
        if not ok:
            return False, 'Burned program', reason

    line_lower = line.lower()

    for pattern in REJECTION_PATTERNS:
        # Check if any keyword matches
        matched = any(kw in line_lower for kw in pattern['keywords'])
        if not matched:
            continue

        # Check if any exception applies
        has_exception = any(exc in line_lower for exc in pattern['unless'])
        if has_exception:
            continue

        return False, pattern['name'], pattern['reason']

    return True, None, None


def check_json_finding(entry):
    """Check a JSON CVE/finding entry against rejection patterns.

    Returns (pass, pattern_name, reason) tuple.
    """
    # Build a searchable text blob from the entry
    parts = [
        entry.get('cve_id', ''),
        entry.get('description', ''),
        entry.get('technology', ''),
        str(entry.get('classification', {})),
        str(entry.get('validation', {})),
        str(entry.get('exploits', [])),
    ]
    blob = ' '.join(parts).lower()

    # CVE-specific checks
    validation = entry.get('validation', {})
    validated = validation.get('validated', False)
    cvss = entry.get('cvss_score', 0)
    in_kev = entry.get('in_kev', False)
    has_exploit = entry.get('classification', {}).get('readiness', '') in (
        'exploit_ready', 'nuclei_verified', 'public_exploit'
    )

    # Auto-pass: validated + high CVSS or KEV
    if validated and (cvss >= 7.0 or in_kev):
        return True, None, None

    # Auto-pass: has working exploit and validated
    if validated and has_exploit:
        return True, None, None

    # Check: outdated software without validation
    # Even CVSS 9.8 gets P4/P5 if you only prove version + surface without exploitation
    if not validated and not in_kev and not has_exploit:
        if cvss >= 9.0:
            return False, 'High-CVSS CVE without exploitation proof', \
                f'CVSS {cvss} but not validated — version + attack surface is NOT exploitation. Must demonstrate the CVE being triggered (file read, RCE, data access). Concrete CMS pattern: P4 at best without PoC.'
        else:
            return False, 'Unvalidated low-impact CVE', \
                f'CVSS {cvss}, not validated, no KEV, no public exploit — would be P5'

    # Check: version-only detection (no endpoint confirmation)
    checks_run = validation.get('checks_run', [])
    any_check_passed = any(c.get('validated') for c in checks_run)
    if not validated and not any_check_passed and not in_kev:
        return False, 'No endpoint validation', \
            'Version detected but no endpoint confirmed accessible — theoretical only'

    # Default: pass through for manual review
    return True, None, None


def gate_text_findings(input_path, output_path, strict=False, program=None):
    """Filter text-format findings file."""
    passed = []
    killed = []

    with open(input_path) as f:
        lines = [l.strip() for l in f if l.strip()]

    for line in lines:
        # Already tagged as DO_NOT_SUBMIT — keep the tag
        if 'DO_NOT_SUBMIT' in line:
            killed.append(('Already tagged', 'DO_NOT_SUBMIT', line))
            continue

        ok, pattern, reason = check_text_finding(line, program=program)
        if ok:
            # In strict mode, also require PRIORITY or exploitation markers
            if strict and not any(m in line for m in [
                'PRIORITY', 'CONFIRMED', 'EXPLOITED', 'VALIDATED',
                'AUTH_BYPASS', 'RCE', 'DATA_ACCESS', 'IDOR', 'SQLI',
                'SSRF', 'SSTI', 'DESERIALIZATION'
            ]):
                killed.append(('Strict mode: no exploitation marker', '', line))
                continue
            passed.append(line)
        else:
            killed.append((pattern, reason, line))

    with open(output_path, 'w') as f:
        for line in passed:
            f.write(line + '\n')

    # Write kill log
    kill_log = Path(output_path).with_suffix('.killed.txt')
    with open(kill_log, 'w') as f:
        f.write(f"# Impact Gate — {len(killed)} findings killed, {len(passed)} passed\n")
        f.write(f"# Based on 25 Bugcrowd submissions, ~19 doomed, 1 confirmed OOS (2026-03-10)\n")
        if program:
            ok, reason = check_burned_program(program)
            if not ok:
                f.write(f"# WARNING: {program} is a BURNED PROGRAM — do not submit\n")
        f.write("\n")
        for pattern, reason, line in killed:
            f.write(f"[KILLED:{pattern}] {reason}\n  {line}\n\n")

    return len(passed), len(killed)


def gate_json_findings(input_path, output_path, strict=False):
    """Filter JSON-format findings (CVE pipeline)."""
    with open(input_path) as f:
        entries = json.load(f)

    passed = []
    killed = []

    for entry in entries:
        ok, pattern, reason = check_json_finding(entry)
        if ok:
            if strict and not entry.get('validation', {}).get('validated'):
                killed.append({
                    'cve_id': entry.get('cve_id'),
                    'reason': 'Strict mode: not validated',
                    'cvss': entry.get('cvss_score'),
                })
                continue
            passed.append(entry)
        else:
            entry['_killed'] = {'pattern': pattern, 'reason': reason}
            killed.append({
                'cve_id': entry.get('cve_id'),
                'reason': f'{pattern}: {reason}',
                'cvss': entry.get('cvss_score'),
            })

    with open(output_path, 'w') as f:
        json.dump(passed, f, indent=2)

    # Write kill log
    kill_log = Path(output_path).with_suffix('.killed.json')
    with open(kill_log, 'w') as f:
        json.dump({
            'summary': f'{len(killed)} killed, {len(passed)} passed',
            'note': 'Based on 25 Bugcrowd submissions, ~19 doomed, 1 confirmed OOS (2026-03-10)',
            'killed': killed,
        }, f, indent=2)

    return len(passed), len(killed)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', '-i', help='Input findings file')
    parser.add_argument('--output', '-o', help='Output filtered file')
    parser.add_argument('--strict', action='store_true',
                        help='Strict mode: only pass demonstrated exploitation')
    parser.add_argument('--program', '-p', default=None,
                        help='Program name — auto-kills if program is burned')
    parser.add_argument('--check-program', metavar='NAME',
                        help='Just check if a program is burned (no file processing)')
    args = parser.parse_args()

    # Quick burned-program check mode
    if args.check_program:
        ok, reason = check_burned_program(args.check_program)
        if ok:
            print(f"OK: {args.check_program} is not burned")
        else:
            print(f"BLOCKED: {reason}")
            sys.exit(1)
        return

    if not args.input or not args.output:
        parser.error("--input and --output are required when not using --check-program")

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}")
        sys.exit(1)

    # Check burned program before processing
    if args.program:
        ok, reason = check_burned_program(args.program)
        if not ok:
            print(f"BLOCKED: {reason}")
            print("All findings killed — program is burned. Do NOT submit.")
            sys.exit(1)

    # Detect format
    if input_path.suffix == '.json':
        passed, killed = gate_json_findings(args.input, args.output, args.strict)
    else:
        passed, killed = gate_text_findings(args.input, args.output, args.strict,
                                            program=args.program)

    print(f"Impact Gate: {passed} passed, {killed} killed")
    if killed:
        kill_file = Path(args.output).with_suffix(
            '.killed.json' if input_path.suffix == '.json' else '.killed.txt'
        )
        print(f"Kill log: {kill_file}")


if __name__ == '__main__':
    main()
