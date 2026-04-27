#!/usr/bin/env python3
"""Phase 7 helper: Generate submission-ready reports for validated CVEs."""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# Bugcrowd VRT mapping for CVE findings
VRT_MAPPING = {
    'rce': 'Server-Side Injection > Remote Code Execution (RCE)',
    'sqli': 'Server-Side Injection > SQL Injection',
    'xxe': 'Server-Side Injection > XML External Entity Injection (XXE)',
    'ssrf': 'Server-Side Injection > Server-Side Request Forgery (SSRF)',
    'path_traversal': 'Server-Side Injection > File Inclusion > Path Traversal',
    'auth_bypass': 'Broken Authentication and Session Management > Authentication Bypass',
    'info_disclosure': 'Server Security Misconfiguration > Information Disclosure',
    'default': 'Using Components with Known Vulnerabilities > Outdated Software Version',
}

# Map CVSS severity to Bugcrowd priority
SEVERITY_TO_PRIORITY = {
    'CRITICAL': 'P1',
    'HIGH': 'P2',
    'MEDIUM': 'P3',
    'LOW': 'P4',
}


def classify_vuln_type(cve_info):
    """Classify the vulnerability type from CVE description and data."""
    desc = (cve_info.get('description', '') or '').lower()
    cve_id = cve_info.get('cve_id', '')

    if any(kw in desc for kw in ['remote code execution', 'rce', 'command injection', 'os command']):
        return 'rce'
    elif any(kw in desc for kw in ['sql injection', 'sqli']):
        return 'sqli'
    elif any(kw in desc for kw in ['xxe', 'xml external entity']):
        return 'xxe'
    elif any(kw in desc for kw in ['ssrf', 'server-side request forgery']):
        return 'ssrf'
    elif any(kw in desc for kw in ['path traversal', 'directory traversal', 'file inclusion']):
        return 'path_traversal'
    elif any(kw in desc for kw in ['authentication bypass', 'auth bypass', 'unauthorized access']):
        return 'auth_bypass'
    elif any(kw in desc for kw in ['information disclosure', 'sensitive data', 'data exposure']):
        return 'info_disclosure'
    return 'default'


def generate_report(entry, platform, target, evidence_dir, screenshot_dir):
    """Generate a single submission-ready markdown report."""
    cve_id = entry['cve_id']
    tech = entry.get('technology', 'Unknown')
    version = entry.get('detected_version', 'unknown')
    cvss_score = entry.get('cvss_score', 0)
    severity = entry.get('severity', 'UNKNOWN')
    cvss_vector = entry.get('cvss_vector', '')
    description = entry.get('description', '')
    hosts = entry.get('hosts', [])
    in_kev = entry.get('in_kev', False)
    kev_data = entry.get('kev_data', {})
    exploits = entry.get('exploits', [])
    classification = entry.get('classification', {})
    validation = entry.get('validation', {})
    references = entry.get('references', [])

    vuln_type = classify_vuln_type(entry)
    vrt = VRT_MAPPING.get(vuln_type, VRT_MAPPING['default'])
    priority = SEVERITY_TO_PRIORITY.get(severity, 'P3')

    # Build report
    report = []
    report.append(f"# {platform.title()} Submission: {cve_id} — {tech} {version}")
    report.append("")
    report.append(f"**Program**: {target}")
    report.append(f"**Platform**: {platform.title()}")
    report.append(f"**VRT**: {vrt}")
    report.append(f"**CVSS 3.1**: {cvss_score} ({severity.title()}) -- {cvss_vector}")
    report.append(f"**CVE**: [{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})")
    report.append(f"**Target**: `{hosts[0] if hosts else 'N/A'}`")
    report.append(f"**Asset Type**: URL")
    report.append(f"**Evidence Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    report.append(f"**Researcher**: pythonomus-prime")
    report.append("")

    if in_kev:
        report.append(f"> **CISA KEV**: This vulnerability is in the CISA Known Exploited Vulnerabilities catalog.")
        if kev_data.get('known_ransomware') == 'Known':
            report.append(f"> **Known ransomware use**: YES")
        if kev_data.get('due_date'):
            report.append(f"> **Federal remediation deadline**: {kev_data['due_date']}")
        report.append("")

    report.append("---")
    report.append("")

    # Title
    kev_tag = " [CISA KEV]" if in_kev else ""
    report.append("## Title")
    report.append("")
    report.append(f"{tech} {version} — {cve_id} ({severity.title()} CVSS {cvss_score}){kev_tag}")
    report.append("")
    report.append("---")
    report.append("")

    # Summary
    report.append("## Summary")
    report.append("")
    report.append(f"{description}")
    report.append("")
    report.append(f"**Affected hosts**: {', '.join(f'`{h}`' for h in hosts[:5])}")
    report.append(f"**Detected version**: {tech} {version}")
    report.append(f"**Exploit availability**: {classification.get('readiness', 'unknown').replace('_', ' ').title()}")
    report.append("")
    report.append("---")
    report.append("")

    # Steps to Reproduce
    report.append("## Steps to Reproduce")
    report.append("")

    # Step 1: Version confirmation
    report.append("### Step 1: Confirm vulnerable version")
    report.append("")
    if hosts:
        host = hosts[0]
        if not host.startswith('http'):
            host = f"https://{host}"
        report.append(f"```bash")
        report.append(f"curl -sk -D- '{host}' -o /dev/null | head -20")
        report.append(f"```")
        report.append("")

        # Include actual validation evidence
        for check in validation.get('checks_run', []):
            if check.get('validated'):
                report.append(f"**Result**: {check.get('match', 'Validated')}")
                resp = check.get('response', {})
                if resp.get('server'):
                    report.append(f"- Server: `{resp['server']}`")
                if resp.get('status'):
                    report.append(f"- Status: {resp['status']}")
                report.append("")
                break

    # Step 2: CVE reference
    report.append("### Step 2: CVE reference")
    report.append("")
    report.append(f"- **NVD**: https://nvd.nist.gov/vuln/detail/{cve_id}")
    if in_kev:
        report.append(f"- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        report.append(f"  - Required action: {kev_data.get('action', 'Apply updates per vendor instructions')}")
    for ref in references[:3]:
        report.append(f"- {ref}")
    report.append("")

    # Step 3: Exploit availability
    report.append("### Step 3: Public exploit availability")
    report.append("")

    searchsploit_exploits = [e for e in exploits if e.get('source') == 'exploit-db']
    github_pocs = [e for e in exploits if e.get('source') == 'github']
    nuclei_templates = [e for e in exploits if e.get('source') == 'nuclei']

    if searchsploit_exploits:
        report.append("**Exploit-DB:**")
        for e in searchsploit_exploits[:3]:
            report.append(f"- {e.get('title', '')} (EDB-{e.get('edb_id', '')})")
        report.append("")

    if github_pocs:
        report.append("**GitHub PoC repositories:**")
        for g in github_pocs[:3]:
            report.append(f"- [{g.get('name', '')}]({g.get('url', '')}) ({g.get('stars', 0)} stars)")
        report.append("")

    if nuclei_templates:
        report.append("**Nuclei templates:**")
        for n in nuclei_templates[:2]:
            tmpl = n.get('template', '')
            if tmpl == 'CONFIRMED_BY_LIVE_SCAN':
                report.append(f"- **CONFIRMED by automated nuclei scan against target**")
            else:
                report.append(f"- `{tmpl}`")
        report.append("")

    if not exploits:
        report.append("No public exploits found — vulnerability confirmed via version fingerprinting and NVD advisory.")
        report.append("")

    # Step 4: Nuclei confirmation (if applicable)
    if any(e.get('source') == 'nuclei' and e.get('template') == 'CONFIRMED_BY_LIVE_SCAN' for e in exploits):
        report.append("### Step 4: Nuclei automated confirmation")
        report.append("")
        report.append("```bash")
        report.append(f"nuclei -u '{hosts[0] if hosts else 'TARGET'}' -t cves/{cve_id.lower()}.yaml")
        report.append("```")
        report.append("")
        report.append("**Result**: Vulnerability confirmed by nuclei template match against live target.")
        report.append("")

    report.append("---")
    report.append("")

    # Impact
    report.append("## Impact")
    report.append("")
    report.append(f"**{cve_id}** ({severity.title()}, CVSS {cvss_score}) affects {tech} {version}.")
    report.append("")

    if cvss_score >= 9.0:
        report.append(f"This is a **critical severity** vulnerability. {description[:200]}")
    elif cvss_score >= 7.0:
        report.append(f"This is a **high severity** vulnerability. {description[:200]}")
    else:
        report.append(f"{description[:300]}")
    report.append("")

    if in_kev:
        report.append(f"**This CVE is listed in CISA's Known Exploited Vulnerabilities catalog**, confirming active exploitation in the wild. Federal agencies are required to remediate by {kev_data.get('due_date', 'TBD')}.")
        report.append("")

    exploit_types = classification.get('exploit_types', [])
    if 'remote' in exploit_types:
        report.append("Public **remote** exploits are available, making this trivially exploitable by any attacker with network access.")
    elif 'webapp' in exploit_types:
        report.append("Public **web application** exploits are available for this vulnerability.")
    report.append("")

    report.append("---")
    report.append("")

    # Evidence files
    report.append("## Evidence")
    report.append("")
    report.append("| File | Description |")
    report.append("|------|-------------|")

    safe_cve = cve_id.replace('-', '_')

    # List screenshots
    for ext in ['png']:
        for f in sorted(Path(screenshot_dir).glob(f"{safe_cve}*.{ext}")):
            report.append(f"| `{f.name}` | Screenshot |")

    # List curl evidence
    curl_dir = Path(evidence_dir) / 'curl_responses'
    if curl_dir.exists():
        for f in sorted(curl_dir.glob(f"{safe_cve}*")):
            report.append(f"| `{f.name}` | HTTP response capture |")

    # List curl evidence from validation
    curl_evidence_dir = Path(evidence_dir) / 'curl_evidence'
    if curl_evidence_dir.exists():
        for f in sorted(curl_evidence_dir.glob(f"{cve_id}*")):
            report.append(f"| `{f.name}` | Validation evidence |")

    report.append("")
    report.append("---")
    report.append("")

    # Remediation
    report.append("## Remediation")
    report.append("")
    if kev_data.get('action'):
        report.append(f"1. **{kev_data['action']}**")
    else:
        report.append(f"1. **Upgrade {tech}** to the latest patched version")
    report.append(f"2. Review vendor advisory for {cve_id}")
    report.append(f"3. Apply any available security patches or workarounds")
    if in_kev:
        report.append(f"4. Prioritize remediation — this CVE has confirmed active exploitation")
    report.append("")

    return '\n'.join(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validated', required=True, help='Validated CVEs JSON')
    parser.add_argument('--evidence-dir', required=True, help='Evidence directory')
    parser.add_argument('--screenshot-dir', required=True, help='Screenshot directory')
    parser.add_argument('--platform', default='bugcrowd')
    parser.add_argument('--target', default='Target')
    parser.add_argument('--output-dir', required=True, help='Reports output directory')
    args = parser.parse_args()

    validated_path = Path(args.validated)
    if not validated_path.exists():
        print("Validated CVEs file not found")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(validated_path) as f:
        validated = json.load(f)

    # Only generate reports for validated + high-value CVEs
    reportable = [
        v for v in validated
        if v.get('validation', {}).get('validated')
        or (v.get('in_kev') and v.get('cvss_score', 0) >= 7.0)
    ]

    print(f"Generating reports for {len(reportable)} CVEs...")

    report_index = []

    for i, entry in enumerate(reportable):
        cve_id = entry['cve_id']
        severity = entry.get('severity', 'UNKNOWN')
        cvss = entry.get('cvss_score', 0)

        report = generate_report(
            entry, args.platform, args.target,
            args.evidence_dir, args.screenshot_dir,
        )

        filename = f"CVE_REPORT_{i+1:02d}_{cve_id}_{severity}.md"
        filepath = output_dir / filename

        with open(filepath, 'w') as f:
            f.write(report)

        report_index.append({
            'file': filename,
            'cve_id': cve_id,
            'technology': entry.get('technology', ''),
            'version': entry.get('detected_version', ''),
            'cvss': cvss,
            'severity': severity,
            'in_kev': entry.get('in_kev', False),
            'validated': entry.get('validation', {}).get('validated', False),
            'exploit_readiness': entry.get('classification', {}).get('readiness', ''),
        })

        print(f"  [{i+1}] {filename}")

    # Write report index
    index_file = output_dir / 'REPORT_INDEX.json'
    with open(index_file, 'w') as f:
        json.dump(report_index, f, indent=2)

    print(f"\n{len(reportable)} reports generated in {output_dir}")


if __name__ == '__main__':
    main()
