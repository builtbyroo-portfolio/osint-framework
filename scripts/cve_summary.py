#!/usr/bin/env python3
"""Phase 8 helper: Generate final summary with triage recommendations."""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validated', required=True, help='Validated CVEs JSON')
    parser.add_argument('--reports-dir', required=True, help='Reports directory')
    parser.add_argument('--platform', default='bugcrowd')
    parser.add_argument('--target', default='Target')
    parser.add_argument('--output', required=True, help='Output summary markdown')
    args = parser.parse_args()

    validated_path = Path(args.validated)
    if not validated_path.exists():
        with open(args.output, 'w') as f:
            f.write("# No CVEs found\n")
        return

    with open(validated_path) as f:
        validated = json.load(f)

    reports_dir = Path(args.reports_dir)
    report_files = sorted(reports_dir.glob('CVE_REPORT_*.md'))

    # Categorize findings
    confirmed = [v for v in validated if v.get('validation', {}).get('validated')]
    kev_hits = [v for v in validated if v.get('in_kev')]
    critical = [v for v in validated if v.get('cvss_score', 0) >= 9.0]
    high = [v for v in validated if 7.0 <= v.get('cvss_score', 0) < 9.0]
    with_exploit = [v for v in validated if v.get('classification', {}).get('readiness') in
                    ('exploit_ready', 'nuclei_verified', 'public_exploit')]

    # Build summary
    lines = []
    lines.append(f"# CVE Scan Summary — {args.target}")
    lines.append(f"")
    lines.append(f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Platform**: {args.platform.title()}")
    lines.append(f"**Total CVEs found**: {len(validated)}")
    lines.append(f"")

    lines.append("## Quick Stats")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total CVEs | {len(validated)} |")
    lines.append(f"| Confirmed exploitable | {len(confirmed)} |")
    lines.append(f"| CISA KEV (actively exploited) | {len(kev_hits)} |")
    lines.append(f"| Critical (CVSS >= 9.0) | {len(critical)} |")
    lines.append(f"| High (CVSS 7.0-8.9) | {len(high)} |")
    lines.append(f"| Public exploit available | {len(with_exploit)} |")
    lines.append(f"| Reports generated | {len(report_files)} |")
    lines.append("")

    # Submit recommendations
    submit = [v for v in confirmed if v.get('cvss_score', 0) >= 4.0]
    review = [v for v in validated if not v.get('validation', {}).get('validated')
              and (v.get('in_kev') or v.get('cvss_score', 0) >= 7.0)]
    skip = [v for v in validated if v.get('cvss_score', 0) < 4.0
            and not v.get('in_kev')
            and not v.get('validation', {}).get('validated')]

    lines.append("## Triage Recommendations")
    lines.append("")

    if submit:
        lines.append("### SUBMIT (confirmed + reportable)")
        lines.append("")
        lines.append("| # | CVE | Tech | CVSS | KEV | Exploit | Report |")
        lines.append("|---|-----|------|------|-----|---------|--------|")
        for i, v in enumerate(sorted(submit, key=lambda x: -x.get('cvss_score', 0))):
            kev = "YES" if v.get('in_kev') else ""
            readiness = v.get('classification', {}).get('readiness', '').replace('_', ' ')
            report_file = next((r.name for r in report_files if v['cve_id'] in r.name), '')
            lines.append(
                f"| {i+1} | {v['cve_id']} | {v.get('technology', '')} {v.get('detected_version', '')} "
                f"| {v.get('cvss_score', 0)} | {kev} | {readiness} | `{report_file}` |"
            )
        lines.append("")

    if review:
        lines.append("### MANUAL REVIEW (high value but not auto-validated)")
        lines.append("")
        lines.append("| CVE | Tech | CVSS | KEV | Notes |")
        lines.append("|-----|------|------|-----|-------|")
        for v in sorted(review, key=lambda x: -x.get('cvss_score', 0))[:15]:
            kev = "YES" if v.get('in_kev') else ""
            notes = '; '.join(v.get('validation', {}).get('validation_notes', []))[:80]
            lines.append(
                f"| {v['cve_id']} | {v.get('technology', '')} {v.get('detected_version', '')} "
                f"| {v.get('cvss_score', 0)} | {kev} | {notes} |"
            )
        lines.append("")

    if skip:
        lines.append(f"### SKIP ({len(skip)} low-severity / no exploit)")
        lines.append("")

    # Technology breakdown
    tech_counts = {}
    for v in validated:
        tech = v.get('technology', 'Unknown')
        tech_counts[tech] = tech_counts.get(tech, 0) + 1

    lines.append("## Technology Breakdown")
    lines.append("")
    lines.append("| Technology | CVEs Found |")
    lines.append("|-----------|-----------|")
    for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {tech} | {count} |")
    lines.append("")

    # Next steps
    lines.append("## Next Steps")
    lines.append("")
    if submit:
        lines.append(f"1. Review {len(submit)} SUBMIT reports in `reports/`")
        lines.append(f"2. Re-verify each finding before submission (things change)")
        lines.append(f"3. Submit in order: highest CVSS + KEV first")
    if review:
        lines.append(f"4. Manually investigate {len(review)} REVIEW candidates")
    lines.append("")

    summary = '\n'.join(lines)

    with open(args.output, 'w') as f:
        f.write(summary)

    # Also print to stdout
    print(summary)


if __name__ == '__main__':
    main()
