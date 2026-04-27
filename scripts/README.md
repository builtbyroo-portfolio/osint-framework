# scripts/ — Reference

All standalone helper scripts. Each main tool (hunt.sh, api.sh, etc.) calls these internally,
but you can run any of them directly against a single target.

---

## Prefix Reference

| Prefix | Count | Category | Called by |
|--------|-------|----------|-----------|
| `ac_` | 10 | Access control — 403 bypass, auth probing, vhost, param mining | access.sh |
| `ap_` | 8 | API — GraphQL recon/exploit/brute, REST abuse, WebSocket, SOAP/XXE | api.sh |
| `cl_` | 8 | Cloud — bucket scan, metadata SSRF, serverless, dep confusion, JS audit | cloud.sh |
| `ct_` | 8 | Cache/transport — poison, deception, smuggling, H2C, host header | cache.sh |
| `cve_` | 8 | CVE pipeline — tech extract, NVD lookup, version map, evidence, report | cve.sh |
| `se_` | 10 | Social engineering surface — email, clickjacking, CSRF, OAuth, redirect | social.sh |
| `vuln_` | 4 | Vuln scanners — XSS, SQLi, SSRF, open redirect | hunt.sh |

## Standalone Scripts

| Script | What It Does | Usage |
|--------|-------------|-------|
| `impact_gate.py` | Filters findings against 18 rejection patterns + 12 burned programs | `python3 scripts/impact_gate.py -i findings.txt -o gated.txt -p "Program"` |
| `monitor.sh` | Daily persistent recon — new subdomains, nuclei, trufflehog | `./scripts/monitor.sh` or cron at 06:00 |
| `credential_validator.py` | Validates 20+ cred types (AWS, Datadog, Stripe, SendGrid…) | `python3 scripts/credential_validator.py -i secrets.txt` |
| `recon.sh` | Phase 1 recon only (subfinder → httpx → gau) | `./scripts/recon.sh -d domains.txt -o out/` |
| `scope.sh` | Validates a URL against a domains.txt scope file | `./scripts/scope.sh -u https://target.com -s domains.txt` |
| `nuclei_scan.sh` | Nuclei against a live hosts file | `./scripts/nuclei_scan.sh -i hosts.txt -o nuclei_out/` |
| `secrets.sh` | JS secret scanning (secretfinder + trufflehog) | `./scripts/secrets.sh -i urls.txt -o secrets_out/` |
| `admin_hunt.sh` | Admin panel discovery (ffuf + common paths) | `./scripts/admin_hunt.sh -d domain.com -o out/` |
| `quick_sweep.sh` | Fast 5-min surface check (httpx + nuclei critical) | `./scripts/quick_sweep.sh -d domains.txt` |
| `supplement.sh` | Extra probes not in main pipeline | `./scripts/supplement.sh -t target -d domains.txt` |
| `waf_bypass.sh` | WAF detection + bypass wordlist testing | `./scripts/waf_bypass.sh -u https://target.com` |
| `misc_scans.sh` | Miscellaneous checks (misc phase in hunt.sh) | `./scripts/misc_scans.sh -d domains.txt -o out/` |

## Exploit Scripts (standalone, use after recon confirms surface)

| Script | Finding Type | Usage |
|--------|-------------|-------|
| `idor_hunter.py` | IDOR — sequential/UUID ID enumeration | `python3 scripts/idor_hunter.py -u URL -r id_param` |
| `race_condition.py` | Race conditions — parallel request bombing | `python3 scripts/race_condition.py -u URL -n 50` |
| `jwt_attack.sh` + `jwt_analyze.py` | JWT — alg:none, RS256→HS256, kid injection | `./scripts/jwt_attack.sh -t token` |
| `ssti_scan.py` + `.sh` | SSTI — template injection (`{{7*7}}`=49) | `python3 scripts/ssti_scan.py -u URL` |
| `path_traversal.py` + `.sh` | Path traversal / LFI — encoding tricks | `python3 scripts/path_traversal.py -u URL` |
| `proto_polluter.py` + `.sh` | Prototype pollution | `python3 scripts/proto_polluter.py -u URL` |
| `unicode_bypass.py` + `.sh` | Unicode normalization bypass | `python3 scripts/unicode_bypass.py -u URL` |
| `orm_leak.py` + `.sh` | ORM data exposure | `python3 scripts/orm_leak.py -u URL` |
| `nextjs_poison.py` + `.sh` | Next.js cache poisoning / `__NEXT_DATA__` leak | `python3 scripts/nextjs_poison.py -u URL` |
| `deserial_scan.py` + `.sh` | Deserialization detection (note: H4sI = gzip FP, not Java serial) | `python3 scripts/deserial_scan.py -u URL` |
| `h2c_smuggle.py` + `.sh` | HTTP/2 cleartext smuggling | `python3 scripts/h2c_smuggle.py -u URL` |
| `takeover_exploiter.sh` | Subdomain takeover — claim + host proof page | `./scripts/takeover_exploiter.sh -d dangling.domain.com` |

---

## Notes

- Scripts with both `.py` and `.sh` variants: `.sh` wraps the Python for use in bash pipelines
- `__pycache__/` — Python cache, ignore
- Always run `impact_gate.py` before writing any report
