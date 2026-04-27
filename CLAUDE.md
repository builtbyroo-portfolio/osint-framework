# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Bug bounty hunting workspace on a BlackArch Linux security research station. Contains recon data, vulnerability reports, exploitation scripts, and automated hunting tooling for HackerOne and Bugcrowd programs. Researcher handle: `pythonomus-prime`.

## System Context

- **OS**: BlackArch Linux (Arch-based), XFCE desktop
- **Python**: 3.14.2 (system), no project-wide venv
- **sudo**: Passwordless for user `raze`
- **GPU**: GTX 1060 6GB — driver 470.256.02 + CUDA 11.4 (locked, do not change)
- **Package manager**: `sudo pacman -S <package>` (BlackArch + Arch repos)
- `wget` and `curl` are aliased to set user-agent to `noleak` — do not override unless necessary

## Installed Security Tools

**Recon/Discovery**: subfinder, httpx-pd, gau, katana, hakrawler, arjun, paramspider, amass, theharvester, nmap
**Vuln Scanning**: nuclei (v3.7.0, 3,900+ templates at `~/nuclei-templates/`), ffuf (v2.1.0), nikto
**Exploitation**: dalfox (XSS), crlfuzz (CRLF), ghauri (SQLi), sqlmap (SQLi), commix (command injection)
**JS Analysis**: secretfinder, linkfinder, cariddi
**Secret Scanning**: gitleaks, trufflehog
**Utilities**: gf (grep patterns for vuln indicators), interactsh-client (OOB callback server)
**Wordlists**: SecLists at `/usr/share/seclists/`
**Other**: shodan (API client in pipenv), Burp Suite/ZAP (GUI)

## Tool Pipeline

### hunt.sh v4.0 — 17-Phase Bug Bounty Hunter
```bash
./hunt.sh -t "Target" -d domains.txt -p bugcrowd   # CLI mode
./hunt.sh --resume ./hunts/Target_20260301_120000   # Resume
```
**Phases**: recon → WAF → sweep → nuclei → secrets → XSS → SQLi → SSRF → redirect → admin → misc → takeover → JWT → IDOR → proto pollution → race condition → report
Output: `hunts/{Target}_{timestamp}/` with manifest.json, findings, and markdown report.

### social.sh v1.0 — 10-Phase SE Surface Hunter
```bash
./social.sh -t "Target" -d domains.txt -p hackerone
```
**Phases**: surface mapping → email (SPF/DKIM/DMARC) → clickjacking → open redirect → content spoofing → reverse tabnabbing → CSRF → OAuth misconfig → subdomain takeover → header/cookie audit

### api.sh v1.0 — 8-Phase Deep API Exploitation Scanner
```bash
./api.sh -t "Target" -d domains.txt -p bugcrowd
```
**Phases**: GraphQL recon → GraphQL exploit → GraphQL brute → REST abuse → WebSocket → SOAP/XXE → rate bypass → schema harvest

### cache.sh v1.0 — 8-Phase Cache & Transport Attack Scanner
```bash
./cache.sh -t "Target" -d domains.txt -p bugcrowd
```
**Phases**: CDN fingerprint → cache poison → cache deception → smuggle detect → H2C smuggle → host header → desync → CDN bypass

### cloud.sh v1.0 — 8-Phase Cloud & Supply Chain Scanner
```bash
./cloud.sh -t "Target" -d domains.txt -p bugcrowd --keyword TARGET
```
**Phases**: cloud enum → bucket scan → metadata SSRF → serverless → JS audit → dep confusion → SRI check → cloud secrets

### access.sh — Deep Access Control Tester (7 phases)
Reads `ac_api_findings.txt`, `ac_graphql_findings.txt`, `ac_swagger_specs.txt` from previous scans.

### scripts/monitor.sh — Daily Persistent Recon
```bash
./scripts/monitor.sh   # or cron: 0 6 * * * ~/operator_toolbox/Bug_Bounty/scripts/monitor.sh
```
Subdomain change detection → live host probing → nuclei on new hosts → trufflehog secret scan.
Output: `monitor/alerts_YYYYMMDD.txt`

### scripts/impact_gate.py — Rejection Pattern Filter
```bash
python3 scripts/impact_gate.py -i findings.json -o gated.json [--strict]
python3 scripts/impact_gate.py --check-program "ProgramName"   # exits 1 if burned
python3 scripts/impact_gate.py -i findings.txt -o gated.txt -p "Target Name"
```
18 rejection patterns + 12 burned programs. Run before ANY report writing.

### Tool Finding Tags
- `[SUBMIT:P1-P3]` — Ready for submission
- `[REVIEW:P4]` — Manual review needed
- `[DO_NOT_SUBMIT:P5]` — Informational, never submit
- `[DO_NOT_SUBMIT:RECON_ONLY]` — No exploitation demonstrated
- `[DO_NOT_SUBMIT:OOS]` — Out of scope target
- `[DO_NOT_SUBMIT:EXCLUDED]` — Program-specific exclusion
- `[DO_NOT_SUBMIT:STANDARD_EXCLUSION]` — Bugcrowd universal exclusion

## Recon Data Convention

Each program directory follows this data flow:

1. `{name}_subfinder_subdomains.txt` — raw subdomain enumeration
2. `{name}_live_subdomains.txt` — httpx output with status codes, titles, tech
3. `{name}_reachable_hosts.txt` — filtered to 200/301/302/401/403/500
4. `{name}_high_value_targets.txt` — non-standard hosts worth deeper probing
5. `domains.txt` — wildcard scope list (one per line: `*.example.com`)
6. `README.md` — program scope, payouts, out-of-scope exclusions

## Submission Gate — MANDATORY

### Step 0: SCOPE VALIDATION (Before ANY Work)
1. Read the FULL program brief — targets, exclusions, reward table, special rules
2. Confirm the target URL/asset is EXPLICITLY listed in "Targets" section
3. Check program-specific exclusions (CORS, headers, subdomain takeover, AWS infra, etc.)
4. If target is NOT listed: DO NOT SUBMIT.
5. Save scope notes to program workspace `README.md` on first hunt

**Scope violations cost signal points permanently.**

### Step 1: Bugcrowd Universal Exclusions
These are NEVER rewardable:
- Targets outside the "Targets" section (including unlisted subdomains)
- Version/banner disclosure without demonstrated exploitation of a specific CVE
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.) — all P5
- Stack traces / error messages / HTTP 404s
- Username enumeration, weak/missing CAPTCHA, missing cookie flags
- Clickjacking on non-sensitive pages, CSRF on anonymous/logout forms
- Directory listing (non-sensitive data)
- GraphQL introspection (without data access chain) — P5
- Source maps — ALWAYS rejected (11/11 submissions, 0 accepted)
- CORS without credential-based data theft PoC (5/5 rejections)
- Subdomain takeover without claiming (3/3 rejections) — MUST host proof page
- API docs/Swagger/dev portals/Backstage — intentionally public
- Unauth access to public content — public data via API = not a vuln
- Splunk HEC / ingest-only endpoints — write-only, CORS irrelevant
- Client-side keys (Sentry DSN, Amplitude, Datadog RUM, LaunchDarkly, MUI license) — public by design
- Spring Boot actuator/health,info only — need /env or /heapdump with secrets
- EOL/outdated software without exploitable CVE demonstration
- Login pages without auth bypass ("Protected" = P5)
- Vendor-default API docs at standard paths ("Intentionally Public")
- SRI missing (without CDN compromise chain)
- Physical testing, social engineering, DoS/DDoS

### Step 2: Exploitation Requirement
Every finding must demonstrate actual exploitation — not just endpoint/handler/version discovery.

**SUBMIT ONLY IF**: finding shows data access, credential validation (live test), auth bypass, IDOR with object access, code execution, or takeover with proof of claim.

**Bugcrowd reward eligibility**: "You will qualify for a reward if you were the first eligible person to alert the Program Owner to a previously unknown issue AND **the issue triggers a code or configuration change**."

### Escalation Pattern (Before Giving Up)
1. Version disclosure → find matching CVE → prove vulnerable handler exists → demonstrate exploitation
2. Endpoint exists → extract sensitive data → validate credentials → chain with access
3. Handler present → attempt actual exploitation → document data extracted
4. Cannot escalate past recon → **DO NOT SUBMIT** — move to next target

## Vulnerability Checklist (Per Target)

**Authentication/Authorization:**
- [ ] Password reset token predictability
- [ ] Session fixation/hijacking
- [ ] JWT algorithm confusion (`alg:none`, RS256→HS256, `kid` injection)
- [ ] OAuth misconfigurations
- [ ] IDOR in user endpoints (sequential/UUID IDs, method switching GET→PUT)
- [ ] Role escalation / horizontal + vertical access control gaps
- [ ] API endpoint auth gaps (version downgrade `/v1/` vs `/v2/`)

**Injection:**
- [ ] SQL injection (in-band, blind, time-based) — GraphQL endpoints too
- [ ] XSS (reflected, stored, DOM-based)
- [ ] Command injection / SSTI (`{{7*7}}`=49 → P1)
- [ ] Template injection
- [ ] LDAP/XML/XPath injection, XXE in SOAP/XML payloads

**Business Logic:**
- [ ] Race conditions (payment, redemption, gift cards, limited items)
- [ ] Price/quantity manipulation
- [ ] Referral system abuse, discount code stacking
- [ ] Payment bypass, coupon abuse, state manipulation

**API Security:**
- [ ] GraphQL introspection + field suggestion bruteforce + batching attacks
- [ ] REST API excessive data exposure / mass assignment
- [ ] SSRF via webhooks, PDF generators, profile picture URLs — cloud metadata 169.254.169.254
- [ ] API rate limiting gaps
- [ ] ASMX endpoints: append `?WSDL` for full SOAP surface

**File Operations:**
- [ ] Unrestricted file upload
- [ ] Path traversal / LFI (URL encoding tricks, server-specific path handling)
- [ ] XXE (XML External Entity)
- [ ] Insecure file permissions

**Modern Web:**
- [ ] CORS misconfigurations (need `Allow-Credentials: true` + sensitive endpoint)
- [ ] Subdomain takeover — claim BEFORE reporting
- [ ] Open redirects (chain with OAuth to be reportable)
- [ ] Clickjacking — needs sensitive action PoC
- [ ] Cache poison / cache deception / H2C smuggling / host header injection
- [ ] Prototype pollution

**Recon Quick Wins (chains only — not standalone):**
- Next.js `__NEXT_DATA__` — SSR config leaks
- Metabase `/api/session/properties` — setup tokens (unauth)
- ServiceNow `/stats.do`, `/threads.do` — often unauth
- Spring Boot `/actuator/env`, `/actuator/heapdump` — need secrets to report
- HashiCorp Vault `/v1/sys/health`, `/v1/sys/seal-status`
- Airflow `/api/v1/health` + `/api/v1/version` — unauth by default
- GraphQL introspection — use for recon, chain before submitting
- Config JS files — auth config leaks, Sentry DSN, internal URLs
- CSP headers — `connect-src`, `img-src` reveal internal architecture

## Report Format

**HackerOne**: Title, Summary, Severity, Description, Steps to Reproduce (curl commands + responses), Impact, Remediation, References.

**Bugcrowd**: Title, Target/URL, Vulnerability Type (VRT category), Severity (P1-P5), Description, Steps to Reproduce, Impact, Remediation.

Both require **working PoC with actual response data** — no placeholders. Include differential proof (valid vs invalid inputs). Chain findings — pure info disclosure gets closed Informative everywhere.

## Platform Notes

- **HackerOne**: `X-HackerOne-Research: pythonomus-prime` header. PayPal also needs `X-PP-BB: HackerOne-pythonomus-prime`.
- **Bugcrowd**: VRT category selection matters — same finding can be P5 or P1 depending on category. `Server Security Misconfiguration` is the catch-all.
- **FIS**: Header `X-Bug-Bounty:BugCrowd-pythonomus-prime` REQUIRED (75% penalty without). 5 req/sec max. No PII in reports.
- **Mastercard**: NO automated scanners — manual testing only.
- **TheFork**: UA must contain "bugcrowd", max 25 req/sec, test restaurants only.

## Burned Programs — DO NOT SUBMIT
Indeed, Linktree, Latitude Financial, SEEK, Atlassian, Okta/Auth0, Chime, Pinterest, The Trade Desk, Tesla

## Directory Layout

- `Bugcrowd/` — Active Bugcrowd programs
- `HackerOne/Ready_To_Submit/` — Hyatt, PayPal reports pending
- `HackerOne/Submitted/` — Syfe, Worldcoin_TFH
- `hunts/` — Automated scan output per target/timestamp
- `scripts/` — Standalone helper scripts (monitor.sh, impact_gate.py, etc.)
- `hunt.sh`, `api.sh`, `cache.sh`, `cloud.sh`, `social.sh`, `access.sh`, `lib.sh` — Main tools
- `submitted_findings.txt` — Cross-hunt dedup tracker
