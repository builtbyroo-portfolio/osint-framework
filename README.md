# OSINT Investigation Framework

Interactive OSINT investigation tool that takes seed data (emails, phone numbers, usernames, IPs, domains, addresses, MACs, SSIDs) and produces a structured dossier zip ready for import into **Maltego**, **Burp Suite**, **recon-ng**, and **SpiderFoot**.

**Pivot engine** automatically follows threads — entities discovered during investigation (WHOIS registrant contacts, harvested emails, DNS IPs, subdomains) are queued and investigated at configurable depth levels without re-running work already done.

---

## Features

- **Interactive data entry** — labeled prompts with examples, comma-separated or one-per-line input
- **9 data types** — emails, phones, usernames, full names, domains, IPs, physical addresses, MAC addresses, SSIDs
- **Pivot engine** — recursive investigation of discovered entities with configurable depth and entity deduplication
- **Username derivation** — auto-generates username candidates from discovered emails (`john.doe@` → `johndoe`, `john.doe`, `john_doe`) and WHOIS names
- **Tool-compatible output** — Maltego CSV, Burp Suite scope JSON, recon-ng workspace script, SpiderFoot target list
- **Unified dossier** — everything zipped to `~/Desktop/{name}_investigation.zip`

---

## Requirements

**Required:**
```
curl  jq  dig  whois  nmap
```

**Recommended (auto-installs via pacman if missing):**
```
sherlock       # 300+ site username scan
phoneinfoga    # phone number OSINT
```

**Used if available:**
```
holehe              # email service registration check (120+ sites)
maigret             # deep username scan
theHarvester        # email/subdomain harvesting (python3 -m theHarvester)
subfinder           # subdomain enumeration
gau                 # historical URL discovery
recon-ng            # framework import
spiderfoot          # framework import
shodan              # IP lookup (requires SHODAN_API_KEY)
nmcli               # local Wi-Fi SSID scan
```

**Optional API keys** (set as env vars, skipped if absent):
```bash
export WIGLE_API_KEY="your_encoded_key"   # SSID geolocation
export SHODAN_API_KEY="your_key"          # IP intelligence
```

---

## Installation

```bash
git clone https://github.com/Sharon-Needles/osint-framework
cd osint-framework

# Global access
sudo ln -s "$(pwd)/osint.sh" /usr/local/bin/osint
```

Or run directly:
```bash
./osint.sh
./osint.sh --depth=2    # deeper pivot
```

---

## Usage

```
osint                  # interactive mode, depth 1 (default)
osint --depth=0        # seed data only, no pivot
osint --depth=2        # follow discovered entities two levels deep
```

**Session flow:**
1. Enter investigation name, case number, investigator
2. Choose target type (person / organization / domain-IP / mixed)
3. Set pivot depth
4. Enter seed data — every field optional, blank line to skip
5. Review screen — confirm before running
6. Investigation runs automatically
7. Pivot engine discovers new entities and investigates them
8. Dossier zipped to `~/Desktop/{name}_investigation.zip`

---

## Output Structure

```
{name}_investigation_{timestamp}/
├── README.txt
├── summary.md              — investigation summary with pivot results
├── timeline.log            — timestamped activity log
├── seed/                   — original seed data files
├── email_osint/            — holehe, DNS/MX, WHOIS, theHarvester
├── username_osint/         — sherlock, maigret
├── phone_osint/            — phoneinfoga, carrier lookup
├── domain_osint/           — WHOIS, DNS, subfinder, crt.sh CT, gau, nmap
├── ip_osint/               — WHOIS, rDNS, ASN/geo (ipinfo.io), nmap, Shodan
├── network_osint/          — MAC vendor lookup, SSID local scan + Wigle
├── address_osint/          — Nominatim geocoding, Google Maps / OSM links
├── pivot/
│   ├── depth_1/
│   │   ├── discovered_entities.txt   — what triggered this depth
│   │   ├── email_osint/
│   │   ├── username_osint/
│   │   ├── domain_osint/             — lighter: no nmap/gau/theHarvester
│   │   └── ip_osint/                 — lighter: no nmap
│   └── depth_2/ ...
├── maltego/
│   ├── entities.csv        — all entities tagged with depth and source
│   └── import_guide.txt
├── burp/
│   ├── scope.json          — Burp Suite project scope (all depths)
│   └── target_list.txt
├── recon_ng/
│   └── workspace.rc        — recon-ng replay script
└── spiderfoot/
    └── targets.txt
```

---

## Pivot Engine

After the initial (depth 0) investigation, the pivot engine:

1. Scans all output files for new entities:
   - Emails from theHarvester/holehe output
   - IPs from DNS A records (private ranges filtered)
   - Subdomains from subfinder/crt.sh output
   - Registrant names and phones from WHOIS (REDACTED filtered)

2. Derives username candidates automatically:
   - `john.doe@corp.com` → `johndoe`, `john.doe`, `john_doe`
   - `Jane Doe` (from WHOIS) → `janedoe`, `jane.doe`, `j.doe`

3. Skips anything already investigated (full deduplication)

4. Runs lighter scans at pivot depth (no nmap, no gau — much faster)

5. Feeds all discoveries back into Maltego CSV with `Depth` column

If a depth pass finds nothing new, investigation converges early.

---

## Tool Import

**Maltego:**
```
Investigate → Import Entities from CSV → maltego/entities.csv
```

**Burp Suite:**
```
Project options → Scope → Load → burp/scope.json
```

**recon-ng:**
```bash
recon-ng -r /path/to/recon_ng/workspace.rc
```

**SpiderFoot:**
```
New Scan → paste targets from spiderfoot/targets.txt
```

---

## Tested On

- BlackArch Linux (Arch-based)
- bash 5.x

---

## License

MIT
