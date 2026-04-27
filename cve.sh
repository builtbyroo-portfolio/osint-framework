#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CVE.SH v1.0 — CVE Discovery & Exploitation Reporter        ║
# ║  Fingerprint · NVD Lookup · Exploit Search · PoC · Report    ║
# ║  Integrates with hunt-suite (lib.sh, hunt.sh output)         ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Standalone:  ./cve.sh -t "Target" -d domains.txt -p bugcrowd
#   From hunt:   ./cve.sh -t "Target" -d domains.txt --hunt-dir ./hunts/Target_*
#   Resume:      ./cve.sh --resume ./hunts/Target_CVE_20260305_*/
#   Single host: ./cve.sh -t "Target" -u https://example.com -p hackerone
#
# Phases:
#   1. Technology Fingerprinting (whatweb, httpx, nmap service scan)
#   2. Version Extraction & Normalization (CPE mapping)
#   3. CVE Lookup (NVD API + CISA KEV + local nuclei templates)
#   4. Exploit Discovery (searchsploit, GitHub PoC repos, nuclei)
#   5. Safe Validation (non-destructive checks, version confirmation)
#   6. Evidence Capture (curl responses, headers, screenshots)
#   7. Report Generation (Bugcrowd/H1 markdown with CVSS + PoC)
#   8. Summary & Triage Recommendations

set -uo pipefail

# ── Source shared library ───────────────────────────────────────
HUNT_DIR="$(dirname "$(readlink -f "$0")")"
source "${HUNT_DIR}/lib.sh"

VERSION="1.0.0"
TOOL_NAME="cve.sh"

# ── Defaults ────────────────────────────────────────────────────
TARGET=""
DOMAINS_FILE=""
SINGLE_URL=""
PLATFORM="bugcrowd"
OUT_DIR=""
HUNT_INPUT_DIR=""
RESUME_DIR=""
SKIP_COMPLETED=false
MAX_HOSTS=200
NMAP_TOP_PORTS=100
NVD_API_KEY="${NVD_API_KEY:-}"
SCREENSHOT_TOOL="selenium"

# Phase tracking
declare -A PHASE_TIMES=()
PHASE_STATUS_FILE=""
MANIFEST_FILE=""

# ── Banner ──────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ╔═╗╦  ╦╔═╗
  ║  ╚╗╔╝║╣
  ╚═╝ ╚╝ ╚═╝  v1.0
  CVE Discovery & Exploitation Reporter
EOF
    echo -e "${NC}"
}

# ── Usage ───────────────────────────────────────────────────────
usage() {
    cat << 'EOF'
Usage: cve.sh [OPTIONS]

Required (one of):
  -d, --domains FILE       Domain list (one per line)
  -u, --url URL            Single target URL
  --hunt-dir DIR           Import from hunt.sh output directory

Options:
  -t, --target NAME        Target/program name (for output dir)
  -p, --platform PLATFORM  bugcrowd|hackerone (report format)
  -o, --out DIR            Output directory (default: hunts/TARGET_CVE_TIMESTAMP)
  --resume DIR             Resume from existing output directory
  --max-hosts N            Max hosts to deep-scan (default: 200)
  --nmap-ports N           Nmap top-N ports (default: 100)
  --nvd-key KEY            NVD API key (2x rate limit)
  -h, --help               Show this help
EOF
    exit 0
}

# ── Argument parsing ────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)    TARGET="$2"; shift 2 ;;
            -d|--domains)   DOMAINS_FILE="$2"; shift 2 ;;
            -u|--url)       SINGLE_URL="$2"; shift 2 ;;
            -p|--platform)  PLATFORM="$2"; shift 2 ;;
            -o|--out)       OUT_DIR="$2"; shift 2 ;;
            --hunt-dir)     HUNT_INPUT_DIR="$2"; shift 2 ;;
            --resume)       RESUME_DIR="$2"; SKIP_COMPLETED=true; shift 2 ;;
            --max-hosts)    MAX_HOSTS="$2"; shift 2 ;;
            --nmap-ports)   NMAP_TOP_PORTS="$2"; shift 2 ;;
            --nvd-key)      NVD_API_KEY="$2"; shift 2 ;;
            -h|--help)      usage ;;
            *)              err "Unknown option: $1"; usage ;;
        esac
    done

    # Validate inputs
    if [[ -z "$RESUME_DIR" ]]; then
        if [[ -z "$DOMAINS_FILE" && -z "$SINGLE_URL" && -z "$HUNT_INPUT_DIR" ]]; then
            err "Need one of: -d domains.txt, -u URL, or --hunt-dir DIR"
            usage
        fi
        [[ -z "$TARGET" ]] && TARGET="CVE_Scan"
    fi
}

# ── Setup output directory ──────────────────────────────────────
setup_output() {
    if [[ -n "$RESUME_DIR" ]]; then
        OUT_DIR="$RESUME_DIR"
        PHASE_STATUS_FILE="${OUT_DIR}/phase_status.txt"
        MANIFEST_FILE="${OUT_DIR}/manifest.json"
        log "Resuming from ${OUT_DIR}"
        return
    fi

    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local safe_target
    safe_target=$(echo "$TARGET" | tr ' /' '_')

    if [[ -z "$OUT_DIR" ]]; then
        OUT_DIR="${HUNT_DIR}/hunts/${safe_target}_CVE_${timestamp}"
    fi

    mkdir -p "${OUT_DIR}"/{fingerprints,cves,exploits,evidence,reports,screenshots}
    PHASE_STATUS_FILE="${OUT_DIR}/phase_status.txt"
    MANIFEST_FILE="${OUT_DIR}/manifest.json"
    touch "$PHASE_STATUS_FILE"

    # Initialize manifest
    cat > "$MANIFEST_FILE" << EOJSON
{
  "tool": "${TOOL_NAME}",
  "version": "${VERSION}",
  "target": "${TARGET}",
  "platform": "${PLATFORM}",
  "started": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "output_dir": "${OUT_DIR}"
}
EOJSON

    log "Output directory: ${OUT_DIR}"
}

# ── Phase tracking (same pattern as hunt.sh) ────────────────────
phase_done() { grep -q "^$1:DONE" "$PHASE_STATUS_FILE" 2>/dev/null; }

mark_phase_done() {
    echo "$1:DONE:$(date '+%s')" >> "$PHASE_STATUS_FILE"
}

start_phase() {
    local num="$1" name="$2"
    if $SKIP_COMPLETED && phase_done "$num"; then
        info "Phase ${num} already complete — skipping"
        return 1
    fi
    phase_header "$num" "$name"
    PHASE_TIMES[$num]=$(date '+%s')
    return 0
}

end_phase() {
    local num="$1"
    local start=${PHASE_TIMES[$num]:-$(date '+%s')}
    local elapsed=$(( $(date '+%s') - start ))
    mark_phase_done "$num"
    info "Phase ${num} completed in ${elapsed}s"
}

# ── Prepare target list ─────────────────────────────────────────
prepare_targets() {
    local targets_file="${OUT_DIR}/targets.txt"

    if [[ -n "$SINGLE_URL" ]]; then
        echo "$SINGLE_URL" > "$targets_file"
    elif [[ -n "$HUNT_INPUT_DIR" ]]; then
        # Import live hosts from hunt.sh output
        # hunt.sh live_hosts_raw.txt format: "URL [status] [size] [title] [tech]"
        # hunt.sh live_hosts_json.txt format: httpx JSON (one object per line)
        if [[ -f "${HUNT_INPUT_DIR}/live_hosts_json.txt" ]]; then
            # Best source: extract URLs from httpx JSON output
            jq -r '.url // empty' "${HUNT_INPUT_DIR}/live_hosts_json.txt" 2>/dev/null > "$targets_file"
            # Copy JSON as-is for Phase 1 tech extraction (skip re-scanning)
            cp "${HUNT_INPUT_DIR}/live_hosts_json.txt" "${OUT_DIR}/fingerprints/httpx_tech.json" 2>/dev/null
            log "Imported $(count_lines "$targets_file") live hosts from hunt.sh (JSON)"
        elif [[ -f "${HUNT_INPUT_DIR}/live_hosts_raw.txt" ]]; then
            # Fallback: strip bracket metadata — extract first field (URL only)
            awk '{print $1}' "${HUNT_INPUT_DIR}/live_hosts_raw.txt" > "$targets_file"
            log "Imported $(count_lines "$targets_file") live hosts from hunt.sh (raw)"
        elif [[ -f "${HUNT_INPUT_DIR}/subdomains.txt" ]]; then
            cp "${HUNT_INPUT_DIR}/subdomains.txt" "$targets_file"
            log "Imported $(count_lines "$targets_file") subdomains from hunt.sh"
        fi
    elif [[ -n "$DOMAINS_FILE" ]]; then
        cp "$DOMAINS_FILE" "$targets_file"
    fi

    # Deduplicate
    sort -u "$targets_file" -o "$targets_file"
    log "Total targets: $(count_lines "$targets_file")"
}

# ════════════════════════════════════════════════════════════════
# PHASE 1: Technology Fingerprinting
# ════════════════════════════════════════════════════════════════
phase1_fingerprint() {
    start_phase 1 "Technology Fingerprinting" || return 0

    local targets_file="${OUT_DIR}/targets.txt"
    local fp_dir="${OUT_DIR}/fingerprints"
    local live_file="${fp_dir}/live_hosts.txt"
    local whatweb_file="${fp_dir}/whatweb_results.json"
    local httpx_file="${fp_dir}/httpx_tech.json"
    local nmap_dir="${fp_dir}/nmap"
    mkdir -p "$nmap_dir"

    # Step 1: Probe live hosts with httpx + tech detection
    if [[ -s "$httpx_file" ]]; then
        # Already imported from hunt.sh — skip re-scanning
        log "Using pre-imported httpx data ($(wc -l < "$httpx_file") entries)"
        jq -r '.url // empty' "$httpx_file" 2>/dev/null | sort -u > "$live_file"
        log "Live hosts: $(count_lines "$live_file")"
    elif [[ -f "$targets_file" ]]; then
        log "Probing live hosts with httpx (tech detection)..."
        httpx -l "$targets_file" -silent -json \
            -tech-detect -status-code -title -server -content-type \
            -follow-redirects -threads "$THREADS" \
            ${HUNT_UA_ARGS[@]+"${HUNT_UA_ARGS[@]}"} \
            -o "$httpx_file" 2>/dev/null

        # Extract live URLs
        jq -r '.url // empty' "$httpx_file" 2>/dev/null | sort -u > "$live_file"
        log "Live hosts: $(count_lines "$live_file")"
    fi

    # Step 2: WhatWeb deep fingerprint on live hosts (capped)
    if check_tool whatweb && [[ -s "$live_file" ]]; then
        log "Running WhatWeb fingerprinting (max ${MAX_HOSTS} hosts)..."
        head -n "$MAX_HOSTS" "$live_file" | while IFS= read -r url; do
            whatweb --color=never -a 3 --log-json="${whatweb_file}.tmp" "$url" 2>/dev/null
            [[ -f "${whatweb_file}.tmp" ]] && cat "${whatweb_file}.tmp" >> "$whatweb_file" && rm -f "${whatweb_file}.tmp"
        done
        log "WhatWeb results: $(wc -l < "$whatweb_file" 2>/dev/null || echo 0) entries"
    fi

    # Step 3: Nmap service/version scan on unique IPs
    # If importing from hunt.sh, try to reuse its nmap data first
    if [[ -n "$HUNT_INPUT_DIR" && -f "${HUNT_INPUT_DIR}/nmap_results.txt" ]]; then
        log "Importing nmap data from hunt.sh..."
        cp "${HUNT_INPUT_DIR}/nmap_results.txt" "${nmap_dir}/service_scan.nmap" 2>/dev/null
        cp "${HUNT_INPUT_DIR}/nmap_greppable.txt" "${nmap_dir}/service_scan.gnmap" 2>/dev/null
        # hunt.sh doesn't run -sV by default, so still do a targeted version scan on top hosts
        log "Running targeted nmap -sV on top ${MAX_HOSTS} hosts..."
        local ips_file="${fp_dir}/unique_ips.txt"
        sed 's|https\?://||;s|/.*||;s|:.*||' "$live_file" | sort -u | head -n "$MAX_HOSTS" | \
            while IFS= read -r host; do
                dig +short "$host" A 2>/dev/null | grep -E '^\d+\.\d+\.\d+\.\d+$'
            done | sort -u > "$ips_file"
        local ip_count
        ip_count=$(count_lines "$ips_file")
        if [[ "$ip_count" -gt 0 && "$ip_count" -le 200 ]]; then
            nmap -sV --top-ports "$NMAP_TOP_PORTS" \
                -oA "${nmap_dir}/service_scan" \
                -iL "$ips_file" \
                --min-rate 300 --max-retries 2 \
                2>/dev/null
            log "Nmap -sV scan complete (${ip_count} IPs)"
        else
            log "Skipping nmap -sV (${ip_count} IPs too many, using httpx data only)"
        fi
    elif [[ -s "$live_file" ]]; then
        log "Extracting unique IPs for nmap service scan..."
        local ips_file="${fp_dir}/unique_ips.txt"
        sed 's|https\?://||;s|/.*||;s|:.*||' "$live_file" | sort -u | \
            while IFS= read -r host; do
                dig +short "$host" A 2>/dev/null | grep -E '^\d+\.\d+\.\d+\.\d+$'
            done | sort -u > "$ips_file"
        local ip_count
        ip_count=$(count_lines "$ips_file")
        if [[ "$ip_count" -gt 0 ]]; then
            log "Scanning ${ip_count} unique IPs with nmap -sV..."
            nmap -sV -sC --top-ports "$NMAP_TOP_PORTS" \
                -oA "${nmap_dir}/service_scan" \
                -iL "$ips_file" \
                --min-rate 300 --max-retries 2 \
                2>/dev/null
            log "Nmap scan complete: ${nmap_dir}/service_scan.*"
        fi
    fi

    # Step 4: Extract and normalize technology stack
    log "Building technology inventory..."
    python3 "${HUNT_DIR}/scripts/cve_extract_tech.py" \
        --httpx "$httpx_file" \
        --whatweb "$whatweb_file" \
        --nmap "${nmap_dir}/service_scan.xml" \
        --output "${fp_dir}/tech_inventory.json" \
        2>/dev/null || warn "Tech extraction had errors (continuing)"

    end_phase 1
}

# ════════════════════════════════════════════════════════════════
# PHASE 2: Version Extraction & CPE Mapping
# ════════════════════════════════════════════════════════════════
phase2_versions() {
    start_phase 2 "Version Extraction & CPE Mapping" || return 0

    local fp_dir="${OUT_DIR}/fingerprints"
    local cve_dir="${OUT_DIR}/cves"

    log "Extracting versions and mapping to CPE identifiers..."
    python3 "${HUNT_DIR}/scripts/cve_version_map.py" \
        --tech-inventory "${fp_dir}/tech_inventory.json" \
        --httpx "${fp_dir}/httpx_tech.json" \
        --nmap "${fp_dir}/nmap/service_scan.xml" \
        --output "${cve_dir}/version_map.json" \
        2>/dev/null

    local count
    count=$(jq 'length' "${cve_dir}/version_map.json" 2>/dev/null || echo 0)
    log "Mapped ${count} technology+version pairs to CPEs"

    end_phase 2
}

# ════════════════════════════════════════════════════════════════
# PHASE 3: CVE Lookup (NVD + CISA KEV + Nuclei)
# ════════════════════════════════════════════════════════════════
phase3_cve_lookup() {
    start_phase 3 "CVE Lookup (NVD + CISA KEV)" || return 0

    local cve_dir="${OUT_DIR}/cves"

    log "Querying NVD API and CISA KEV for known CVEs..."
    python3 "${HUNT_DIR}/scripts/cve_lookup.py" \
        --version-map "${cve_dir}/version_map.json" \
        --output "${cve_dir}/cve_matches.json" \
        --kev-output "${cve_dir}/kev_matches.json" \
        ${NVD_API_KEY:+--nvd-key "$NVD_API_KEY"} \
        2>/dev/null

    local total kev
    total=$(jq 'length' "${cve_dir}/cve_matches.json" 2>/dev/null || echo 0)
    kev=$(jq 'length' "${cve_dir}/kev_matches.json" 2>/dev/null || echo 0)
    log "CVE matches: ${total} total, ${kev} in CISA KEV (actively exploited)"

    # Run nuclei with CVE templates for validation
    local live_file="${OUT_DIR}/fingerprints/live_hosts.txt"
    if check_tool nuclei && [[ -s "$live_file" ]]; then
        log "Running nuclei CVE templates..."
        nuclei -l "$live_file" \
            -t "${NUCLEI_TEMPLATES}/http/cves/" \
            -severity critical,high,medium \
            -json -o "${cve_dir}/nuclei_cve_results.json" \
            -rate-limit 50 -bulk-size 25 -concurrency 10 \
            ${HUNT_UA_ARGS[@]+"${HUNT_UA_ARGS[@]}"} \
            -silent 2>/dev/null
        local nuclei_count
        nuclei_count=$(wc -l < "${cve_dir}/nuclei_cve_results.json" 2>/dev/null || echo 0)
        log "Nuclei CVE hits: ${nuclei_count}"
    fi

    end_phase 3
}

# ════════════════════════════════════════════════════════════════
# PHASE 4: Exploit Discovery
# ════════════════════════════════════════════════════════════════
phase4_exploits() {
    start_phase 4 "Exploit Discovery (SearchSploit + GitHub)" || return 0

    local cve_dir="${OUT_DIR}/cves"
    local exp_dir="${OUT_DIR}/exploits"

    log "Searching for public exploits..."
    python3 "${HUNT_DIR}/scripts/cve_exploit_search.py" \
        --cve-matches "${cve_dir}/cve_matches.json" \
        --nuclei-results "${cve_dir}/nuclei_cve_results.json" \
        --output "${exp_dir}/exploit_map.json" \
        2>/dev/null

    local count
    count=$(jq 'length' "${exp_dir}/exploit_map.json" 2>/dev/null || echo 0)
    log "Exploits found: ${count} (searchsploit + GitHub PoC repos)"

    end_phase 4
}

# ════════════════════════════════════════════════════════════════
# PHASE 5: Safe Validation
# ════════════════════════════════════════════════════════════════
phase5_validate() {
    start_phase 5 "Safe Exploitation Validation" || return 0

    local exp_dir="${OUT_DIR}/exploits"
    local evidence_dir="${OUT_DIR}/evidence"

    log "Validating exploitability with safe checks..."
    python3 "${HUNT_DIR}/scripts/cve_validate.py" \
        --exploit-map "${exp_dir}/exploit_map.json" \
        --output "${evidence_dir}/validated_cves.json" \
        --curl-output "${evidence_dir}/curl_evidence/" \
        2>/dev/null

    local validated
    validated=$(jq '[.[] | select(.validated == true)] | length' "${evidence_dir}/validated_cves.json" 2>/dev/null || echo 0)
    log "Validated exploitable: ${validated}"

    end_phase 5
}

# ════════════════════════════════════════════════════════════════
# PHASE 6: Evidence Capture (Screenshots + Response Data)
# ════════════════════════════════════════════════════════════════
phase6_evidence() {
    start_phase 6 "Evidence Capture" || return 0

    local evidence_dir="${OUT_DIR}/evidence"
    local ss_dir="${OUT_DIR}/screenshots"

    log "Capturing evidence (screenshots + response data)..."
    python3 "${HUNT_DIR}/scripts/cve_evidence.py" \
        --validated "${evidence_dir}/validated_cves.json" \
        --screenshot-dir "$ss_dir" \
        --evidence-dir "$evidence_dir" \
        --method "$SCREENSHOT_TOOL" \
        2>/dev/null

    local screenshots
    screenshots=$(ls "$ss_dir"/*.png 2>/dev/null | wc -l)
    log "Screenshots captured: ${screenshots}"

    end_phase 6
}

# ════════════════════════════════════════════════════════════════
# PHASE 6.5: Impact Gate — Kill doomed findings before report
# ════════════════════════════════════════════════════════════════
phase6_5_impact_gate() {
    local validated_in="${OUT_DIR}/evidence/validated_cves.json"
    local gated_out="${OUT_DIR}/evidence/gated_cves.json"

    [[ ! -f "$validated_in" ]] && return 0

    log "Running impact gate (filtering known-rejected patterns)..."
    python3 "${HUNT_DIR}/scripts/impact_gate.py" \
        --input "$validated_in" \
        --output "$gated_out" \
        2>/dev/null

    if [[ -f "$gated_out" ]]; then
        local before after killed
        before=$(python3 -c "import json; print(len(json.load(open('$validated_in'))))" 2>/dev/null || echo "?")
        after=$(python3 -c "import json; print(len(json.load(open('$gated_out'))))" 2>/dev/null || echo "?")
        killed=$((before - after))
        log "Impact gate: ${after} passed, ${killed} killed (of ${before} total)"
        if [[ -f "${gated_out%.json}.killed.json" ]]; then
            log "Kill log: ${gated_out%.json}.killed.json"
        fi
    fi
}

# ════════════════════════════════════════════════════════════════
# PHASE 7: Report Generation
# ════════════════════════════════════════════════════════════════
phase7_reports() {
    start_phase 7 "Report Generation" || return 0

    # Run impact gate first
    phase6_5_impact_gate

    local reports_dir="${OUT_DIR}/reports"
    # Use gated findings if available, fall back to validated
    local findings_file="${OUT_DIR}/evidence/gated_cves.json"
    [[ ! -f "$findings_file" ]] && findings_file="${OUT_DIR}/evidence/validated_cves.json"

    log "Generating submission-ready reports..."
    python3 "${HUNT_DIR}/scripts/cve_report.py" \
        --validated "$findings_file" \
        --evidence-dir "${OUT_DIR}/evidence" \
        --screenshot-dir "${OUT_DIR}/screenshots" \
        --platform "$PLATFORM" \
        --target "$TARGET" \
        --output-dir "$reports_dir" \
        2>/dev/null

    local report_count
    report_count=$(ls "$reports_dir"/*.md 2>/dev/null | wc -l)
    log "Reports generated: ${report_count}"

    end_phase 7
}

# ════════════════════════════════════════════════════════════════
# PHASE 8: Summary & Triage
# ════════════════════════════════════════════════════════════════
phase8_summary() {
    start_phase 8 "Summary & Triage Recommendations" || return 0

    local summary_file="${OUT_DIR}/CVE_SUMMARY.md"
    local evidence_dir="${OUT_DIR}/evidence"
    local reports_dir="${OUT_DIR}/reports"

    log "Building final summary..."
    python3 "${HUNT_DIR}/scripts/cve_summary.py" \
        --validated "${evidence_dir}/validated_cves.json" \
        --reports-dir "$reports_dir" \
        --platform "$PLATFORM" \
        --target "$TARGET" \
        --output "$summary_file" \
        2>/dev/null

    echo ""
    echo -e "${BOLD}════════════════════════════════════════${NC}"
    echo -e "${BOLD}  CVE.SH SCAN COMPLETE${NC}"
    echo -e "${BOLD}════════════════════════════════════════${NC}"

    if [[ -f "$summary_file" ]]; then
        cat "$summary_file"
    fi

    echo ""
    log "Full output: ${OUT_DIR}"
    log "Reports: ${reports_dir}/"
    log "Evidence: ${evidence_dir}/"

    end_phase 8
}

# ── Main ────────────────────────────────────────────────────────
main() {
    banner
    parse_args "$@"
    setup_output
    prepare_targets

    phase1_fingerprint
    phase2_versions
    phase3_cve_lookup
    phase4_exploits
    phase5_validate
    phase6_evidence
    phase7_reports
    phase8_summary
}

main "$@"
