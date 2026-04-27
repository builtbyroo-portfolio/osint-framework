#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CACHE.SH v1.0.0 — Cache & Transport Attack Scanner          ║
# ║  Cache poisoning · Deception · Smuggling · Host attacks       ║
# ║  Per-phase timing · Resume support · VRT-aware output          ║
# ║  JSON manifest · Auto-validation · Error recovery              ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Interactive:  ./cache.sh
#   CLI mode:     ./cache.sh --target "Acme Corp" --domains domains.txt \
#                   --platform bugcrowd --out ./output
#   Resume:       ./cache.sh --resume ./hunts/Acme_CACHE_20260303_120000
#   Single phase: ./scripts/ct_fingerprint.sh -d example.com -o ./out
#
# Each script in scripts/ can run standalone or be chained here.

set -uo pipefail

# ── Source shared library ───────────────────────────────────────
HUNT_DIR="$(dirname "$(readlink -f "$0")")"
source "${HUNT_DIR}/lib.sh"

VERSION="1.0.0"

# Resume mode
RESUME_DIR=""
SKIP_COMPLETED=false

# Phase tracking
declare -A PHASE_TIMES=()
PHASE_STATUS_FILE=""
MANIFEST_FILE=""

# ── Banner ──────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
   ╔═╗╔═╗╔═╗╦ ╦╔═╗
   ║  ╠═╣║  ╠═╣║╣
   ╚═╝╩ ╩╚═╝╩ ╩╚═╝ v1.0
   Cache & Transport Attack Scanner
EOF
    echo -e "${NC}"
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    local required=(curl python3 dig)
    local optional=(smuggler smuggler-py h2csmuggler nmap)

    info "Checking required tools..."
    for tool in "${required[@]}"; do
        check_tool "$tool" || missing+=("$tool")
    done

    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing required tools: ${missing[*]}"
        echo "  Install with: sudo pacman -S ${missing[*]}"
        exit 1
    fi

    info "Checking optional tools..."
    for tool in "${optional[@]}"; do
        check_tool "$tool" 2>/dev/null || true
    done

    # Scripts check
    info "Checking scripts/ directory..."
    local scripts=(ct_fingerprint ct_cache_poison ct_cache_deception ct_smuggle_detect ct_smuggle_h2c ct_host_header ct_desync ct_cdn_bypass)
    for script in "${scripts[@]}"; do
        if [ -x "${SCRIPTS_DIR}/${script}.sh" ]; then
            log "  Script: ${script}.sh ✓"
        else
            err "  Script: ${script}.sh MISSING"
        fi
    done

    log "Dependency check passed"
}

# ── Interactive prompts ───────────────────────────────────────
prompt_config() {
    echo ""
    echo -e "${BOLD}── Target Configuration ──${NC}"
    echo ""

    if [ -z "${TARGET_NAME:-}" ]; then
        read -rp "$(echo -e "${CYAN}Target name${NC} (e.g., Acme Corp): ")" TARGET_NAME
        [ -z "$TARGET_NAME" ] && err "Target name is required" && exit 1
    fi

    if [ -z "${PLATFORM:-}" ]; then
        echo ""
        echo "  1) Bugcrowd"
        echo "  2) HackerOne"
        echo "  3) Other"
        read -rp "$(echo -e "${CYAN}Platform${NC} [1/2/3]: ")" platform_choice
        case "$platform_choice" in
            1) PLATFORM="bugcrowd" ;;
            2) PLATFORM="hackerone" ;;
            *) PLATFORM="other" ;;
        esac
    fi

    if [ -z "${DOMAINS_FILE:-}" ]; then
        echo ""
        echo -e "  Enter target domains ${YELLOW}(one per line, blank line to finish)${NC}:"
        echo "  Examples: example.com  |  cdn.example.com"
        echo ""
        DOMAINS_FILE="${OUT_DIR}/domains.txt"
        > "$DOMAINS_FILE"
        while true; do
            read -rp "  > " domain_entry
            [ -z "$domain_entry" ] && break
            echo "$domain_entry" >> "$DOMAINS_FILE"
        done
        if [ ! -s "$DOMAINS_FILE" ]; then
            err "At least one domain is required"
            exit 1
        fi
    fi

    if [ -z "${MAX_BOUNTY:-}" ]; then
        read -rp "$(echo -e "${CYAN}Max critical payout${NC} (e.g., \$25000, or press Enter to skip): ")" MAX_BOUNTY
        MAX_BOUNTY="${MAX_BOUNTY:-unknown}"
    fi

    if [ -z "${SCOPE_NOTES:-}" ]; then
        read -rp "$(echo -e "${CYAN}Scope notes${NC} (e.g., 'CDN in scope', or Enter to skip): ")" SCOPE_NOTES
        SCOPE_NOTES="${SCOPE_NOTES:-none}"
    fi

    read -rp "$(echo -e "${CYAN}Threads${NC} [${THREADS}]: ")" custom_threads
    THREADS="${custom_threads:-$THREADS}"

    echo ""
    echo -e "${BOLD}── Configuration Summary ──${NC}"
    echo "  Target:       ${TARGET_NAME}"
    echo "  Platform:     ${PLATFORM}"
    echo "  Domains:      $(count_lines "$DOMAINS_FILE") entries"
    echo "  Max payout:   ${MAX_BOUNTY}"
    echo "  Threads:      ${THREADS}"
    echo "  Output:       ${OUT_DIR}/"
    echo ""
    read -rp "$(echo -e "${YELLOW}Proceed? [Y/n]:${NC} ")" confirm
    [[ "$confirm" =~ ^[Nn] ]] && echo "Aborted." && exit 0
}

# ── Parse CLI args ────────────────────────────────────────────
parse_args() {
    TARGET_NAME="" PLATFORM="" DOMAINS_FILE="" OUT_DIR="" MAX_BOUNTY="" SCOPE_NOTES=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --target|-t)  TARGET_NAME="$2"; shift 2 ;;
            --domains|-d) DOMAINS_FILE="$2"; shift 2 ;;
            --platform|-p) PLATFORM="$2"; shift 2 ;;
            --out|-o)     OUT_DIR="$2"; shift 2 ;;
            --bounty)     MAX_BOUNTY="$2"; shift 2 ;;
            --scope)      SCOPE_NOTES="$2"; shift 2 ;;
            --threads)    THREADS="$2"; shift 2 ;;
            --submitted)  SUBMITTED_FILE="$2"; shift 2 ;;
            --resume)     RESUME_DIR="$2"; SKIP_COMPLETED=true; shift 2 ;;
            --mark-submitted) mark_submitted "$2" "${3:-}"; exit 0 ;;
            --list-submitted) list_submitted; exit 0 ;;
            --version|-v) echo "cache.sh v${VERSION}"; exit 0 ;;
            --help|-h)    usage; exit 0 ;;
            *)            err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUT_DIR="${OUT_DIR:-./hunts/${SAFE_NAME}_CACHE_${TIMESTAMP}}"
    mkdir -p "$OUT_DIR"
}

usage() {
    echo "Usage: cache.sh [OPTIONS]"
    echo ""
    echo "Interactive mode (no args):  ./cache.sh"
    echo ""
    echo "Cache & Transport Attack Scanner — tests web cache poisoning,"
    echo "cache deception, HTTP request smuggling (CL.TE/TE.CL/h2c),"
    echo "host header attacks, HTTP desync, and CDN/WAF origin bypass."
    echo ""
    echo "Options:"
    echo "  -t, --target NAME      Target name (e.g., 'Acme Corp')"
    echo "  -d, --domains FILE     File with domains (one per line)"
    echo "  -p, --platform NAME    Platform: bugcrowd, hackerone, other"
    echo "  -o, --out DIR          Output directory"
    echo "  --bounty AMOUNT        Max critical payout"
    echo "  --scope NOTES          Scope notes"
    echo "  --threads N            Concurrency level (default: 30)"
    echo "  --resume DIR           Resume a previous hunt from its output directory"
    echo "  --submitted FILE       Custom submitted findings tracker file"
    echo "  --mark-submitted PAT   Add a pattern to submitted tracker and exit"
    echo "  --list-submitted       Show all submitted finding patterns and exit"
    echo "  -v, --version          Show version"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Standalone scripts (run individually):"
    echo "  scripts/ct_fingerprint.sh      CDN & cache fingerprinting"
    echo "  scripts/ct_cache_poison.sh     Web cache poisoning"
    echo "  scripts/ct_cache_deception.sh  Web cache deception"
    echo "  scripts/ct_smuggle_detect.sh   HTTP request smuggling detection"
    echo "  scripts/ct_smuggle_h2c.sh      HTTP/2 cleartext smuggling"
    echo "  scripts/ct_host_header.sh      Host header attacks"
    echo "  scripts/ct_desync.sh           HTTP desync & connection abuse"
    echo "  scripts/ct_cdn_bypass.sh       CDN/WAF origin bypass"
}

# ══════════════════════════════════════════════════════════════
#                  PHASE TRACKING & RESUME
# ══════════════════════════════════════════════════════════════

init_phase_tracking() {
    PHASE_STATUS_FILE="${OUT_DIR}/phase_status.txt"
    MANIFEST_FILE="${OUT_DIR}/manifest.json"

    if [ ! -f "$PHASE_STATUS_FILE" ]; then
        > "$PHASE_STATUS_FILE"
    fi
}

phase_completed() {
    local phase_name="$1"
    grep -qF "${phase_name}=done" "$PHASE_STATUS_FILE" 2>/dev/null
}

mark_phase_done() {
    local phase_name="$1"
    local duration="$2"
    echo "${phase_name}=done duration=${duration}s" >> "$PHASE_STATUS_FILE"
}

run_phase() {
    local phase_num="$1"
    local phase_name="$2"
    local script_name="$3"
    shift 3

    # Resume: skip if already completed
    if $SKIP_COMPLETED && phase_completed "$phase_name"; then
        warn "Phase ${phase_num} (${phase_name}) already completed — skipping"
        return 0
    fi

    phase_header "$phase_num" "$phase_name"

    local start_time
    start_time=$(date +%s)

    local script_path="${SCRIPTS_DIR}/${script_name}"
    if [ ! -x "$script_path" ]; then
        err "Script not found or not executable: ${script_path}"
        err "Phase ${phase_num} SKIPPED"
        return 0
    fi

    # Export env vars for child scripts
    export BHEH_DIR SUBMITTED_FILE THREADS NUCLEI_TEMPLATES SECLISTS HUNT_UA
    [ -n "${HTTP_PROXY:-}" ] && export HTTP_PROXY
    [ -n "${HTTPS_PROXY:-}" ] && export HTTPS_PROXY

    # Run with error recovery
    if bash "$script_path" "$@"; then
        local end_time elapsed
        end_time=$(date +%s)
        elapsed=$(( end_time - start_time ))
        PHASE_TIMES[$phase_name]=$elapsed
        mark_phase_done "$phase_name" "$elapsed"
        log "Phase ${phase_num} completed in $(format_duration $elapsed)"
    else
        local exit_code=$?
        local end_time elapsed
        end_time=$(date +%s)
        elapsed=$(( end_time - start_time ))
        PHASE_TIMES[$phase_name]=$elapsed
        err "Phase ${phase_num} (${phase_name}) FAILED (exit ${exit_code}) after $(format_duration $elapsed)"
        err "Continuing to next phase..."
    fi
}

format_duration() {
    local secs=$1
    if [ "$secs" -ge 3600 ]; then
        printf "%dh %dm %ds" $((secs/3600)) $((secs%3600/60)) $((secs%60))
    elif [ "$secs" -ge 60 ]; then
        printf "%dm %ds" $((secs/60)) $((secs%60))
    else
        printf "%ds" "$secs"
    fi
}

# ══════════════════════════════════════════════════════════════
#                   AUTO-VALIDATION
# ══════════════════════════════════════════════════════════════

validate_findings() {
    local finding_files=(
        ct_fingerprint_findings.txt ct_cache_poison_findings.txt
        ct_cache_deception_findings.txt ct_smuggle_detect_findings.txt
        ct_h2c_smuggle_findings.txt ct_host_header_findings.txt
        ct_desync_findings.txt ct_cdn_bypass_findings.txt
    )
    local total=0 confirmed=0 high_confidence=0
    local validated_file="${OUT_DIR}/validated_findings.txt"
    local priority_file="${OUT_DIR}/priority_findings.txt"

    > "$validated_file"
    > "$priority_file"

    for ff in "${finding_files[@]}"; do
        local fpath="${OUT_DIR}/${ff}"
        [ ! -s "$fpath" ] && continue
        local finding_type="${ff%_findings.txt}"
        finding_type="${finding_type#ct_}"

        while IFS= read -r line; do
            ((total++)) || true
            local url
            url=$(echo "$line" | grep -oP 'https?://[^\s\]\)]+' | head -1)
            [ -z "$url" ] && url=$(echo "$line" | awk '{print $NF}')

            local status validation_detail=""

            if echo "$url" | grep -qP '^https?://'; then
                status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 30 \
                    --retry 2 --retry-delay 5 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")
            else
                status="N/A"
            fi

            # Type-aware severity classification
            case "$finding_type" in
                cache_poison)
                    if echo "$line" | grep -qi "POISON_CONFIRMED\|REFLECTED_CACHED\|UNKEYED_HEADER"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CACHE_POISON] ${line}" >> "$priority_file"
                        validation_detail="CACHE_POISON"
                    fi
                    ;;
                cache_deception)
                    if echo "$line" | grep -qi "DECEPTION_CONFIRMED\|AUTH_DATA_CACHED\|SENSITIVE_CACHED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CACHE_DECEPTION] ${line}" >> "$priority_file"
                        validation_detail="CACHE_DECEPTION"
                    fi
                    ;;
                smuggle_detect)
                    if echo "$line" | grep -qi "CL_TE\|TE_CL\|SMUGGLE_CONFIRMED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:SMUGGLING] ${line}" >> "$priority_file"
                        validation_detail="SMUGGLING"
                    fi
                    ;;
                h2c_smuggle)
                    if echo "$line" | grep -qi "H2C_BYPASS\|ACCESS_CONTROL_BYPASS\|H2C_CONFIRMED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:H2C_SMUGGLE] ${line}" >> "$priority_file"
                        validation_detail="H2C_SMUGGLE"
                    fi
                    ;;
                host_header)
                    if echo "$line" | grep -qi "RESET_POISON\|HOST_INJECT\|ROUTING_ABUSE"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:HOST_INJECT] ${line}" >> "$priority_file"
                        validation_detail="HOST_INJECT"
                    fi
                    ;;
                desync)
                    if echo "$line" | grep -qi "DESYNC_CONFIRMED\|TE_MISMATCH\|CL_MISMATCH"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:DESYNC] ${line}" >> "$priority_file"
                        validation_detail="DESYNC"
                    fi
                    ;;
                cdn_bypass)
                    if echo "$line" | grep -qi "ORIGIN_EXPOSED\|WAF_BYPASSED\|DIRECT_IP"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CDN_BYPASS] ${line}" >> "$priority_file"
                        validation_detail="CDN_BYPASS"
                    fi
                    ;;
            esac

            if [[ "$status" =~ ^(200|301|302|401|403|500)$ ]]; then
                echo "[CONFIRMED:${status}${validation_detail:+ ${validation_detail}}] ${line}" >> "$validated_file"
                ((confirmed++)) || true
            else
                echo "[UNCONFIRMED:${status}${validation_detail:+ ${validation_detail}}] ${line}" >> "$validated_file"
            fi
        done < "$fpath"
    done

    # ── Apply Bugcrowd Universal Exclusion Filter ──
    local tmp_excl; tmp_excl=$(mktemp)
    filter_standard_exclusions "$validated_file" "$tmp_excl"
    mv "$tmp_excl" "$validated_file"
    local tmp_scope; tmp_scope=$(mktemp)
    filter_oos_findings "$validated_file" "$tmp_scope"
    mv "$tmp_scope" "$validated_file"

    local dns_count
    dns_count=$(grep -c '^\[DO_NOT_SUBMIT' "$validated_file" 2>/dev/null || echo 0)
    local std_excl_count
    std_excl_count=$(grep -c '^\[DO_NOT_SUBMIT:STANDARD_EXCLUSION\]' "$validated_file" 2>/dev/null || echo 0)

    if [ "$total" -gt 0 ]; then
        log "Validation: ${confirmed}/${total} findings confirmed"
        if [ "$dns_count" -gt 0 ]; then
            warn "DO_NOT_SUBMIT total: ${dns_count}"
        fi
        if [ "$std_excl_count" -gt 0 ]; then
            warn "Bugcrowd standard exclusions (P5): ${std_excl_count}"
        fi
        if [ "$high_confidence" -gt 0 ]; then
            warn "HIGH-CONFIDENCE findings: ${high_confidence} (see priority_findings.txt)"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════
#                   JSON MANIFEST
# ══════════════════════════════════════════════════════════════

generate_manifest() {
    local finding_types=(fingerprint cache_poison cache_deception smuggle_detect h2c_smuggle host_header desync cdn_bypass)
    local counts=""

    for ff in "${finding_types[@]}"; do
        local count
        count=$(wc -l < "${OUT_DIR}/ct_${ff}_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)
        counts+="\"${ff}\": ${count}, "
    done
    counts="${counts%, }"

    local phase_timings=""
    for phase in "${!PHASE_TIMES[@]}"; do
        phase_timings+="\"${phase}\": ${PHASE_TIMES[$phase]}, "
    done
    phase_timings="${phase_timings%, }"

    local validated_count priority_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)
    priority_count=$(wc -l < "${OUT_DIR}/priority_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)

    cat > "$MANIFEST_FILE" << JSONEOF
{
    "version": "${VERSION}",
    "tool": "cache.sh",
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "timestamp_start": "${HUNT_START_TIME}",
    "timestamp_end": "$(date -Iseconds)",
    "duration_seconds": $(( $(date +%s) - HUNT_START_EPOCH )),
    "threads": ${THREADS},
    "domains_file": "${DOMAINS_FILE}",
    "domains_count": $(wc -l < "$DOMAINS_FILE" | tr -d ' '),
    "output_dir": "${OUT_DIR}",
    "findings": { ${counts} },
    "validated_confirmed": ${validated_count},
    "priority_findings": ${priority_count},
    "phase_durations": { ${phase_timings} },
    "report_file": "${OUT_DIR}/${SAFE_NAME}_CACHE_REPORT.md"
}
JSONEOF
    log "Manifest: ${MANIFEST_FILE}"
}

# ══════════════════════════════════════════════════════════════
#                    REPORT GENERATION
# ══════════════════════════════════════════════════════════════
generate_report() {
    phase_header "R" "Report Generation"

    REPORT_FILE="${OUT_DIR}/${SAFE_NAME}_CACHE_REPORT.md"
    info "Generating ${REPORT_FILE}..."

    # ── Dedup: filter previously-submitted findings ──
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        info "Filtering previously-submitted findings (${sub_count} patterns)..."
        for finding_file in \
            "${OUT_DIR}/ct_fingerprint_findings.txt" \
            "${OUT_DIR}/ct_cache_poison_findings.txt" \
            "${OUT_DIR}/ct_cache_deception_findings.txt" \
            "${OUT_DIR}/ct_smuggle_detect_findings.txt" \
            "${OUT_DIR}/ct_h2c_smuggle_findings.txt" \
            "${OUT_DIR}/ct_host_header_findings.txt" \
            "${OUT_DIR}/ct_desync_findings.txt" \
            "${OUT_DIR}/ct_cdn_bypass_findings.txt"; do
            if [ -s "$finding_file" ]; then
                filter_submitted "$finding_file" "${finding_file}.deduped"
                mv "${finding_file}.deduped" "$finding_file"
            fi
        done
    fi

    # Count findings
    local fp_count poison_count deception_count smuggle_count
    local h2c_count host_count desync_count cdn_count
    fp_count=$(count_lines "${OUT_DIR}/ct_fingerprint_findings.txt" 2>/dev/null || echo 0)
    poison_count=$(count_lines "${OUT_DIR}/ct_cache_poison_findings.txt" 2>/dev/null || echo 0)
    deception_count=$(count_lines "${OUT_DIR}/ct_cache_deception_findings.txt" 2>/dev/null || echo 0)
    smuggle_count=$(count_lines "${OUT_DIR}/ct_smuggle_detect_findings.txt" 2>/dev/null || echo 0)
    h2c_count=$(count_lines "${OUT_DIR}/ct_h2c_smuggle_findings.txt" 2>/dev/null || echo 0)
    host_count=$(count_lines "${OUT_DIR}/ct_host_header_findings.txt" 2>/dev/null || echo 0)
    desync_count=$(count_lines "${OUT_DIR}/ct_desync_findings.txt" 2>/dev/null || echo 0)
    cdn_count=$(count_lines "${OUT_DIR}/ct_cdn_bypass_findings.txt" 2>/dev/null || echo 0)

    local total_findings=$(( fp_count + poison_count + deception_count + smuggle_count + h2c_count + host_count + desync_count + cdn_count ))
    local hunt_duration=$(( $(date +%s) - HUNT_START_EPOCH ))
    local validated_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORTEOF
# Cache & Transport Attack Report: ${TARGET_NAME}

**Date**: $(date +%Y-%m-%d)
**Platform**: ${PLATFORM^}
**Researcher**: pythonomus-prime
**Max Critical Payout**: ${MAX_BOUNTY}
**Scanner**: cache.sh v${VERSION}
**Hunt Duration**: $(format_duration $hunt_duration)

---

## Executive Summary

Cache and transport layer attack assessment of **${TARGET_NAME}** targeting $(count_lines "$DOMAINS_FILE") domain(s). The scan tested for web cache poisoning, cache deception, HTTP request smuggling (CL.TE/TE.CL/TE.TE), HTTP/2 cleartext smuggling, host header attacks, HTTP desync, and CDN/WAF origin bypass.

### Finding Summary

| Category | Count | Severity | Script |
|----------|-------|----------|--------|
| CDN/Cache Fingerprint | ${fp_count} | INFO | ct_fingerprint.sh |
| Cache Poisoning | ${poison_count} | CRITICAL | ct_cache_poison.sh |
| Cache Deception | ${deception_count} | HIGH-CRITICAL | ct_cache_deception.sh |
| HTTP Smuggling | ${smuggle_count} | CRITICAL | ct_smuggle_detect.sh |
| H2C Smuggling | ${h2c_count} | HIGH-CRITICAL | ct_smuggle_h2c.sh |
| Host Header | ${host_count} | MEDIUM-HIGH | ct_host_header.sh |
| HTTP Desync | ${desync_count} | HIGH-CRITICAL | ct_desync.sh |
| CDN/WAF Bypass | ${cdn_count} | HIGH | ct_cdn_bypass.sh |
| **Total** | **${total_findings}** | | **${validated_count} confirmed** |

### Phase Timing

| Phase | Duration |
|-------|----------|
REPORTEOF

    for phase in ct_fingerprint ct_cache_poison ct_cache_deception ct_smuggle_detect ct_smuggle_h2c ct_host_header ct_desync ct_cdn_bypass; do
        local dur="${PHASE_TIMES[$phase]:-0}"
        echo "| ${phase} | $(format_duration $dur) |" >> "$REPORT_FILE"
    done

    cat >> "$REPORT_FILE" << REPORTEOF

---

## Scope

**In scope:**
\`\`\`
$(cat "$DOMAINS_FILE")
\`\`\`

**Scope notes**: ${SCOPE_NOTES}

---

## Findings

REPORTEOF

    # ── CDN Fingerprint ──
    if [ "$fp_count" -gt 0 ]; then
        echo '### CDN & Cache Fingerprint' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/ct_fingerprint_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Cache Poisoning ──
    if [ "$poison_count" -gt 0 ]; then
        echo '### Cache Poisoning (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_cache_poison_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Cache Deception ──
    if [ "$deception_count" -gt 0 ]; then
        echo '### Cache Deception (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_cache_deception_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── HTTP Smuggling ──
    if [ "$smuggle_count" -gt 0 ]; then
        echo '### HTTP Request Smuggling (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_smuggle_detect_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── H2C Smuggling ──
    if [ "$h2c_count" -gt 0 ]; then
        echo '### HTTP/2 Cleartext Smuggling (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_h2c_smuggle_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Host Header ──
    if [ "$host_count" -gt 0 ]; then
        echo '### Host Header Attacks' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_host_header_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Desync ──
    if [ "$desync_count" -gt 0 ]; then
        echo '### HTTP Desync (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_desync_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── CDN Bypass ──
    if [ "$cdn_count" -gt 0 ]; then
        echo '### CDN/WAF Origin Bypass (HIGH)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ct_cdn_bypass_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Priority Findings ──
    if [ -s "${OUT_DIR}/priority_findings.txt" ]; then
        local p_count
        p_count=$(wc -l < "${OUT_DIR}/priority_findings.txt" | tr -d ' ')
        echo "### Priority Findings (${p_count} high-confidence — triage first)" >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/priority_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Validated Findings ──
    if [ -s "${OUT_DIR}/validated_findings.txt" ]; then
        local v_confirmed v_total
        v_confirmed=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" || echo 0)
        v_total=$(wc -l < "${OUT_DIR}/validated_findings.txt" | tr -d ' ')
        echo "### Validation Results (${v_confirmed}/${v_total} confirmed)" >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        grep '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" >> "$REPORT_FILE" || true
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── No findings ──
    if [ "$total_findings" -eq 0 ]; then
        echo "No cache or transport layer vulnerabilities were identified by automated scanning." >> "$REPORT_FILE"
        echo "Manual testing recommended for complex smuggling and cache poisoning scenarios." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Footer ──
    cat >> "$REPORT_FILE" << FOOTER

---

## Methodology

This report was generated using cache.sh v${VERSION} — an 8-phase cache & transport attack pipeline:

1. **CDN Fingerprint** — CDN detection (Cloudflare/Akamai/Fastly/Varnish), cache key analysis, Vary handling
2. **Cache Poisoning** — Unkeyed header reflection (X-Forwarded-Host, X-Original-URL), poison persistence verification
3. **Cache Deception** — Static extension appending, path normalization, delimiter confusion
4. **Smuggling Detection** — CL.TE/TE.CL/TE.TE detection (smuggler, timing-based differential)
5. **H2C Smuggling** — HTTP/2 cleartext access control bypass (h2csmuggler)
6. **Host Header** — Password reset poisoning, routing abuse, multiple Host headers
7. **HTTP Desync** — Connection header manipulation, Transfer-Encoding variants, CL mismatch
8. **CDN Bypass** — DNS history, certificate transparency, origin hostname patterns, IPv6 fallback

**Note**: All testing was performed with appropriate authorization context.

---

*Generated by cache.sh v${VERSION} on $(date)*
*Duration: $(format_duration $hunt_duration)*
*All output files: ${OUT_DIR}/*
*Manifest: ${OUT_DIR}/manifest.json*
FOOTER

    log "Report saved: ${REPORT_FILE}"
    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  REPORT: ${REPORT_FILE}${NC}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════${NC}"
}

# ══════════════════════════════════════════════════════════════
#                         MAIN
# ══════════════════════════════════════════════════════════════
main() {
    banner
    check_deps
    parse_args "$@"

    # Handle resume mode
    if [ -n "$RESUME_DIR" ]; then
        if [ ! -d "$RESUME_DIR" ]; then
            err "Resume directory not found: ${RESUME_DIR}"
            exit 1
        fi
        OUT_DIR="$RESUME_DIR"
        if [ -f "${OUT_DIR}/hunt_config.json" ]; then
            if ! python3 -c "import json; json.load(open('${OUT_DIR}/hunt_config.json'))" 2>/dev/null; then
                err "Corrupt hunt_config.json — cannot resume"; exit 1
            fi
            TARGET_NAME=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['target'])" 2>/dev/null || echo "Unknown")
            PLATFORM=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['platform'])" 2>/dev/null || echo "other")
            DOMAINS_FILE=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['domains_file'])" 2>/dev/null || echo "")
            MAX_BOUNTY=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['max_bounty'])" 2>/dev/null || echo "unknown")
            SCOPE_NOTES=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json')).get('scope_notes','none'))" 2>/dev/null || echo "none")
            SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
            log "Resuming CACHE hunt: ${TARGET_NAME} from ${OUT_DIR}"
            log "Completed phases will be skipped"
        else
            err "No hunt_config.json found in ${OUT_DIR}"
            exit 1
        fi
    fi

    init_submitted
    init_phase_tracking

    HUNT_START_TIME=$(date -Iseconds)
    HUNT_START_EPOCH=$(date +%s)

    # Show previously submitted findings
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        echo ""
        list_submitted
        warn "Findings matching these patterns will be excluded from the report"
        echo ""
    fi

    # Interactive mode if no target specified
    if [ -z "$TARGET_NAME" ]; then
        prompt_config
    else
        SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    fi

    log "CACHE Hunt started: $(date)"
    log "Target: ${TARGET_NAME}"
    log "Output: ${OUT_DIR}/"
    log "Version: ${VERSION}"

    # Save config
    cat > "${OUT_DIR}/hunt_config.json" << CFGEOF
{
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "domains_file": "${DOMAINS_FILE}",
    "max_bounty": "${MAX_BOUNTY}",
    "scope_notes": "${SCOPE_NOTES}",
    "threads": ${THREADS},
    "timestamp": "$(date -Iseconds)",
    "version": "${VERSION}",
    "tool": "cache.sh"
}
CFGEOF

    local primary_domain
    primary_domain=$(sed 's/\*\.//' "$DOMAINS_FILE" | head -1)

    # ═══════════════════════════════════════════════════════
    #  Phase 1: CDN & Cache Fingerprinting
    # ═══════════════════════════════════════════════════════
    run_phase 1 "ct_fingerprint" "ct_fingerprint.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 2: Web Cache Poisoning
    # ═══════════════════════════════════════════════════════
    run_phase 2 "ct_cache_poison" "ct_cache_poison.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 3: Web Cache Deception
    # ═══════════════════════════════════════════════════════
    run_phase 3 "ct_cache_deception" "ct_cache_deception.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 4: HTTP Request Smuggling Detection
    # ═══════════════════════════════════════════════════════
    run_phase 4 "ct_smuggle_detect" "ct_smuggle_detect.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 5: HTTP/2 Cleartext Smuggling
    # ═══════════════════════════════════════════════════════
    run_phase 5 "ct_smuggle_h2c" "ct_smuggle_h2c.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 6: Host Header Attacks
    # ═══════════════════════════════════════════════════════
    run_phase 6 "ct_host_header" "ct_host_header.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 7: HTTP Desync & Connection Abuse
    # ═══════════════════════════════════════════════════════
    run_phase 7 "ct_desync" "ct_desync.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 8: CDN/WAF Origin Bypass
    # ═══════════════════════════════════════════════════════
    run_phase 8 "ct_cdn_bypass" "ct_cdn_bypass.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Auto-Validation
    # ═══════════════════════════════════════════════════════
    phase_header "V" "Auto-Validation"
    validate_findings

    # ═══════════════════════════════════════════════════════
    #  Report + Manifest
    # ═══════════════════════════════════════════════════════
    generate_report
    generate_manifest

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "${BOLD}       CACHE HUNT COMPLETE: $(date)${NC}"
    echo -e "${BOLD}       Duration: $(format_duration $(( $(date +%s) - HUNT_START_EPOCH )))${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  Report:    ${REPORT_FILE}"
    echo "  Manifest:  ${MANIFEST_FILE}"
    echo "  Data:      ${OUT_DIR}/"
    echo ""
}

main "$@"
