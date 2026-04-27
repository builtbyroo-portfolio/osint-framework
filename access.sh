#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ACCESS.SH v1.0.0 — Automated Access Discovery Tool         ║
# ║  SecLists-driven endpoint, panel, and credential discovery   ║
# ║  Per-phase timing · Resume support · VRT-aware output        ║
# ║  JSON manifest · Auto-validation · Error recovery            ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Interactive:  ./access.sh
#   CLI mode:     ./access.sh --target "Acme Corp" --domains domains.txt \
#                   --platform bugcrowd --out ./output
#   Deep mode:    ./access.sh -t "Acme" -d domains.txt --deep
#   Recursive:    ./access.sh -t "Acme" -d domains.txt --recursive
#   Resume:       ./access.sh --resume ./hunts/Acme_ACCESS_20260302_120000
#   Single phase: ./scripts/ac_fingerprint.sh -d example.com -o ./out
#
# Each script in scripts/ can run standalone or be chained here.

set -uo pipefail

# ── Source shared library ───────────────────────────────────────
HUNT_DIR="$(dirname "$(readlink -f "$0")")"
source "${HUNT_DIR}/lib.sh"

VERSION="1.0.0"

# Mode flags
DEEP_MODE=false
RECURSIVE_MODE=false

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
  ╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗
  ╠═╣║  ║  ║╣ ╚═╗╚═╗
  ╩ ╩╚═╝╚═╝╚═╝╚═╝╚═╝ v1.0
  Automated Access Discovery
EOF
    echo -e "${NC}"
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    local required=(curl ffuf dig python3)
    local optional=(whatweb httpx-pd nuclei arjun gobuster katana nmap nikto)

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

    # SecLists check
    if [ ! -d "$SECLISTS" ]; then
        err "SecLists not found at ${SECLISTS}"
        echo "  Install with: sudo pacman -S seclists"
        exit 1
    fi
    log "SecLists: ${SECLISTS}"

    # Scripts check
    info "Checking scripts/ directory..."
    local scripts=(ac_fingerprint ac_content_discovery ac_api_discovery ac_backup_config ac_vhost_discovery ac_403_bypass ac_default_creds ac_param_mining ac_method_tamper ac_login_spray ac_misconfig_probe)
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
        echo "  Examples: example.com  |  api.example.com"
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
        read -rp "$(echo -e "${CYAN}Scope notes${NC} (e.g., 'QA/staging in scope', or Enter to skip): ")" SCOPE_NOTES
        SCOPE_NOTES="${SCOPE_NOTES:-none}"
    fi

    echo ""
    echo "  Scan modes:"
    echo "    --deep       Enable Tier 3 (DirBuster-medium, 220K words)"
    echo "    --recursive  Re-fuzz discovered directories one level deep"
    echo ""
    read -rp "$(echo -e "${CYAN}Enable deep mode?${NC} [y/N]: ")" deep_choice
    [[ "$deep_choice" =~ ^[Yy] ]] && DEEP_MODE=true

    read -rp "$(echo -e "${CYAN}Enable recursive mode?${NC} [y/N]: ")" recursive_choice
    [[ "$recursive_choice" =~ ^[Yy] ]] && RECURSIVE_MODE=true

    read -rp "$(echo -e "${CYAN}Threads${NC} [${THREADS}]: ")" custom_threads
    THREADS="${custom_threads:-$THREADS}"

    echo ""
    echo -e "${BOLD}── Configuration Summary ──${NC}"
    echo "  Target:       ${TARGET_NAME}"
    echo "  Platform:     ${PLATFORM}"
    echo "  Domains:      $(count_lines "$DOMAINS_FILE") entries"
    echo "  Max payout:   ${MAX_BOUNTY}"
    echo "  Deep mode:    ${DEEP_MODE}"
    echo "  Recursive:    ${RECURSIVE_MODE}"
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
            --deep)       DEEP_MODE=true; shift ;;
            --recursive)  RECURSIVE_MODE=true; shift ;;
            --submitted)  SUBMITTED_FILE="$2"; shift 2 ;;
            --resume)     RESUME_DIR="$2"; SKIP_COMPLETED=true; shift 2 ;;
            --mark-submitted) mark_submitted "$2" "${3:-}"; exit 0 ;;
            --list-submitted) list_submitted; exit 0 ;;
            --version|-v) echo "access.sh v${VERSION}"; exit 0 ;;
            --help|-h)    usage; exit 0 ;;
            *)            err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUT_DIR="${OUT_DIR:-./hunts/${SAFE_NAME}_ACCESS_${TIMESTAMP}}"
    mkdir -p "$OUT_DIR"
}

usage() {
    echo "Usage: access.sh [OPTIONS]"
    echo ""
    echo "Interactive mode (no args):  ./access.sh"
    echo ""
    echo "Automated Access Discovery — finds hidden endpoints, exposed panels,"
    echo "default credentials, backup files, API surfaces, virtual hosts, and"
    echo "tests 403 bypasses, parameter mining, method tampering, login spraying."
    echo ""
    echo "Options:"
    echo "  -t, --target NAME      Target name (e.g., 'Acme Corp')"
    echo "  -d, --domains FILE     File with domains (one per line)"
    echo "  -p, --platform NAME    Platform: bugcrowd, hackerone, other"
    echo "  -o, --out DIR          Output directory"
    echo "  --bounty AMOUNT        Max critical payout"
    echo "  --scope NOTES          Scope notes"
    echo "  --threads N            Concurrency level (default: 30)"
    echo "  --deep                 Enable Tier 3 (DirBuster-medium, 220K words)"
    echo "  --recursive            Re-fuzz discovered directories one level deep"
    echo "  --resume DIR           Resume a previous hunt from its output directory"
    echo "  --submitted FILE       Custom submitted findings tracker file"
    echo "  --mark-submitted PAT   Add a pattern to submitted tracker and exit"
    echo "  --list-submitted       Show all submitted finding patterns and exit"
    echo "  -v, --version          Show version"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Standalone scripts (run individually):"
    echo "  scripts/ac_fingerprint.sh        Technology fingerprinting"
    echo "  scripts/ac_content_discovery.sh  Tiered content discovery (core)"
    echo "  scripts/ac_api_discovery.sh      API endpoint discovery"
    echo "  scripts/ac_backup_config.sh      Backup & config file discovery"
    echo "  scripts/ac_vhost_discovery.sh    Virtual host discovery"
    echo "  scripts/ac_403_bypass.sh         403 bypass (30+ techniques)"
    echo "  scripts/ac_default_creds.sh      Default credential testing"
    echo "  scripts/ac_param_mining.sh       Hidden parameter discovery"
    echo "  scripts/ac_method_tamper.sh      HTTP method tampering"
    echo "  scripts/ac_login_spray.sh        Login panel credential spray"
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
    export DEEP_MODE RECURSIVE_MODE
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
        ac_content_findings.txt ac_api_findings.txt ac_graphql_findings.txt
        ac_swagger_specs.txt ac_backup_findings.txt ac_sourcemap_findings.txt
        ac_vhost_findings.txt ac_bypass_findings.txt ac_cred_findings.txt
        ac_param_findings.txt ac_method_findings.txt ac_login_spray_findings.txt
        ac_misconfig_findings.txt
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
        finding_type="${finding_type#ac_}"

        while IFS= read -r line; do
            ((total++)) || true
            local url
            url=$(echo "$line" | grep -oP 'https?://[^\s\]\)]+' | head -1)
            [ -z "$url" ] && url=$(echo "$line" | awk '{print $NF}')

            local status validation_detail=""

            if echo "$url" | grep -qP '^https?://'; then
                status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 12 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")
            else
                status="N/A"
            fi

            # Type-aware severity classification
            case "$finding_type" in
                cred|login_spray)
                    if echo "$line" | grep -qi "CRITICAL\|LOGIN_SUCCESS\|AUTH_BYPASS"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CRED_ACCESS] ${line}" >> "$priority_file"
                        validation_detail="CRIT_AUTH"
                    fi
                    ;;
                bypass)
                    if echo "$line" | grep -qi "HIGH\|BYPASS_200"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:403_BYPASS] ${line}" >> "$priority_file"
                        validation_detail="AUTH_BYPASS"
                    fi
                    ;;
                backup|sourcemap)
                    if echo "$line" | grep -qi "CRITICAL\|\.env\|\.git\|database"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:DATA_EXPOSURE] ${line}" >> "$priority_file"
                        validation_detail="DATA_LEAK"
                    fi
                    ;;
                swagger|graphql)
                    if echo "$line" | grep -qi "INTROSPECTION\|FULL_SPEC\|OPENAPI"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:API_EXPOSURE] ${line}" >> "$priority_file"
                        validation_detail="API_EXPOSED"
                    fi
                    ;;
                vhost)
                    if echo "$line" | grep -qi "CONFIRMED\|admin\|internal\|staging"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:VHOST] ${line}" >> "$priority_file"
                        validation_detail="HIDDEN_HOST"
                    fi
                    ;;
                method)
                    if echo "$line" | grep -qi "HIGH\|PUT_OK\|DELETE_OK"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:METHOD_TAMPER] ${line}" >> "$priority_file"
                        validation_detail="UNSAFE_METHOD"
                    fi
                    ;;
                param)
                    if echo "$line" | grep -qi "debug\|admin\|token\|key\|secret"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:HIDDEN_PARAM] ${line}" >> "$priority_file"
                        validation_detail="SENSITIVE_PARAM"
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

    if [ "$total" -gt 0 ]; then
        log "Validation: ${confirmed}/${total} findings confirmed"
        if [ "$high_confidence" -gt 0 ]; then
            warn "HIGH-CONFIDENCE findings: ${high_confidence} (see priority_findings.txt)"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════
#                   JSON MANIFEST
# ══════════════════════════════════════════════════════════════

generate_manifest() {
    local finding_types=(content api graphql swagger backup sourcemap vhost bypass cred param method login_spray misconfig)
    local counts=""

    for ff in "${finding_types[@]}"; do
        local count
        count=$(wc -l < "${OUT_DIR}/ac_${ff}_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)
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
    "tool": "access.sh",
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "timestamp_start": "${HUNT_START_TIME}",
    "timestamp_end": "$(date -Iseconds)",
    "duration_seconds": $(( $(date +%s) - HUNT_START_EPOCH )),
    "threads": ${THREADS},
    "deep_mode": ${DEEP_MODE},
    "recursive_mode": ${RECURSIVE_MODE},
    "domains_file": "${DOMAINS_FILE}",
    "domains_count": $(wc -l < "$DOMAINS_FILE" | tr -d ' '),
    "output_dir": "${OUT_DIR}",
    "findings": { ${counts} },
    "validated_confirmed": ${validated_count},
    "priority_findings": ${priority_count},
    "phase_durations": { ${phase_timings} },
    "report_file": "${OUT_DIR}/${SAFE_NAME}_ACCESS_REPORT.md"
}
JSONEOF
    log "Manifest: ${MANIFEST_FILE}"
}

# ══════════════════════════════════════════════════════════════
#                    REPORT GENERATION
# ══════════════════════════════════════════════════════════════
generate_report() {
    phase_header 11 "Report Generation"

    REPORT_FILE="${OUT_DIR}/${SAFE_NAME}_ACCESS_REPORT.md"
    info "Generating ${REPORT_FILE}..."

    # ── Dedup: filter previously-submitted findings ──
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        info "Filtering previously-submitted findings (${sub_count} patterns)..."
        for finding_file in \
            "${OUT_DIR}/ac_content_findings.txt" \
            "${OUT_DIR}/ac_api_findings.txt" \
            "${OUT_DIR}/ac_graphql_findings.txt" \
            "${OUT_DIR}/ac_swagger_specs.txt" \
            "${OUT_DIR}/ac_backup_findings.txt" \
            "${OUT_DIR}/ac_sourcemap_findings.txt" \
            "${OUT_DIR}/ac_vhost_findings.txt" \
            "${OUT_DIR}/ac_bypass_findings.txt" \
            "${OUT_DIR}/ac_cred_findings.txt" \
            "${OUT_DIR}/ac_param_findings.txt" \
            "${OUT_DIR}/ac_method_findings.txt" \
            "${OUT_DIR}/ac_login_spray_findings.txt" \
            "${OUT_DIR}/ac_misconfig_findings.txt"; do
            if [ -s "$finding_file" ]; then
                filter_submitted "$finding_file" "${finding_file}.deduped"
                mv "${finding_file}.deduped" "$finding_file"
            fi
        done
    fi

    # Count findings
    local content_count api_count graphql_count swagger_count backup_count srcmap_count
    local vhost_count bypass_count cred_count param_count method_count spray_count misconfig_count
    content_count=$(count_lines "${OUT_DIR}/ac_content_findings.txt" 2>/dev/null || echo 0)
    api_count=$(count_lines "${OUT_DIR}/ac_api_findings.txt" 2>/dev/null || echo 0)
    graphql_count=$(count_lines "${OUT_DIR}/ac_graphql_findings.txt" 2>/dev/null || echo 0)
    swagger_count=$(count_lines "${OUT_DIR}/ac_swagger_specs.txt" 2>/dev/null || echo 0)
    backup_count=$(count_lines "${OUT_DIR}/ac_backup_findings.txt" 2>/dev/null || echo 0)
    srcmap_count=$(count_lines "${OUT_DIR}/ac_sourcemap_findings.txt" 2>/dev/null || echo 0)
    vhost_count=$(count_lines "${OUT_DIR}/ac_vhost_findings.txt" 2>/dev/null || echo 0)
    bypass_count=$(count_lines "${OUT_DIR}/ac_bypass_findings.txt" 2>/dev/null || echo 0)
    cred_count=$(count_lines "${OUT_DIR}/ac_cred_findings.txt" 2>/dev/null || echo 0)
    param_count=$(count_lines "${OUT_DIR}/ac_param_findings.txt" 2>/dev/null || echo 0)
    method_count=$(count_lines "${OUT_DIR}/ac_method_findings.txt" 2>/dev/null || echo 0)
    spray_count=$(count_lines "${OUT_DIR}/ac_login_spray_findings.txt" 2>/dev/null || echo 0)
    misconfig_count=$(count_lines "${OUT_DIR}/ac_misconfig_findings.txt" 2>/dev/null || echo 0)

    local total_findings=$(( content_count + api_count + graphql_count + swagger_count + backup_count + srcmap_count + vhost_count + bypass_count + cred_count + param_count + method_count + spray_count + misconfig_count ))
    local hunt_duration=$(( $(date +%s) - HUNT_START_EPOCH ))
    local validated_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORTEOF
# Access Discovery Report: ${TARGET_NAME}

**Date**: $(date +%Y-%m-%d)
**Platform**: ${PLATFORM^}
**Researcher**: pythonomus-prime
**Max Critical Payout**: ${MAX_BOUNTY}
**Scanner**: access.sh v${VERSION}
**Hunt Duration**: $(format_duration $hunt_duration)
**Deep Mode**: ${DEEP_MODE} | **Recursive**: ${RECURSIVE_MODE}

---

## Executive Summary

Automated access discovery assessment of **${TARGET_NAME}** targeting $(count_lines "$DOMAINS_FILE") domain(s). The scan probed for hidden content, API surfaces, backup/config files, virtual hosts, and tested 403 bypasses, default credentials, parameter mining, method tampering, and login spraying.

### Finding Summary

| Category | Count | Severity | Script |
|----------|-------|----------|--------|
| Content Discovery | ${content_count} | VARIES | ac_content_discovery.sh |
| API Endpoints | ${api_count} | MEDIUM-HIGH | ac_api_discovery.sh |
| GraphQL Introspection | ${graphql_count} | P5 (unless chained) | ac_api_discovery.sh |
| Swagger/OpenAPI Specs | ${swagger_count} | MEDIUM | ac_api_discovery.sh |
| Backup/Config Files | ${backup_count} | CRITICAL-HIGH | ac_backup_config.sh |
| Source Maps | ${srcmap_count} | HIGH | ac_backup_config.sh |
| Virtual Hosts | ${vhost_count} | MEDIUM-HIGH | ac_vhost_discovery.sh |
| 403 Bypass | ${bypass_count} | HIGH | ac_403_bypass.sh |
| Default Credentials | ${cred_count} | CRITICAL | ac_default_creds.sh |
| Hidden Parameters | ${param_count} | MEDIUM | ac_param_mining.sh |
| Method Tampering | ${method_count} | MEDIUM-HIGH | ac_method_tamper.sh |
| Login Spray | ${spray_count} | CRITICAL | ac_login_spray.sh |
| Misconfig Probes | ${misconfig_count} | VARIES | ac_misconfig_probe.sh |
| **Total** | **${total_findings}** | | **${validated_count} confirmed** |

### Phase Timing

| Phase | Duration |
|-------|----------|
REPORTEOF

    for phase in ac_fingerprint ac_content_discovery ac_api_discovery ac_backup_config ac_vhost_discovery ac_403_bypass ac_default_creds ac_param_mining ac_method_tamper ac_login_spray ac_misconfig_probe; do
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

    # ── Content Discovery ──
    if [ "$content_count" -gt 0 ]; then
        echo '### Content Discovery' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -50 "${OUT_DIR}/ac_content_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── API Endpoints ──
    if [ "$api_count" -gt 0 ]; then
        echo '### API Endpoint Discovery' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/ac_api_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── GraphQL ──
    if [ "$graphql_count" -gt 0 ]; then
        echo '### GraphQL Findings' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '> Note: GraphQL introspection alone = P5 per Bugcrowd VRT. Only submit if chained.' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_graphql_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Swagger ──
    if [ "$swagger_count" -gt 0 ]; then
        echo '### Swagger/OpenAPI Specs' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_swagger_specs.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Backup/Config ──
    if [ "$backup_count" -gt 0 ]; then
        echo '### Backup & Config File Exposure (CRITICAL-HIGH)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_backup_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Source Maps ──
    if [ "$srcmap_count" -gt 0 ]; then
        echo '### Source Map Exposure (HIGH)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/ac_sourcemap_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Virtual Hosts ──
    if [ "$vhost_count" -gt 0 ]; then
        echo '### Virtual Host Discovery' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_vhost_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 403 Bypass ──
    if [ "$bypass_count" -gt 0 ]; then
        echo '### 403 Bypass (HIGH)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_bypass_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Default Creds ──
    if [ "$cred_count" -gt 0 ]; then
        echo '### Default Credential Findings (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_cred_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Hidden Params ──
    if [ "$param_count" -gt 0 ]; then
        echo '### Hidden Parameter Discovery' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/ac_param_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Method Tampering ──
    if [ "$method_count" -gt 0 ]; then
        echo '### HTTP Method Tampering' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_method_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Misconfig Probes ──
    if [ "$misconfig_count" -gt 0 ]; then
        echo '### Misconfiguration Probes' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_misconfig_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Login Spray ──
    if [ "$spray_count" -gt 0 ]; then
        echo '### Login Spray Findings (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ac_login_spray_findings.txt" >> "$REPORT_FILE"
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
        echo "No access control issues were identified by automated scanning." >> "$REPORT_FILE"
        echo "Manual testing recommended for complex authorization bypasses." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Footer ──
    cat >> "$REPORT_FILE" << FOOTER

---

## Methodology

This report was generated using access.sh v${VERSION} — a 10-phase access discovery pipeline:

1. **Fingerprinting** — Technology identification (whatweb, curl header analysis)
2. **Content Discovery** — Tiered fuzzing: common.txt+quickhits → big.txt → DirBuster-medium (ffuf)
3. **API Discovery** — REST, GraphQL introspection, Swagger/OpenAPI (ffuf, curl)
4. **Backup/Config** — .env, .git, .bak, source maps, DB dumps, CMS configs (curl, ffuf)
5. **Virtual Hosts** — Host header fuzzing for hidden vhosts (ffuf)
6. **403 Bypass** — 30+ URL manipulation, header injection, method override techniques (curl)
7. **Default Credentials** — Service-specific credential testing (curl)
8. **Parameter Mining** — Hidden GET/header parameter discovery (arjun, ffuf)
9. **Method Tampering** — PUT/DELETE/TRACE/PATCH method testing (curl)
10. **Login Spray** — Form-based credential spray with lockout detection (curl)
11. **Misconfig Probes** — 80+ technology-specific endpoints: Actuator, ServiceNow, Metabase, Vault, Airflow, WordPress, Telerik, CORS, .env/.git (curl)

**Note**: All testing was performed with appropriate authorization context.

---

*Generated by access.sh v${VERSION} on $(date)*
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
            TARGET_NAME=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['target'])" 2>/dev/null || echo "Unknown")
            PLATFORM=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['platform'])" 2>/dev/null || echo "other")
            DOMAINS_FILE=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['domains_file'])" 2>/dev/null || echo "")
            MAX_BOUNTY=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['max_bounty'])" 2>/dev/null || echo "unknown")
            SCOPE_NOTES=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json')).get('scope_notes','none'))" 2>/dev/null || echo "none")
            local _dm _rm
            _dm=$(python3 -c "import json; print(str(json.load(open('${OUT_DIR}/hunt_config.json')).get('deep_mode',False)).lower())" 2>/dev/null || echo "false")
            _rm=$(python3 -c "import json; print(str(json.load(open('${OUT_DIR}/hunt_config.json')).get('recursive_mode',False)).lower())" 2>/dev/null || echo "false")
            [[ "$_dm" == "true" ]] && DEEP_MODE=true || DEEP_MODE=false
            [[ "$_rm" == "true" ]] && RECURSIVE_MODE=true || RECURSIVE_MODE=false
            SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
            log "Resuming ACCESS hunt: ${TARGET_NAME} from ${OUT_DIR}"
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

    log "ACCESS Hunt started: $(date)"
    log "Target: ${TARGET_NAME}"
    log "Output: ${OUT_DIR}/"
    log "Version: ${VERSION}"
    log "Deep mode: ${DEEP_MODE} | Recursive: ${RECURSIVE_MODE}"

    # Save config
    cat > "${OUT_DIR}/hunt_config.json" << CFGEOF
{
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "domains_file": "${DOMAINS_FILE}",
    "max_bounty": "${MAX_BOUNTY}",
    "scope_notes": "${SCOPE_NOTES}",
    "deep_mode": ${DEEP_MODE},
    "recursive_mode": ${RECURSIVE_MODE},
    "threads": ${THREADS},
    "timestamp": "$(date -Iseconds)",
    "version": "${VERSION}",
    "tool": "access.sh"
}
CFGEOF

    local primary_domain
    primary_domain=$(sed 's/\*\.//' "$DOMAINS_FILE" | head -1)

    # Deep/recursive flags for child scripts
    local mode_args=()
    $DEEP_MODE && mode_args+=(--deep)
    $RECURSIVE_MODE && mode_args+=(--recursive)

    # ═══════════════════════════════════════════════════════
    #  Phase 1: Technology Fingerprinting
    # ═══════════════════════════════════════════════════════
    run_phase 1 "ac_fingerprint" "ac_fingerprint.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 2: Tiered Content Discovery (Core)
    # ═══════════════════════════════════════════════════════
    run_phase 2 "ac_content_discovery" "ac_content_discovery.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS" "${mode_args[@]}"

    # ═══════════════════════════════════════════════════════
    #  Phase 3: API Endpoint Discovery
    # ═══════════════════════════════════════════════════════
    run_phase 3 "ac_api_discovery" "ac_api_discovery.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 4: Backup & Config File Discovery
    # ═══════════════════════════════════════════════════════
    run_phase 4 "ac_backup_config" "ac_backup_config.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 5: Virtual Host Discovery
    # ═══════════════════════════════════════════════════════
    run_phase 5 "ac_vhost_discovery" "ac_vhost_discovery.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS" "${mode_args[@]}"

    # ═══════════════════════════════════════════════════════
    #  Phase 6: 403 Bypass (30+ techniques)
    # ═══════════════════════════════════════════════════════
    run_phase 6 "ac_403_bypass" "ac_403_bypass.sh" -u "${OUT_DIR}/ac_403_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 7: Default Credential Testing
    # ═══════════════════════════════════════════════════════
    run_phase 7 "ac_default_creds" "ac_default_creds.sh" -u "${OUT_DIR}/ac_login_panels.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 8: Hidden Parameter Discovery
    # ═══════════════════════════════════════════════════════
    run_phase 8 "ac_param_mining" "ac_param_mining.sh" -u "${OUT_DIR}/ac_interesting_endpoints.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 9: HTTP Method Tampering
    # ═══════════════════════════════════════════════════════
    run_phase 9 "ac_method_tamper" "ac_method_tamper.sh" -u "${OUT_DIR}/ac_interesting_endpoints.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 10: Login Panel Credential Spray
    # ═══════════════════════════════════════════════════════
    run_phase 10 "ac_login_spray" "ac_login_spray.sh" -u "${OUT_DIR}/ac_login_panels.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 11: Known Misconfiguration Probing
    # ═══════════════════════════════════════════════════════
    run_phase 11 "ac_misconfig_probe" "ac_misconfig_probe.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 11.5: Auto-Validation
    # ═══════════════════════════════════════════════════════
    phase_header "10.5" "Auto-Validation"
    validate_findings

    # ═══════════════════════════════════════════════════════
    #  Phase 11: Report + Manifest
    # ═══════════════════════════════════════════════════════
    generate_report
    generate_manifest

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "${BOLD}       ACCESS HUNT COMPLETE: $(date)${NC}"
    echo -e "${BOLD}       Duration: $(format_duration $(( $(date +%s) - HUNT_START_EPOCH )))${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  Report:    ${REPORT_FILE}"
    echo "  Manifest:  ${MANIFEST_FILE}"
    echo "  Data:      ${OUT_DIR}/"
    echo ""
}

main "$@"
