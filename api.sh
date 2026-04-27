#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  API.SH v1.0.0 — Deep API Exploitation Scanner                ║
# ║  GraphQL · REST abuse · WebSocket · SOAP/XXE · Rate bypass    ║
# ║  Per-phase timing · Resume support · VRT-aware output          ║
# ║  JSON manifest · Auto-validation · Error recovery              ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Interactive:  ./api.sh
#   CLI mode:     ./api.sh --target "Acme Corp" --domains domains.txt \
#                   --platform bugcrowd --out ./output
#   Resume:       ./api.sh --resume ./hunts/Acme_API_20260303_120000
#   Single phase: ./scripts/ap_graphql_recon.sh -d example.com -o ./out
#
# Cross-tool input: Reads ac_api_findings.txt, ac_graphql_findings.txt,
#                   ac_swagger_specs.txt from access.sh runs if present.
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
   ╔═╗╔═╗╦
   ╠═╣╠═╝║
   ╩ ╩╩  ╩ v1.0
   Deep API Exploitation Scanner
EOF
    echo -e "${NC}"
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    local required=(curl python3)
    local optional=(graphql-cop clairvoyance crackql graphinder graphqlmap graphql-path-enum websocat ffuf)

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
    local scripts=(ap_graphql_recon ap_graphql_exploit ap_graphql_brute ap_rest_abuse ap_websocket ap_soap_xxe ap_rate_bypass ap_schema_harvest)
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
        read -rp "$(echo -e "${CYAN}Scope notes${NC} (e.g., 'API-only scope', or Enter to skip): ")" SCOPE_NOTES
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
            --version|-v) echo "api.sh v${VERSION}"; exit 0 ;;
            --help|-h)    usage; exit 0 ;;
            *)            err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUT_DIR="${OUT_DIR:-./hunts/${SAFE_NAME}_API_${TIMESTAMP}}"
    mkdir -p "$OUT_DIR"
}

usage() {
    echo "Usage: api.sh [OPTIONS]"
    echo ""
    echo "Interactive mode (no args):  ./api.sh"
    echo ""
    echo "Deep API Exploitation Scanner — discovers and tests GraphQL endpoints,"
    echo "REST API abuse vectors, WebSocket vulnerabilities, SOAP/XXE, rate limit"
    echo "bypasses, and harvests API schemas/documentation."
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
    echo "  scripts/ap_graphql_recon.sh    GraphQL endpoint discovery & fingerprinting"
    echo "  scripts/ap_graphql_exploit.sh  GraphQL deep exploitation"
    echo "  scripts/ap_graphql_brute.sh    GraphQL credential testing"
    echo "  scripts/ap_rest_abuse.sh       REST API abuse (BOLA, mass assign, downgrade)"
    echo "  scripts/ap_websocket.sh        WebSocket vulnerability testing"
    echo "  scripts/ap_soap_xxe.sh         SOAP/WSDL discovery & XXE testing"
    echo "  scripts/ap_rate_bypass.sh      Rate limit bypass testing"
    echo "  scripts/ap_schema_harvest.sh   API schema & documentation harvesting"
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
        ap_graphql_recon_findings.txt ap_graphql_exploit_findings.txt
        ap_graphql_brute_findings.txt ap_rest_abuse_findings.txt
        ap_websocket_findings.txt ap_soap_xxe_findings.txt
        ap_rate_bypass_findings.txt ap_schema_harvest_findings.txt
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
        finding_type="${finding_type#ap_}"

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
                graphql_recon)
                    if echo "$line" | grep -qi "INTROSPECTION_ENABLED\|FULL_SCHEMA"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:GRAPHQL_EXPOSED] ${line}" >> "$priority_file"
                        validation_detail="GRAPHQL_EXPOSED"
                    fi
                    ;;
                graphql_exploit)
                    if echo "$line" | grep -qi "SCHEMA_EXTRACTED\|MUTATION_ABUSE\|AUTH_BYPASS\|BATCHING"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:GRAPHQL_EXPLOIT] ${line}" >> "$priority_file"
                        validation_detail="GRAPHQL_EXPLOIT"
                    fi
                    ;;
                graphql_brute)
                    if echo "$line" | grep -qi "LOGIN_SUCCESS\|CRED_VALID\|AUTH_BYPASS"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:GRAPHQL_AUTH] ${line}" >> "$priority_file"
                        validation_detail="GRAPHQL_AUTH"
                    fi
                    ;;
                rest_abuse)
                    if echo "$line" | grep -qi "MASS_ASSIGN\|BOLA_CONFIRMED\|VERSION_BYPASS\|IDOR"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:REST_EXPLOIT] ${line}" >> "$priority_file"
                        validation_detail="REST_EXPLOIT"
                    fi
                    ;;
                websocket)
                    if echo "$line" | grep -qi "AUTH_BYPASS\|CSWSH_CONFIRMED\|WS_OPEN"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:WEBSOCKET] ${line}" >> "$priority_file"
                        validation_detail="WEBSOCKET"
                    fi
                    ;;
                soap_xxe)
                    if echo "$line" | grep -qi "XXE_CONFIRMED\|WSDL_SENSITIVE\|SOAP_INJECTION"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:SOAP_XXE] ${line}" >> "$priority_file"
                        validation_detail="SOAP_XXE"
                    fi
                    ;;
                rate_bypass)
                    if echo "$line" | grep -qi "BYPASS_CONFIRMED\|RATE_CIRCUMVENTED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:RATE_BYPASS] ${line}" >> "$priority_file"
                        validation_detail="RATE_BYPASS"
                    fi
                    ;;
                schema_harvest)
                    if echo "$line" | grep -qi "FULL_SPEC\|OPENAPI\|POSTMAN\|UNDOCUMENTED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:API_EXPOSURE] ${line}" >> "$priority_file"
                        validation_detail="API_EXPOSED"
                    fi
                    ;;
            esac

            # ── Recon-Only Detection ──
            # Tag surface-level findings without demonstrated exploitation
            local is_recon_only=false
            if [[ "$finding_type" == "graphql_recon" ]] && \
               ! echo "$line" | grep -qiP '(DATA_ACCESS|AUTH_BYPASS|SENSITIVE_FIELD|PII)'; then
                is_recon_only=true  # GraphQL introspection alone = P5
            elif [[ "$finding_type" == "schema_harvest" ]] && \
                 ! echo "$line" | grep -qiP '(UNDOCUMENTED|SENSITIVE|AUTH|INTERNAL)'; then
                is_recon_only=true  # Public API docs at vendor-default paths
            elif [[ "$finding_type" == "soap_xxe" ]] && \
                 echo "$line" | grep -qiP 'WSDL_FOUND' && \
                 ! echo "$line" | grep -qiP '(XXE_CONFIRMED|SOAP_INJECTION|WSDL_SENSITIVE)'; then
                is_recon_only=true  # WSDL exists but no exploitation
            elif echo "$line" | grep -qiP '(/health|/version|/status|/info)$' && \
                 ! echo "$line" | grep -qiP '(secret|credential|password|token)'; then
                is_recon_only=true  # Health/version endpoints without secrets
            fi

            if $is_recon_only; then
                echo "[DO_NOT_SUBMIT:RECON_ONLY] ${line}" >> "$validated_file"
                warn "RECON-ONLY (no exploitation): ${url:-$line}"
                continue
            fi

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

    local recon_only_count
    recon_only_count=$(grep -c '^\[DO_NOT_SUBMIT' "$validated_file" 2>/dev/null || echo 0)
    local std_excl_count
    std_excl_count=$(grep -c '^\[DO_NOT_SUBMIT:STANDARD_EXCLUSION\]' "$validated_file" 2>/dev/null || echo 0)

    if [ "$total" -gt 0 ]; then
        log "Validation: ${confirmed}/${total} findings confirmed"
        if [ "$recon_only_count" -gt 0 ]; then
            warn "DO_NOT_SUBMIT total: ${recon_only_count}"
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
    local finding_types=(graphql_recon graphql_exploit graphql_brute rest_abuse websocket soap_xxe rate_bypass schema_harvest)
    local counts=""

    for ff in "${finding_types[@]}"; do
        local count
        count=$(wc -l < "${OUT_DIR}/ap_${ff}_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)
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
    "tool": "api.sh",
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
    "report_file": "${OUT_DIR}/${SAFE_NAME}_API_REPORT.md"
}
JSONEOF
    log "Manifest: ${MANIFEST_FILE}"
}

# ══════════════════════════════════════════════════════════════
#                    REPORT GENERATION
# ══════════════════════════════════════════════════════════════
generate_report() {
    phase_header "R" "Report Generation"

    REPORT_FILE="${OUT_DIR}/${SAFE_NAME}_API_REPORT.md"
    info "Generating ${REPORT_FILE}..."

    # ── Dedup: filter previously-submitted findings ──
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        info "Filtering previously-submitted findings (${sub_count} patterns)..."
        for finding_file in \
            "${OUT_DIR}/ap_graphql_recon_findings.txt" \
            "${OUT_DIR}/ap_graphql_exploit_findings.txt" \
            "${OUT_DIR}/ap_graphql_brute_findings.txt" \
            "${OUT_DIR}/ap_rest_abuse_findings.txt" \
            "${OUT_DIR}/ap_websocket_findings.txt" \
            "${OUT_DIR}/ap_soap_xxe_findings.txt" \
            "${OUT_DIR}/ap_rate_bypass_findings.txt" \
            "${OUT_DIR}/ap_schema_harvest_findings.txt"; do
            if [ -s "$finding_file" ]; then
                filter_submitted "$finding_file" "${finding_file}.deduped"
                mv "${finding_file}.deduped" "$finding_file"
            fi
        done
    fi

    # Count findings
    local gql_recon_count gql_exploit_count gql_brute_count rest_count
    local ws_count soap_count rate_count schema_count
    gql_recon_count=$(count_lines "${OUT_DIR}/ap_graphql_recon_findings.txt" 2>/dev/null || echo 0)
    gql_exploit_count=$(count_lines "${OUT_DIR}/ap_graphql_exploit_findings.txt" 2>/dev/null || echo 0)
    gql_brute_count=$(count_lines "${OUT_DIR}/ap_graphql_brute_findings.txt" 2>/dev/null || echo 0)
    rest_count=$(count_lines "${OUT_DIR}/ap_rest_abuse_findings.txt" 2>/dev/null || echo 0)
    ws_count=$(count_lines "${OUT_DIR}/ap_websocket_findings.txt" 2>/dev/null || echo 0)
    soap_count=$(count_lines "${OUT_DIR}/ap_soap_xxe_findings.txt" 2>/dev/null || echo 0)
    rate_count=$(count_lines "${OUT_DIR}/ap_rate_bypass_findings.txt" 2>/dev/null || echo 0)
    schema_count=$(count_lines "${OUT_DIR}/ap_schema_harvest_findings.txt" 2>/dev/null || echo 0)

    local total_findings=$(( gql_recon_count + gql_exploit_count + gql_brute_count + rest_count + ws_count + soap_count + rate_count + schema_count ))
    local hunt_duration=$(( $(date +%s) - HUNT_START_EPOCH ))
    local validated_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORTEOF
# API Exploitation Report: ${TARGET_NAME}

**Date**: $(date +%Y-%m-%d)
**Platform**: ${PLATFORM^}
**Researcher**: pythonomus-prime
**Max Critical Payout**: ${MAX_BOUNTY}
**Scanner**: api.sh v${VERSION}
**Hunt Duration**: $(format_duration $hunt_duration)

---

## Executive Summary

Deep API exploitation assessment of **${TARGET_NAME}** targeting $(count_lines "$DOMAINS_FILE") domain(s). The scan tested GraphQL endpoints for introspection, exploitation, and credential attacks; REST APIs for BOLA, mass assignment, and version downgrade; WebSocket vulnerabilities; SOAP/XXE; rate limit bypasses; and harvested API schemas.

### Finding Summary

| Category | Count | Severity | Script |
|----------|-------|----------|--------|
| GraphQL Recon | ${gql_recon_count} | MEDIUM-HIGH | ap_graphql_recon.sh |
| GraphQL Exploitation | ${gql_exploit_count} | HIGH-CRITICAL | ap_graphql_exploit.sh |
| GraphQL Credential | ${gql_brute_count} | CRITICAL | ap_graphql_brute.sh |
| REST API Abuse | ${rest_count} | HIGH-CRITICAL | ap_rest_abuse.sh |
| WebSocket | ${ws_count} | MEDIUM-HIGH | ap_websocket.sh |
| SOAP/XXE | ${soap_count} | HIGH-CRITICAL | ap_soap_xxe.sh |
| Rate Limit Bypass | ${rate_count} | MEDIUM | ap_rate_bypass.sh |
| Schema Harvest | ${schema_count} | MEDIUM | ap_schema_harvest.sh |
| **Total** | **${total_findings}** | | **${validated_count} confirmed** |

### Phase Timing

| Phase | Duration |
|-------|----------|
REPORTEOF

    for phase in ap_graphql_recon ap_graphql_exploit ap_graphql_brute ap_rest_abuse ap_websocket ap_soap_xxe ap_rate_bypass ap_schema_harvest; do
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

    # ── GraphQL Recon ──
    if [ "$gql_recon_count" -gt 0 ]; then
        echo '### GraphQL Endpoint Discovery' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '> Note: GraphQL introspection alone = P5 per Bugcrowd VRT. Only submit if chained with data access.' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/ap_graphql_recon_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── GraphQL Exploitation ──
    if [ "$gql_exploit_count" -gt 0 ]; then
        echo '### GraphQL Exploitation (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ap_graphql_exploit_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── GraphQL Brute ──
    if [ "$gql_brute_count" -gt 0 ]; then
        echo '### GraphQL Credential Findings (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ap_graphql_brute_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── REST Abuse ──
    if [ "$rest_count" -gt 0 ]; then
        echo '### REST API Abuse (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -40 "${OUT_DIR}/ap_rest_abuse_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── WebSocket ──
    if [ "$ws_count" -gt 0 ]; then
        echo '### WebSocket Findings' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ap_websocket_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── SOAP/XXE ──
    if [ "$soap_count" -gt 0 ]; then
        echo '### SOAP/XXE Findings (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ap_soap_xxe_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Rate Bypass ──
    if [ "$rate_count" -gt 0 ]; then
        echo '### Rate Limit Bypass' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/ap_rate_bypass_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Schema Harvest ──
    if [ "$schema_count" -gt 0 ]; then
        echo '### API Schema & Documentation' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/ap_schema_harvest_findings.txt" >> "$REPORT_FILE"
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
        echo "No API exploitation issues were identified by automated scanning." >> "$REPORT_FILE"
        echo "Manual testing recommended for complex business logic flaws." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Footer ──
    cat >> "$REPORT_FILE" << FOOTER

---

## Methodology

This report was generated using api.sh v${VERSION} — an 8-phase deep API exploitation pipeline:

1. **GraphQL Recon** — Endpoint discovery (graphinder), fingerprinting (graphql-cop), introspection testing
2. **GraphQL Exploit** — Schema extraction (clairvoyance), batching, nested DoS, mutation abuse, alias bypass
3. **GraphQL Brute** — Credential testing via batched mutations (crackql), default credentials
4. **REST Abuse** — Version downgrade, mass assignment, BOLA, method override, content-type switching
5. **WebSocket** — WS endpoint discovery, auth bypass, CSWSH, message injection
6. **SOAP/XXE** — WSDL discovery, operation enumeration, XXE injection, SOAP injection
7. **Rate Bypass** — Rate limit detection, header rotation, case variation, method switching
8. **Schema Harvest** — Swagger/OpenAPI, Postman collections, GraphQL playgrounds, endpoint extraction

**Note**: All testing was performed with appropriate authorization context.

---

*Generated by api.sh v${VERSION} on $(date)*
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
            log "Resuming API hunt: ${TARGET_NAME} from ${OUT_DIR}"
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

    log "API Hunt started: $(date)"
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
    "tool": "api.sh"
}
CFGEOF

    local primary_domain
    primary_domain=$(sed 's/\*\.//' "$DOMAINS_FILE" | head -1)

    # ═══════════════════════════════════════════════════════
    #  Phase 1: GraphQL Endpoint Discovery & Fingerprinting
    # ═══════════════════════════════════════════════════════
    run_phase 1 "ap_graphql_recon" "ap_graphql_recon.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 2: GraphQL Deep Exploitation
    # ═══════════════════════════════════════════════════════
    run_phase 2 "ap_graphql_exploit" "ap_graphql_exploit.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 3: GraphQL Credential Testing
    # ═══════════════════════════════════════════════════════
    run_phase 3 "ap_graphql_brute" "ap_graphql_brute.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 4: REST API Abuse
    # ═══════════════════════════════════════════════════════
    run_phase 4 "ap_rest_abuse" "ap_rest_abuse.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 5: WebSocket Testing
    # ═══════════════════════════════════════════════════════
    run_phase 5 "ap_websocket" "ap_websocket.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 6: SOAP & XXE Testing
    # ═══════════════════════════════════════════════════════
    run_phase 6 "ap_soap_xxe" "ap_soap_xxe.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 7: Rate Limit Bypass
    # ═══════════════════════════════════════════════════════
    run_phase 7 "ap_rate_bypass" "ap_rate_bypass.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 8: API Schema & Documentation Harvesting
    # ═══════════════════════════════════════════════════════
    run_phase 8 "ap_schema_harvest" "ap_schema_harvest.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

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
    echo -e "${BOLD}       API HUNT COMPLETE: $(date)${NC}"
    echo -e "${BOLD}       Duration: $(format_duration $(( $(date +%s) - HUNT_START_EPOCH )))${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  Report:    ${REPORT_FILE}"
    echo "  Manifest:  ${MANIFEST_FILE}"
    echo "  Data:      ${OUT_DIR}/"
    echo ""
}

main "$@"
