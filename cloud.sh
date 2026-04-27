#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CLOUD.SH v1.0.0 — Cloud & Supply Chain Scanner              ║
# ║  Buckets · Metadata · Serverless · JS CVEs · Dep confusion   ║
# ║  Per-phase timing · Resume support · VRT-aware output          ║
# ║  JSON manifest · Auto-validation · Error recovery              ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Interactive:  ./cloud.sh
#   CLI mode:     ./cloud.sh --target "Acme Corp" --domains domains.txt \
#                   --platform bugcrowd --keyword acme --out ./output
#   Resume:       ./cloud.sh --resume ./hunts/Acme_CLOUD_20260303_120000
#   Single phase: ./scripts/cl_cloud_enum.sh -d example.com --keyword acme -o ./out
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

# Cloud-specific
KEYWORD="${KEYWORD:-}"

# ── Banner ──────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
   ╔═╗╦  ╔═╗╦ ╦╔╦╗
   ║  ║  ║ ║║ ║ ║║
   ╚═╝╩═╝╚═╝╚═╝═╩╝ v1.0
   Cloud & Supply Chain Scanner
EOF
    echo -e "${NC}"
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    local required=(curl python3 dig)
    local optional=(cloud-enum s3scanner gcpbucketbrute cloudlist retire)

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
    local scripts=(cl_cloud_enum cl_bucket_scan cl_metadata_ssrf cl_serverless cl_js_audit cl_dep_confusion cl_sri_check cl_cloud_secrets)
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

    if [ -z "${KEYWORD:-}" ]; then
        read -rp "$(echo -e "${CYAN}Keyword for bucket enumeration${NC} (e.g., 'acme', or Enter to auto-derive): ")" KEYWORD
        if [ -z "$KEYWORD" ]; then
            # Auto-derive from first domain — strip wildcard prefix and TLD
            KEYWORD=$(head -1 "$DOMAINS_FILE" | sed 's/\*\.//; s/\..*//' | tr -cd '[:alnum:]-')
            if [ -z "$KEYWORD" ]; then
                read -rp "$(echo -e "${CYAN}Could not auto-derive keyword. Enter manually: ")" KEYWORD
            else
                info "Auto-derived keyword: ${KEYWORD}"
            fi
        fi
    fi

    if [ -z "${MAX_BOUNTY:-}" ]; then
        read -rp "$(echo -e "${CYAN}Max critical payout${NC} (e.g., \$25000, or press Enter to skip): ")" MAX_BOUNTY
        MAX_BOUNTY="${MAX_BOUNTY:-unknown}"
    fi

    if [ -z "${SCOPE_NOTES:-}" ]; then
        read -rp "$(echo -e "${CYAN}Scope notes${NC} (e.g., 'Cloud assets in scope', or Enter to skip): ")" SCOPE_NOTES
        SCOPE_NOTES="${SCOPE_NOTES:-none}"
    fi

    read -rp "$(echo -e "${CYAN}Threads${NC} [${THREADS}]: ")" custom_threads
    THREADS="${custom_threads:-$THREADS}"

    echo ""
    echo -e "${BOLD}── Configuration Summary ──${NC}"
    echo "  Target:       ${TARGET_NAME}"
    echo "  Platform:     ${PLATFORM}"
    echo "  Domains:      $(count_lines "$DOMAINS_FILE") entries"
    echo "  Keyword:      ${KEYWORD}"
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
            --keyword|-k) KEYWORD="$2"; shift 2 ;;
            --bounty)     MAX_BOUNTY="$2"; shift 2 ;;
            --scope)      SCOPE_NOTES="$2"; shift 2 ;;
            --threads)    THREADS="$2"; shift 2 ;;
            --submitted)  SUBMITTED_FILE="$2"; shift 2 ;;
            --resume)     RESUME_DIR="$2"; SKIP_COMPLETED=true; shift 2 ;;
            --mark-submitted) mark_submitted "$2" "${3:-}"; exit 0 ;;
            --list-submitted) list_submitted; exit 0 ;;
            --version|-v) echo "cloud.sh v${VERSION}"; exit 0 ;;
            --help|-h)    usage; exit 0 ;;
            *)            err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUT_DIR="${OUT_DIR:-./hunts/${SAFE_NAME}_CLOUD_${TIMESTAMP}}"
    mkdir -p "$OUT_DIR"
}

usage() {
    echo "Usage: cloud.sh [OPTIONS]"
    echo ""
    echo "Interactive mode (no args):  ./cloud.sh"
    echo ""
    echo "Cloud & Supply Chain Scanner — enumerates cloud assets (S3/Azure/GCP),"
    echo "tests bucket permissions, probes for cloud metadata via SSRF, discovers"
    echo "serverless functions, audits JS libraries for CVEs, checks for dependency"
    echo "confusion, validates SRI, and scans for exposed cloud secrets."
    echo ""
    echo "Options:"
    echo "  -t, --target NAME      Target name (e.g., 'Acme Corp')"
    echo "  -d, --domains FILE     File with domains (one per line)"
    echo "  -p, --platform NAME    Platform: bugcrowd, hackerone, other"
    echo "  -k, --keyword WORD     Keyword for bucket name generation"
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
    echo "  scripts/cl_cloud_enum.sh       Cloud asset enumeration"
    echo "  scripts/cl_bucket_scan.sh      Deep bucket permission testing"
    echo "  scripts/cl_metadata_ssrf.sh    Cloud metadata via SSRF"
    echo "  scripts/cl_serverless.sh       Serverless function discovery"
    echo "  scripts/cl_js_audit.sh         JavaScript CVE audit"
    echo "  scripts/cl_dep_confusion.sh    Dependency confusion check"
    echo "  scripts/cl_sri_check.sh        Subresource integrity check"
    echo "  scripts/cl_cloud_secrets.sh    Cloud secret & credential scanning"
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
    export KEYWORD
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
        cl_cloud_enum_findings.txt cl_bucket_scan_findings.txt
        cl_metadata_ssrf_findings.txt cl_serverless_findings.txt
        cl_js_audit_findings.txt cl_dep_confusion_findings.txt
        cl_sri_check_findings.txt cl_cloud_secrets_findings.txt
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
        finding_type="${finding_type#cl_}"

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
                cloud_enum)
                    if echo "$line" | grep -qi "BUCKET_FOUND\|BLOB_FOUND\|OPEN_LISTING"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:BUCKET_ACCESS] ${line}" >> "$priority_file"
                        validation_detail="BUCKET_ACCESS"
                    fi
                    ;;
                bucket_scan)
                    if echo "$line" | grep -qi "LIST_OK\|READ_OK\|WRITE_OK\|ACL_EXPOSED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:BUCKET_ACCESS] ${line}" >> "$priority_file"
                        validation_detail="BUCKET_ACCESS"
                    fi
                    ;;
                metadata_ssrf)
                    if echo "$line" | grep -qi "METADATA_LEAKED\|IMDS_EXPOSED\|SSRF_CONFIRMED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:METADATA_SSRF] ${line}" >> "$priority_file"
                        validation_detail="METADATA_SSRF"
                    fi
                    ;;
                serverless)
                    if echo "$line" | grep -qi "UNAUTH_INVOKE\|FUNCTION_EXPOSED\|LAMBDA_OPEN"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:SERVERLESS] ${line}" >> "$priority_file"
                        validation_detail="SERVERLESS"
                    fi
                    ;;
                js_audit)
                    if echo "$line" | grep -qi "CRITICAL\|HIGH.*CVE"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:JS_CVE] ${line}" >> "$priority_file"
                        validation_detail="JS_CVE"
                    fi
                    ;;
                dep_confusion)
                    if echo "$line" | grep -qi "CLAIMABLE\|NOT_FOUND_PUBLIC\|DEP_CONFUSION"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:DEP_CONFUSION] ${line}" >> "$priority_file"
                        validation_detail="DEP_CONFUSION"
                    fi
                    ;;
                sri_check)
                    # SRI findings are DO_NOT_SUBMIT unless chained
                    validation_detail="DO_NOT_SUBMIT"
                    ;;
                cloud_secrets)
                    if echo "$line" | grep -qi "AKIA\|VALIDATED\|SECRET_KEY\|STRIPE_LIVE\|SERVICE_ACCOUNT"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CLOUD_SECRET] ${line}" >> "$priority_file"
                        validation_detail="CLOUD_SECRET"
                    fi
                    ;;
            esac

            # ── Recon-Only Detection ──
            # Tag surface-level findings that lack demonstrated exploitation
            local is_recon_only=false
            if [[ "$validation_detail" == "DO_NOT_SUBMIT" ]]; then
                is_recon_only=true  # Already tagged (e.g., SRI)
            elif echo "$line" | grep -qiP '(/health|/version|/status|/info)$' && \
                 ! echo "$line" | grep -qiP '(secret|credential|password|token|AKIA)'; then
                is_recon_only=true  # Health/version endpoints without secrets
            elif echo "$line" | grep -qiP '(fingerprint|banner|server.header)' && \
                 ! echo "$line" | grep -qiP '(CVE-|exploit|critical)'; then
                is_recon_only=true  # Version fingerprinting without CVE chain
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
    local finding_types=(cloud_enum bucket_scan metadata_ssrf serverless js_audit dep_confusion sri_check cloud_secrets)
    local counts=""

    for ff in "${finding_types[@]}"; do
        local count
        count=$(wc -l < "${OUT_DIR}/cl_${ff}_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)
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
    "tool": "cloud.sh",
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "keyword": "${KEYWORD}",
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
    "report_file": "${OUT_DIR}/${SAFE_NAME}_CLOUD_REPORT.md"
}
JSONEOF
    log "Manifest: ${MANIFEST_FILE}"
}

# ══════════════════════════════════════════════════════════════
#                    REPORT GENERATION
# ══════════════════════════════════════════════════════════════
generate_report() {
    phase_header "R" "Report Generation"

    REPORT_FILE="${OUT_DIR}/${SAFE_NAME}_CLOUD_REPORT.md"
    info "Generating ${REPORT_FILE}..."

    # ── Dedup: filter previously-submitted findings ──
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        info "Filtering previously-submitted findings (${sub_count} patterns)..."
        for finding_file in \
            "${OUT_DIR}/cl_cloud_enum_findings.txt" \
            "${OUT_DIR}/cl_bucket_scan_findings.txt" \
            "${OUT_DIR}/cl_metadata_ssrf_findings.txt" \
            "${OUT_DIR}/cl_serverless_findings.txt" \
            "${OUT_DIR}/cl_js_audit_findings.txt" \
            "${OUT_DIR}/cl_dep_confusion_findings.txt" \
            "${OUT_DIR}/cl_sri_check_findings.txt" \
            "${OUT_DIR}/cl_cloud_secrets_findings.txt"; do
            if [ -s "$finding_file" ]; then
                filter_submitted "$finding_file" "${finding_file}.deduped"
                mv "${finding_file}.deduped" "$finding_file"
            fi
        done
    fi

    # Count findings
    local enum_count bucket_count meta_count serverless_count
    local js_count dep_count sri_count secrets_count
    enum_count=$(count_lines "${OUT_DIR}/cl_cloud_enum_findings.txt" 2>/dev/null || echo 0)
    bucket_count=$(count_lines "${OUT_DIR}/cl_bucket_scan_findings.txt" 2>/dev/null || echo 0)
    meta_count=$(count_lines "${OUT_DIR}/cl_metadata_ssrf_findings.txt" 2>/dev/null || echo 0)
    serverless_count=$(count_lines "${OUT_DIR}/cl_serverless_findings.txt" 2>/dev/null || echo 0)
    js_count=$(count_lines "${OUT_DIR}/cl_js_audit_findings.txt" 2>/dev/null || echo 0)
    dep_count=$(count_lines "${OUT_DIR}/cl_dep_confusion_findings.txt" 2>/dev/null || echo 0)
    sri_count=$(count_lines "${OUT_DIR}/cl_sri_check_findings.txt" 2>/dev/null || echo 0)
    secrets_count=$(count_lines "${OUT_DIR}/cl_cloud_secrets_findings.txt" 2>/dev/null || echo 0)

    local total_findings=$(( enum_count + bucket_count + meta_count + serverless_count + js_count + dep_count + sri_count + secrets_count ))
    local hunt_duration=$(( $(date +%s) - HUNT_START_EPOCH ))
    local validated_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORTEOF
# Cloud & Supply Chain Report: ${TARGET_NAME}

**Date**: $(date +%Y-%m-%d)
**Platform**: ${PLATFORM^}
**Researcher**: pythonomus-prime
**Max Critical Payout**: ${MAX_BOUNTY}
**Scanner**: cloud.sh v${VERSION}
**Hunt Duration**: $(format_duration $hunt_duration)
**Keyword**: ${KEYWORD}

---

## Executive Summary

Cloud and supply chain assessment of **${TARGET_NAME}** targeting $(count_lines "$DOMAINS_FILE") domain(s) with keyword "${KEYWORD}". The scan enumerated cloud assets (S3/Azure/GCP), tested bucket permissions, probed for cloud metadata via SSRF, discovered serverless functions, audited JS libraries for CVEs, checked for dependency confusion, validated SRI, and scanned for exposed cloud secrets.

### Finding Summary

| Category | Count | Severity | Script |
|----------|-------|----------|--------|
| Cloud Asset Enum | ${enum_count} | MEDIUM | cl_cloud_enum.sh |
| Bucket Permissions | ${bucket_count} | HIGH-CRITICAL | cl_bucket_scan.sh |
| Metadata SSRF | ${meta_count} | CRITICAL | cl_metadata_ssrf.sh |
| Serverless Functions | ${serverless_count} | MEDIUM-HIGH | cl_serverless.sh |
| JS CVE Audit | ${js_count} | VARIES | cl_js_audit.sh |
| Dependency Confusion | ${dep_count} | CRITICAL | cl_dep_confusion.sh |
| SRI Check | ${sri_count} | P5 (DO_NOT_SUBMIT) | cl_sri_check.sh |
| Cloud Secrets | ${secrets_count} | CRITICAL | cl_cloud_secrets.sh |
| **Total** | **${total_findings}** | | **${validated_count} confirmed** |

### Phase Timing

| Phase | Duration |
|-------|----------|
REPORTEOF

    for phase in cl_cloud_enum cl_bucket_scan cl_metadata_ssrf cl_serverless cl_js_audit cl_dep_confusion cl_sri_check cl_cloud_secrets; do
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

**Keyword**: ${KEYWORD}
**Scope notes**: ${SCOPE_NOTES}

---

## Findings

REPORTEOF

    # ── Cloud Enum ──
    if [ "$enum_count" -gt 0 ]; then
        echo '### Cloud Asset Enumeration' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/cl_cloud_enum_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Bucket Scan ──
    if [ "$bucket_count" -gt 0 ]; then
        echo '### Bucket Permission Findings (HIGH-CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/cl_bucket_scan_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Metadata SSRF ──
    if [ "$meta_count" -gt 0 ]; then
        echo '### Cloud Metadata SSRF (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/cl_metadata_ssrf_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Serverless ──
    if [ "$serverless_count" -gt 0 ]; then
        echo '### Serverless Function Discovery' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/cl_serverless_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── JS Audit ──
    if [ "$js_count" -gt 0 ]; then
        echo '### JavaScript CVE Audit' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -40 "${OUT_DIR}/cl_js_audit_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Dep Confusion ──
    if [ "$dep_count" -gt 0 ]; then
        echo '### Dependency Confusion (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/cl_dep_confusion_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── SRI Check ──
    if [ "$sri_count" -gt 0 ]; then
        echo '### Subresource Integrity [DO_NOT_SUBMIT — P5 unless chained]' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '> SRI findings alone are P5 per Bugcrowd VRT. Only submit if chained with CDN compromise.' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/cl_sri_check_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Cloud Secrets ──
    if [ "$secrets_count" -gt 0 ]; then
        echo '### Cloud Secret & Credential Exposure (CRITICAL)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/cl_cloud_secrets_findings.txt" >> "$REPORT_FILE"
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
        echo "No cloud or supply chain vulnerabilities were identified by automated scanning." >> "$REPORT_FILE"
        echo "Manual testing recommended for complex cloud misconfigurations." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Footer ──
    cat >> "$REPORT_FILE" << FOOTER

---

## Methodology

This report was generated using cloud.sh v${VERSION} — an 8-phase cloud & supply chain pipeline:

1. **Cloud Enum** — S3/Azure/GCP asset enumeration (cloud_enum) with keyword variations
2. **Bucket Scan** — Deep permission testing (s3scanner, gcpbucketbrute), ACL checks
3. **Metadata SSRF** — Cloud metadata via SSRF candidates (IMDSv1/v2, Azure, GCP, DigitalOcean)
4. **Serverless** — Lambda/API Gateway/Azure Functions/Vercel/Netlify/GCP Cloud Functions discovery
5. **JS Audit** — retire.js vulnerability scanning, version extraction, CVE cross-reference
6. **Dep Confusion** — Exposed manifest discovery, public registry availability checking
7. **SRI Check** — CDN-loaded scripts/styles missing integrity= attribute
8. **Cloud Secrets** — AWS keys, Azure strings, GCP service accounts, Firebase/Stripe/Twilio (with public-key filtering)

**Note**: All testing was performed with appropriate authorization context.

---

*Generated by cloud.sh v${VERSION} on $(date)*
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
            KEYWORD=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json')).get('keyword',''))" 2>/dev/null || echo "")
            SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
            log "Resuming CLOUD hunt: ${TARGET_NAME} from ${OUT_DIR}"
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

    # Auto-derive keyword if not set
    if [ -z "$KEYWORD" ]; then
        KEYWORD=$(head -1 "$DOMAINS_FILE" | sed 's/\*\.//; s/\..*//')
        info "Auto-derived keyword: ${KEYWORD}"
    fi

    log "CLOUD Hunt started: $(date)"
    log "Target: ${TARGET_NAME}"
    log "Keyword: ${KEYWORD}"
    log "Output: ${OUT_DIR}/"
    log "Version: ${VERSION}"

    # Save config
    cat > "${OUT_DIR}/hunt_config.json" << CFGEOF
{
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "domains_file": "${DOMAINS_FILE}",
    "keyword": "${KEYWORD}",
    "max_bounty": "${MAX_BOUNTY}",
    "scope_notes": "${SCOPE_NOTES}",
    "threads": ${THREADS},
    "timestamp": "$(date -Iseconds)",
    "version": "${VERSION}",
    "tool": "cloud.sh"
}
CFGEOF

    local primary_domain
    primary_domain=$(sed 's/\*\.//' "$DOMAINS_FILE" | head -1)

    # ═══════════════════════════════════════════════════════
    #  Phase 1: Cloud Asset Enumeration
    # ═══════════════════════════════════════════════════════
    run_phase 1 "cl_cloud_enum" "cl_cloud_enum.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS" --keyword "$KEYWORD"

    # ═══════════════════════════════════════════════════════
    #  Phase 2: Deep Bucket Permission Testing
    # ═══════════════════════════════════════════════════════
    run_phase 2 "cl_bucket_scan" "cl_bucket_scan.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS" --keyword "$KEYWORD"

    # ═══════════════════════════════════════════════════════
    #  Phase 3: Cloud Metadata via SSRF
    # ═══════════════════════════════════════════════════════
    run_phase 3 "cl_metadata_ssrf" "cl_metadata_ssrf.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 4: Serverless Function Discovery
    # ═══════════════════════════════════════════════════════
    run_phase 4 "cl_serverless" "cl_serverless.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS" --keyword "$KEYWORD"

    # ═══════════════════════════════════════════════════════
    #  Phase 5: JavaScript CVE Audit
    # ═══════════════════════════════════════════════════════
    run_phase 5 "cl_js_audit" "cl_js_audit.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 6: Dependency Confusion Check
    # ═══════════════════════════════════════════════════════
    run_phase 6 "cl_dep_confusion" "cl_dep_confusion.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 7: Subresource Integrity Check
    # ═══════════════════════════════════════════════════════
    run_phase 7 "cl_sri_check" "cl_sri_check.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 8: Cloud Secret & Credential Scanning
    # ═══════════════════════════════════════════════════════
    run_phase 8 "cl_cloud_secrets" "cl_cloud_secrets.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

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
    echo -e "${BOLD}       CLOUD HUNT COMPLETE: $(date)${NC}"
    echo -e "${BOLD}       Duration: $(format_duration $(( $(date +%s) - HUNT_START_EPOCH )))${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  Report:    ${REPORT_FILE}"
    echo "  Manifest:  ${MANIFEST_FILE}"
    echo "  Data:      ${OUT_DIR}/"
    echo ""
}

main "$@"
