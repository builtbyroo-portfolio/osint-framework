#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  SOCIAL.SH v1.0.0 — Social Engineering Surface Hunter        ║
# ║  Identifies SE attack surfaces for bug bounty reporting       ║
# ║  Per-phase timing · Resume support · VRT-aware output         ║
# ║  JSON manifest · Auto-validation · Error recovery             ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Interactive:  ./social.sh
#   CLI mode:     ./social.sh --target "Acme Corp" --domains domains.txt \
#                   --platform bugcrowd --out ./output
#   Resume:       ./social.sh --resume ./hunts/Acme_SE_20260302_120000
#   Single phase: ./scripts/se_email_security.sh -d example.com -o ./out
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
  ╔═╗╔═╗╔═╗╦╔═╗╦
  ╚═╗║ ║║  ║╠═╣║
  ╚═╝╚═╝╚═╝╩╩ ╩╩═╝ v1.0
  Social Engineering Surface Hunter
EOF
    echo -e "${NC}"
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    local required=(curl dig)
    local optional=(httpx-pd nuclei whatweb subfinder katana wafw00f nmap)

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
    local scripts=(se_surface_map se_email_security se_clickjacking se_open_redirect se_content_spoof se_reverse_tabnab se_csrf se_oauth_misconfig se_takeover_phish se_header_cookie)
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
        read -rp "$(echo -e "${CYAN}Target name${NC} (e.g., Chime, Pinterest): ")" TARGET_NAME
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
        echo "  Examples: *.chime.com  |  api.example.com"
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

    if [ -z "${OUT_OF_SCOPE:-}" ]; then
        read -rp "$(echo -e "${CYAN}Out of scope${NC} (comma-separated, or Enter for none): ")" OUT_OF_SCOPE
        OUT_OF_SCOPE="${OUT_OF_SCOPE:-none}"
    fi

    read -rp "$(echo -e "${CYAN}Threads${NC} [${THREADS}]: ")" custom_threads
    THREADS="${custom_threads:-$THREADS}"

    echo ""
    echo -e "${BOLD}── Configuration Summary ──${NC}"
    echo "  Target:       ${TARGET_NAME}"
    echo "  Platform:     ${PLATFORM}"
    echo "  Domains:      $(count_lines "$DOMAINS_FILE") entries"
    echo "  Max payout:   ${MAX_BOUNTY}"
    echo "  Scope notes:  ${SCOPE_NOTES}"
    echo "  Out of scope: ${OUT_OF_SCOPE}"
    echo "  Threads:      ${THREADS}"
    echo "  Output:       ${OUT_DIR}/"
    echo ""
    read -rp "$(echo -e "${YELLOW}Proceed? [Y/n]:${NC} ")" confirm
    [[ "$confirm" =~ ^[Nn] ]] && echo "Aborted." && exit 0
}

# ── Parse CLI args ────────────────────────────────────────────
parse_args() {
    TARGET_NAME="" PLATFORM="" DOMAINS_FILE="" OUT_DIR="" MAX_BOUNTY="" SCOPE_NOTES="" OUT_OF_SCOPE=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --target|-t)  TARGET_NAME="$2"; shift 2 ;;
            --domains|-d) DOMAINS_FILE="$2"; shift 2 ;;
            --platform|-p) PLATFORM="$2"; shift 2 ;;
            --out|-o)     OUT_DIR="$2"; shift 2 ;;
            --bounty)     MAX_BOUNTY="$2"; shift 2 ;;
            --scope)      SCOPE_NOTES="$2"; shift 2 ;;
            --exclude)    OUT_OF_SCOPE="$2"; shift 2 ;;
            --threads)    THREADS="$2"; shift 2 ;;
            --submitted)  SUBMITTED_FILE="$2"; shift 2 ;;
            --resume)     RESUME_DIR="$2"; SKIP_COMPLETED=true; shift 2 ;;
            --mark-submitted) mark_submitted "$2" "${3:-}"; exit 0 ;;
            --list-submitted) list_submitted; exit 0 ;;
            --version|-v) echo "social.sh v${VERSION}"; exit 0 ;;
            --help|-h)    usage; exit 0 ;;
            *)            err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUT_DIR="${OUT_DIR:-./hunts/${SAFE_NAME}_SE_${TIMESTAMP}}"
    mkdir -p "$OUT_DIR"
}

usage() {
    echo "Usage: social.sh [OPTIONS]"
    echo ""
    echo "Interactive mode (no args):  ./social.sh"
    echo ""
    echo "Social Engineering Surface Hunter — identifies SE attack surfaces"
    echo "(email spoofing, clickjacking, CSRF, OAuth misconfig, open redirect,"
    echo "content spoofing, reverse tabnabbing, subdomain takeover on auth pages)"
    echo "that are reportable on HackerOne/Bugcrowd."
    echo ""
    echo "Options:"
    echo "  -t, --target NAME      Target name (e.g., 'Chime')"
    echo "  -d, --domains FILE     File with domains (one per line)"
    echo "  -p, --platform NAME    Platform: bugcrowd, hackerone, other"
    echo "  -o, --out DIR          Output directory"
    echo "  --bounty AMOUNT        Max critical payout"
    echo "  --scope NOTES          Scope notes"
    echo "  --exclude TARGETS      Out-of-scope targets (comma-separated)"
    echo "  --threads N            Concurrency level (default: 30)"
    echo "  --resume DIR           Resume a previous hunt from its output directory"
    echo "  --submitted FILE       Custom submitted findings tracker file"
    echo "  --mark-submitted PAT   Add a pattern to submitted tracker and exit"
    echo "  --list-submitted       Show all submitted finding patterns and exit"
    echo "  -v, --version          Show version"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Standalone scripts (run individually):"
    echo "  scripts/se_surface_map.sh      Login/form/OAuth endpoint discovery"
    echo "  scripts/se_email_security.sh   SPF/DKIM/DMARC analysis"
    echo "  scripts/se_clickjacking.sh     X-Frame-Options / frame-ancestors"
    echo "  scripts/se_open_redirect.sh    Redirect params in login/OAuth flows"
    echo "  scripts/se_content_spoof.sh    Reflected content / HTML injection"
    echo "  scripts/se_reverse_tabnab.sh   target=\"_blank\" without noopener"
    echo "  scripts/se_csrf.sh             Missing CSRF tokens on sensitive forms"
    echo "  scripts/se_oauth_misconfig.sh  OAuth redirect_uri, state, PKCE"
    echo "  scripts/se_takeover_phish.sh   Dangling CNAMEs on auth subdomains"
    echo "  scripts/se_header_cookie.sh    Cookie flags + security headers"
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
        email_findings.txt clickjack_findings.txt redirect_findings.txt
        content_spoof_findings.txt tabnab_findings.txt csrf_findings.txt
        oauth_findings.txt takeover_findings.txt header_cookie_findings.txt
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

        while IFS= read -r line; do
            ((total++)) || true
            local url
            url=$(echo "$line" | grep -oP 'https?://[^\s"<>\]\)]+' | head -1)

            local status validation_detail=""

            # Not all findings have URLs (e.g., email/DNS findings)
            if echo "$url" | grep -qP '^https?://'; then
                status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 20 \
                    --retry 2 --retry-delay 3 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")
            else
                status="DNS"
            fi

            # Type-aware validation
            case "$finding_type" in
                email)
                    # Email spoofing: high-confidence if SPOOFABLE_HIGH
                    if echo "$line" | grep -qi "SPOOFABLE_HIGH"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:EMAIL_SPOOF] ${line}" >> "$priority_file"
                        validation_detail="HIGH_SPOOF"
                    elif echo "$line" | grep -qi "SPOOFABLE_MEDIUM"; then
                        validation_detail="MEDIUM_SPOOF"
                    fi
                    ;;
                clickjack)
                    # Clickjacking: max P4 per VRT, only on sensitive pages
                    if echo "$line" | grep -qi "FRAMEABLE"; then
                        if echo "$line" | grep -qiP '(login|account|settings|payment|admin)'; then
                            ((high_confidence++)) || true
                            echo "[PRIORITY:CLICKJACK] ${line}" >> "$priority_file"
                        fi
                    fi
                    ;;
                redirect)
                    # Open redirect in auth flow = higher severity
                    if echo "$line" | grep -qi "OAUTH_REDIRECT\|AUTH_REDIRECT"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:OPEN_REDIRECT_AUTH] ${line}" >> "$priority_file"
                    fi
                    ;;
                content_spoof)
                    # Content spoofing: only if HTML renders
                    if echo "$line" | grep -qi "HTML_RENDERED"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CONTENT_SPOOF] ${line}" >> "$priority_file"
                    fi
                    ;;
                csrf)
                    # CSRF on sensitive actions = P3+
                    if echo "$line" | grep -qiP '(password|email|delete|transfer|payment)'; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:CSRF] ${line}" >> "$priority_file"
                    fi
                    ;;
                oauth)
                    # OAuth misconfig: redirect_uri bypass = P2+
                    if echo "$line" | grep -qi "REDIRECT_URI_BYPASS\|IMPLICIT_FLOW"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:OAUTH] ${line}" >> "$priority_file"
                    fi
                    ;;
                takeover)
                    # Auth subdomain takeover = critical
                    if echo "$line" | grep -qi "CLAIMABLE"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:TAKEOVER_PHISH] ${line}" >> "$priority_file"
                    fi
                    ;;
                header_cookie)
                    # Standalone header findings = P5, tag as DO_NOT_SUBMIT
                    if ! echo "$line" | grep -qiP '(session|csrf|auth).*missing.*(secure|httponly)'; then
                        echo "[DO_NOT_SUBMIT] ${line}" >> "$validated_file"
                        continue
                    fi
                    ;;
            esac

            if [[ "$status" =~ ^(200|301|302|401|403|500|DNS)$ ]]; then
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
    local finding_types=(email clickjack redirect content_spoof tabnab csrf oauth takeover header_cookie)
    local counts=""

    for ff in "${finding_types[@]}"; do
        local count
        count=$(wc -l < "${OUT_DIR}/${ff}_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)
        counts+="\"${ff}\": ${count}, "
    done
    counts="${counts%, }"

    local phase_timings=""
    for phase in "${!PHASE_TIMES[@]}"; do
        phase_timings+="\"${phase}\": ${PHASE_TIMES[$phase]}, "
    done
    phase_timings="${phase_timings%, }"

    local surface_count sensitive_count oauth_count validated_count priority_count
    surface_count=$(wc -l < "${OUT_DIR}/surface_urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
    sensitive_count=$(wc -l < "${OUT_DIR}/sensitive_urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
    oauth_count=$(wc -l < "${OUT_DIR}/oauth_urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)
    priority_count=$(wc -l < "${OUT_DIR}/priority_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)

    cat > "$MANIFEST_FILE" << JSONEOF
{
    "version": "${VERSION}",
    "tool": "social.sh",
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "timestamp_start": "${HUNT_START_TIME}",
    "timestamp_end": "$(date -Iseconds)",
    "duration_seconds": $(( $(date +%s) - HUNT_START_EPOCH )),
    "threads": ${THREADS},
    "domains_file": "${DOMAINS_FILE}",
    "domains_count": $(wc -l < "$DOMAINS_FILE" | tr -d ' '),
    "output_dir": "${OUT_DIR}",
    "surface": {
        "surface_urls": ${surface_count},
        "sensitive_urls": ${sensitive_count},
        "oauth_urls": ${oauth_count}
    },
    "findings": { ${counts} },
    "validated_confirmed": ${validated_count},
    "priority_findings": ${priority_count},
    "phase_durations": { ${phase_timings} },
    "report_file": "${OUT_DIR}/${SAFE_NAME}_SE_REPORT.md"
}
JSONEOF
    log "Manifest: ${MANIFEST_FILE}"
}

# ══════════════════════════════════════════════════════════════
#                    REPORT GENERATION
# ══════════════════════════════════════════════════════════════
generate_report() {
    phase_header 11 "Report Generation"

    REPORT_FILE="${OUT_DIR}/${SAFE_NAME}_SE_REPORT.md"
    info "Generating ${REPORT_FILE}..."

    # ── Dedup: filter previously-submitted findings ──
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        info "Filtering previously-submitted findings (${sub_count} patterns)..."
        for finding_file in \
            "${OUT_DIR}/email_findings.txt" \
            "${OUT_DIR}/clickjack_findings.txt" \
            "${OUT_DIR}/redirect_findings.txt" \
            "${OUT_DIR}/content_spoof_findings.txt" \
            "${OUT_DIR}/tabnab_findings.txt" \
            "${OUT_DIR}/csrf_findings.txt" \
            "${OUT_DIR}/oauth_findings.txt" \
            "${OUT_DIR}/takeover_findings.txt" \
            "${OUT_DIR}/header_cookie_findings.txt"; do
            if [ -s "$finding_file" ]; then
                filter_submitted "$finding_file" "${finding_file}.deduped"
                mv "${finding_file}.deduped" "$finding_file"
            fi
        done
    fi

    # Count findings
    local email_count clickjack_count redirect_count spoof_count tabnab_count csrf_count oauth_count takeover_count header_count
    email_count=$(count_lines "${OUT_DIR}/email_findings.txt" 2>/dev/null || echo 0)
    clickjack_count=$(count_lines "${OUT_DIR}/clickjack_findings.txt" 2>/dev/null || echo 0)
    redirect_count=$(count_lines "${OUT_DIR}/redirect_findings.txt" 2>/dev/null || echo 0)
    spoof_count=$(count_lines "${OUT_DIR}/content_spoof_findings.txt" 2>/dev/null || echo 0)
    tabnab_count=$(count_lines "${OUT_DIR}/tabnab_findings.txt" 2>/dev/null || echo 0)
    csrf_count=$(count_lines "${OUT_DIR}/csrf_findings.txt" 2>/dev/null || echo 0)
    oauth_count=$(count_lines "${OUT_DIR}/oauth_findings.txt" 2>/dev/null || echo 0)
    takeover_count=$(count_lines "${OUT_DIR}/takeover_findings.txt" 2>/dev/null || echo 0)
    header_count=$(count_lines "${OUT_DIR}/header_cookie_findings.txt" 2>/dev/null || echo 0)

    local surface_count sensitive_count oauth_url_count
    surface_count=$(count_lines "${OUT_DIR}/surface_urls.txt" 2>/dev/null || echo 0)
    sensitive_count=$(count_lines "${OUT_DIR}/sensitive_urls.txt" 2>/dev/null || echo 0)
    oauth_url_count=$(count_lines "${OUT_DIR}/oauth_urls.txt" 2>/dev/null || echo 0)

    local total_findings=$(( email_count + clickjack_count + redirect_count + spoof_count + tabnab_count + csrf_count + oauth_count + takeover_count + header_count ))
    local hunt_duration=$(( $(date +%s) - HUNT_START_EPOCH ))
    local validated_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORTEOF
# Social Engineering Surface Report: ${TARGET_NAME}

**Date**: $(date +%Y-%m-%d)
**Platform**: ${PLATFORM^}
**Researcher**: pythonomus-prime
**Max Critical Payout**: ${MAX_BOUNTY}
**Scanner**: social.sh v${VERSION}
**Hunt Duration**: $(format_duration $hunt_duration)

---

## Executive Summary

Social engineering surface assessment of **${TARGET_NAME}** targeting $(count_lines "$DOMAINS_FILE") domain(s). The scan discovered ${surface_count} surface URLs, ${sensitive_count} sensitive endpoints, and ${oauth_url_count} OAuth/SSO endpoints.

| Category | Count |
|----------|-------|
| Surface URLs (login/register/reset) | ${surface_count} |
| Sensitive endpoints | ${sensitive_count} |
| OAuth/SSO URLs | ${oauth_url_count} |

### Finding Summary

| Category | Count | VRT Max | Script |
|----------|-------|---------|--------|
| Email Spoofing (SPF/DKIM/DMARC) | ${email_count} | P3 | se_email_security.sh |
| Clickjacking | ${clickjack_count} | P4 | se_clickjacking.sh |
| Open Redirect (Auth Flow) | ${redirect_count} | P3 | se_open_redirect.sh |
| Content Spoofing / HTML Injection | ${spoof_count} | P4 | se_content_spoof.sh |
| Reverse Tabnabbing | ${tabnab_count} | P4 | se_reverse_tabnab.sh |
| CSRF on Sensitive Actions | ${csrf_count} | P2 | se_csrf.sh |
| OAuth/SSO Misconfiguration | ${oauth_count} | P1 | se_oauth_misconfig.sh |
| Subdomain Takeover (Auth/Phishing) | ${takeover_count} | P1 | se_takeover_phish.sh |
| Header/Cookie Security | ${header_count} | P5 [DO_NOT_SUBMIT] | se_header_cookie.sh |
| **Total** | **${total_findings}** | | **${validated_count} confirmed** |

### Phase Timing

| Phase | Duration |
|-------|----------|
REPORTEOF

    for phase in se_surface_map se_email_security se_clickjacking se_open_redirect se_content_spoof se_reverse_tabnab se_csrf se_oauth_misconfig se_takeover_phish se_header_cookie; do
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
**Out of scope**: ${OUT_OF_SCOPE}

---

## Findings

REPORTEOF

    # ── Email Spoofing ──
    if [ "$email_count" -gt 0 ]; then
        echo '### Email Spoofing Surface (SPF/DKIM/DMARC)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/email_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Clickjacking ──
    if [ "$clickjack_count" -gt 0 ]; then
        echo '### Clickjacking (P4 max)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/clickjack_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Open Redirect ──
    if [ "$redirect_count" -gt 0 ]; then
        echo '### Open Redirect in Auth Flows' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/redirect_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Content Spoofing ──
    if [ "$spoof_count" -gt 0 ]; then
        echo '### Content Spoofing / HTML Injection' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/content_spoof_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Reverse Tabnabbing ──
    if [ "$tabnab_count" -gt 0 ]; then
        echo '### Reverse Tabnabbing' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '> Note: Modern browsers (Chrome 88+, Firefox 79+) default to `noopener` behavior.' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/tabnab_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── CSRF ──
    if [ "$csrf_count" -gt 0 ]; then
        echo '### CSRF on Sensitive Actions (P2-P3)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/csrf_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── OAuth ──
    if [ "$oauth_count" -gt 0 ]; then
        echo '### OAuth/SSO Misconfiguration (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/oauth_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Subdomain Takeover ──
    if [ "$takeover_count" -gt 0 ]; then
        echo '### Subdomain Takeover — Auth/Phishing Surface (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/takeover_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Header/Cookie (informational) ──
    if [ "$header_count" -gt 0 ]; then
        echo '### Header/Cookie Security [DO_NOT_SUBMIT — P5]' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '> These findings are informational only. Standalone security header' >> "$REPORT_FILE"
        echo '> issues are P5 on all platforms. Only submit if chained with impact.' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/header_cookie_findings.txt" >> "$REPORT_FILE"
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
        echo "No social engineering attack surfaces were identified by automated scanning." >> "$REPORT_FILE"
        echo "Manual testing recommended for complex phishing scenarios and chained exploits." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Footer ──
    cat >> "$REPORT_FILE" << FOOTER

---

## Methodology

This report was generated using social.sh v${VERSION} — a 10-phase SE surface hunting pipeline:

1. **Surface Mapping** — Login/register/reset/OAuth endpoint discovery (curl, httpx, whatweb, katana)
2. **Email Security** — SPF/DKIM/DMARC analysis, spoofing verdict (dig, nuclei)
3. **Clickjacking** — X-Frame-Options + CSP frame-ancestors on sensitive pages (curl, nuclei)
4. **Open Redirect** — Auth flow redirect parameter extraction + bypass testing (curl, httpx)
5. **Content Spoofing** — Reflected content in error pages, search results (curl)
6. **Reverse Tabnabbing** — target="_blank" without rel="noopener" (curl, katana)
7. **CSRF** — Missing CSRF tokens on sensitive forms + SameSite analysis (curl)
8. **OAuth Misconfiguration** — redirect_uri bypass, missing state/PKCE, implicit flow (curl)
9. **Subdomain Takeover** — Dangling CNAMEs on login/auth/sso/mail subdomains (dig, nuclei)
10. **Header/Cookie Security** — Session cookie flags, HSTS, Referrer-Policy (curl, nuclei)

**Note**: This tool identifies SE *attack surfaces* — it does NOT run phishing campaigns.
All findings are passive reconnaissance suitable for bug bounty reporting.

---

*Generated by social.sh v${VERSION} on $(date)*
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
            OUT_OF_SCOPE=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json')).get('out_of_scope','none'))" 2>/dev/null || echo "none")
            SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
            log "Resuming SE hunt: ${TARGET_NAME} from ${OUT_DIR}"
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

    log "SE Hunt started: $(date)"
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
    "out_of_scope": "${OUT_OF_SCOPE}",
    "threads": ${THREADS},
    "timestamp": "$(date -Iseconds)",
    "version": "${VERSION}",
    "tool": "social.sh"
}
CFGEOF

    local primary_domain
    primary_domain=$(sed 's/\*\.//' "$DOMAINS_FILE" | head -1)

    # ═══════════════════════════════════════════════════════
    #  Phase 1: Surface Mapping (feeds all other phases)
    # ═══════════════════════════════════════════════════════
    run_phase 1 "se_surface_map" "se_surface_map.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 2: Email Security (SPF/DKIM/DMARC)
    # ═══════════════════════════════════════════════════════
    run_phase 2 "se_email_security" "se_email_security.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR"

    # ═══════════════════════════════════════════════════════
    #  Phase 3: Clickjacking
    # ═══════════════════════════════════════════════════════
    run_phase 3 "se_clickjacking" "se_clickjacking.sh" -u "${OUT_DIR}/sensitive_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 4: Open Redirect (Auth Flows)
    # ═══════════════════════════════════════════════════════
    run_phase 4 "se_open_redirect" "se_open_redirect.sh" -u "${OUT_DIR}/oauth_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 5: Content Spoofing
    # ═══════════════════════════════════════════════════════
    run_phase 5 "se_content_spoof" "se_content_spoof.sh" -u "${OUT_DIR}/surface_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 6: Reverse Tabnabbing
    # ═══════════════════════════════════════════════════════
    run_phase 6 "se_reverse_tabnab" "se_reverse_tabnab.sh" -u "${OUT_DIR}/surface_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 7: CSRF on Sensitive Actions
    # ═══════════════════════════════════════════════════════
    run_phase 7 "se_csrf" "se_csrf.sh" -u "${OUT_DIR}/sensitive_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 8: OAuth/SSO Misconfiguration
    # ═══════════════════════════════════════════════════════
    run_phase 8 "se_oauth_misconfig" "se_oauth_misconfig.sh" -u "${OUT_DIR}/oauth_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 9: Subdomain Takeover (Phishing Surface)
    # ═══════════════════════════════════════════════════════
    run_phase 9 "se_takeover_phish" "se_takeover_phish.sh" --domains "$DOMAINS_FILE" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 10: Header/Cookie Security
    # ═══════════════════════════════════════════════════════
    run_phase 10 "se_header_cookie" "se_header_cookie.sh" -u "${OUT_DIR}/sensitive_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 10.5: Auto-Validation
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
    echo -e "${BOLD}       SE HUNT COMPLETE: $(date)${NC}"
    echo -e "${BOLD}       Duration: $(format_duration $(( $(date +%s) - HUNT_START_EPOCH )))${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  Report:    ${REPORT_FILE}"
    echo "  Manifest:  ${MANIFEST_FILE}"
    echo "  Data:      ${OUT_DIR}/"
    echo ""
}

main "$@"
