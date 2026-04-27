#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  HUNT.SH v3.1 — Modular Bug Bounty Hunting Orchestrator     ║
# ║  Per-phase timing · Resume support · Auto-validation         ║
# ║  JSON manifest · Agent-friendly output · Error recovery      ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   Interactive:  ./hunt.sh
#   CLI mode:     ./hunt.sh --target "Acme Corp" --domains domains.txt \
#                   --platform bugcrowd --out ./output
#   Resume:       ./hunt.sh --resume ./hunts/Acme_20260227_153015
#   Single phase: ./scripts/vuln_xss.sh -d example.com -o ./out
#
# Each script in scripts/ can run standalone or be chained here.

set -uo pipefail

# ── Source shared library ───────────────────────────────────────
HUNT_DIR="$(dirname "$(readlink -f "$0")")"
source "${HUNT_DIR}/lib.sh"

VERSION="4.1.0"
MAX_JS=300
MAX_PARAMS=150
MAX_FUZZ_TARGETS=25
WORDLIST_WEB="${SECLISTS}/Discovery/Web-Content/common.txt"
WORDLIST_API="${SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt"

# Flareprox: if configured, sets HTTP_PROXY for traffic masking
FLAREPROX_URL="${FLAREPROX_URL:-}"

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
  ╦ ╦╦ ╦╔╗╔╔╦╗
  ╠═╣║ ║║║║ ║
  ╩ ╩╚═╝╝╚╝ ╩  v4.1
  Modular Bug Bounty Hunter
EOF
    echo -e "${NC}"
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    local required=(subfinder httpx-pd gau katana nuclei ffuf dalfox nmap curl)
    local optional=(arjun crlfuzz commix nikto ghauri cariddi linkfinder secretfinder gitleaks trufflehog interactsh-client dnsx dig whatweb)

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

    # BHEH tools
    info "Checking BHEH tools (${BHEH_DIR})..."
    local bheh_tools=(
        "evilwaf/evilwaf.py"
        "FormPoison/formpoison.py"
        "ZoomeyeSearch"
        "CF-GeoBypasser-Cyberpunk-Framework/CF-GeoBypasser-Cyberpunk-Framework.sh"
        "flareprox/flareprox.py"
        "ScopeHunter/ScopeHunter.sh"
        "Nucleimonst3r/Nucleimonst3r.sh"
        "TerminatorZ/TerminatorZ.sh"
        "SQLMutant/SQLMutant.sh"
    )
    for btool in "${bheh_tools[@]}"; do
        local bname="${btool%%/*}"
        if [ -e "${BHEH_DIR}/${btool}" ]; then
            log "  BHEH: ${bname} ✓"
        else
            warn "  BHEH: ${bname} (not installed — run bheh_tools/install.sh)"
        fi
    done

    # Scripts check
    info "Checking scripts/ directory..."
    local scripts=(scope recon waf_bypass quick_sweep nuclei_scan secrets vuln_xss vuln_sqli vuln_ssrf vuln_redirect admin_hunt misc_scans takeover_exploiter jwt_attack idor_hunter proto_polluter race_condition)
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
        echo -e "  Enter target domains/IPs ${YELLOW}(one per line, blank line to finish)${NC}:"
        echo "  Examples: *.chime.com  |  10.0.0.1  |  api.example.com"
        echo ""
        DOMAINS_FILE="${OUT_DIR}/domains.txt"
        > "$DOMAINS_FILE"
        while true; do
            read -rp "  > " domain_entry
            [ -z "$domain_entry" ] && break
            echo "$domain_entry" >> "$DOMAINS_FILE"
        done
        if [ ! -s "$DOMAINS_FILE" ]; then
            err "At least one domain or IP is required"
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
            --version|-v) echo "hunt.sh v${VERSION}"; exit 0 ;;
            --help|-h)    usage; exit 0 ;;
            *)            err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUT_DIR="${OUT_DIR:-./hunts/${SAFE_NAME}_${TIMESTAMP}}"
    mkdir -p "$OUT_DIR"
}

usage() {
    echo "Usage: hunt.sh [OPTIONS]"
    echo ""
    echo "Interactive mode (no args):  ./hunt.sh"
    echo ""
    echo "Options:"
    echo "  -t, --target NAME      Target name (e.g., 'Chime')"
    echo "  -d, --domains FILE     File with domains/IPs (one per line)"
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
    echo "  scripts/scope.sh         Scope discovery (ScopeHunter)"
    echo "  scripts/recon.sh         Subdomains, URLs, dorking, nmap"
    echo "  scripts/waf_bypass.sh    WAF detection + bypass"
    echo "  scripts/quick_sweep.sh   Fast 24+ vuln sweep (TerminatorZ)"
    echo "  scripts/nuclei_scan.sh   Nuclei scanning + hail-mary"
    echo "  scripts/secrets.sh       JS secrets + regex grep + nuclei"
    echo "  scripts/vuln_xss.sh      XSS (dalfox + FormPoison)"
    echo "  scripts/vuln_sqli.sh     SQLi (SQLMutant + ghauri)"
    echo "  scripts/vuln_ssrf.sh     SSRF (parameter extraction + probing)"
    echo "  scripts/vuln_redirect.sh Open redirect (parameter extraction + probing)"
    echo "  scripts/admin_hunt.sh    Admin panel discovery"
    echo "  scripts/misc_scans.sh    CRLF, nikto, dir fuzzing, 403 bypass"
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

# Runs a phase with timing, error recovery, and resume support
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
        return 0  # Continue to next phase
    fi

    # Export env vars for child scripts
    export BHEH_DIR SUBMITTED_FILE THREADS NUCLEI_TEMPLATES SECLISTS HUNT_UA
    [ -n "${HTTP_PROXY:-}" ] && export HTTP_PROXY
    [ -n "${HTTPS_PROXY:-}" ] && export HTTPS_PROXY

    # Run with error recovery — don't abort the whole hunt
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
        nuclei_findings.txt xss_findings.txt sqli_findings.txt
        ssrf_findings.txt redirect_findings.txt admin_findings.txt
        secrets_findings.txt sweep_findings.txt misc_findings.txt
        takeover_findings.txt jwt_findings.txt idor_findings.txt
        proto_findings.txt race_findings.txt validated_credentials.txt
        nextjs_findings.txt unicode_findings.txt pathtraversal_findings.txt
        ssti_findings.txt orm_findings.txt deserial_findings.txt
        h2c_findings.txt
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
            [ -z "$url" ] && continue

            local status validation_detail=""
            status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 20 \
                --retry 2 --retry-delay 3 "$url" 2>/dev/null || echo "000")

            # Type-aware validation
            case "$finding_type" in
                misc)
                    # CORS: DO NOT prioritize — 0% acceptance rate across 4 programs
                    # Only flag if we can prove credential-based data theft
                    if echo "$line" | grep -qi "CORS"; then
                        validation_detail="CORS_DEPRIORITIZED"
                        # Skip prioritization — CORS findings waste signal score
                        # To make CORS reportable: build HTML PoC stealing logged-in user data
                    fi
                    ;;
                xss)
                    # Check if CSP blocks XSS execution
                    local csp_header
                    csp_header=$(curl -sk -D- -o /dev/null --max-time 8 "$url" 2>/dev/null | grep -i "content-security-policy" | head -1)
                    if echo "$csp_header" | grep -qiP "(nonce-|strict-dynamic|unsafe-inline)"; then
                        validation_detail="CSP_PRESENT"
                    else
                        validation_detail="NO_CSP"
                        if [[ "$status" =~ ^(200|301|302)$ ]]; then
                            ((high_confidence++)) || true
                            echo "[PRIORITY:XSS] ${line}" >> "$priority_file"
                        fi
                    fi
                    ;;
                admin)
                    # Check for actual content, not just redirects to login
                    if [[ "$status" == "200" ]]; then
                        local body_size
                        body_size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 8 "$url" 2>/dev/null || echo "0")
                        if [ "${body_size:-0}" -gt 500 ]; then
                            validation_detail="ACCESSIBLE_${body_size}B"
                            ((high_confidence++)) || true
                            echo "[PRIORITY:ADMIN] ${line}" >> "$priority_file"
                        fi
                    fi
                    ;;
                nuclei)
                    # Nuclei findings with severity markers get auto-prioritized
                    if echo "$line" | grep -qiP '\[(critical|high)\]'; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:NUCLEI_HIGH] ${line}" >> "$priority_file"
                    fi
                    ;;
                secrets)
                    # Filter out known public-by-design patterns
                    if echo "$line" | grep -qiP '(amplitude|readme\.io|segment|gtag|analytics)'; then
                        validation_detail="PUBLIC_KEY_SKIP"
                        continue
                    fi
                    ;;
                takeover)
                    # Takeover findings are already verified — auto-prioritize CLAIMABLE
                    if echo "$line" | grep -qi "CLAIMABLE"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:TAKEOVER] ${line}" >> "$priority_file"
                    fi
                    ;;
                jwt)
                    # JWT findings: CRIT and HIGH auto-prioritize
                    if echo "$line" | grep -qiP '\[P1:'; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:JWT_CRIT] ${line}" >> "$priority_file"
                    fi
                    ;;
                idor)
                    # IDOR findings: P1 auth removal and horizontal access auto-prioritize
                    if echo "$line" | grep -qiP '(AUTH_REMOVAL|HORIZONTAL_ACCESS|METHOD_SWITCH.*DELETE)'; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:IDOR] ${line}" >> "$priority_file"
                    fi
                    ;;
                proto)
                    # Prototype pollution: SERVER_SIDE confirmed = high priority
                    if echo "$line" | grep -qi "SERVER_SIDE"; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:PROTO] ${line}" >> "$priority_file"
                    fi
                    ;;
                race)
                    # Race conditions: HIGH confidence findings
                    if echo "$line" | grep -qiP '\[P2:RACE:HIGH\]'; then
                        ((high_confidence++)) || true
                        echo "[PRIORITY:RACE] ${line}" >> "$priority_file"
                    fi
                    ;;
            esac

            # ── Recon-Only Detection ──
            # Tag findings that are surface-level discovery without demonstrated exploitation.
            # These get [DO_NOT_SUBMIT] — programs reject "endpoint exists" without proven impact.
            local is_recon_only=false
            if echo "$line" | grep -qiP '(stats\.do|threads\.do|background_progress_worker|xmlstats\.do)' && \
               ! echo "$line" | grep -qiP '(password|secret|token|session|credential|PII|SSN)'; then
                is_recon_only=true  # ServiceNow debug endpoints without sensitive data extraction
            elif echo "$line" | grep -qiP 'wp-json/wp/v2/users'; then
                is_recon_only=true  # WordPress user enum = intended functionality
            elif echo "$line" | grep -qiP '(\.asmx\?wsdl|\.asmx\?WSDL)' && \
                 ! echo "$line" | grep -qiP '(EXPLOITABLE|DATA_ACCESS|AUTH_BYPASS)'; then
                is_recon_only=true  # ASMX WSDL disclosure without exploitation
            elif echo "$line" | grep -qiP '(/api/v1/health|/api/v1/version|actuator/health|actuator/info)' && \
                 ! echo "$line" | grep -qiP '(secret|credential|password|internal)'; then
                is_recon_only=true  # Health/version endpoints without sensitive data
            elif echo "$line" | grep -qiP '(IIS.*default|iisstart\.htm|welcome.*page)'; then
                is_recon_only=true  # Default web server pages
            elif echo "$line" | grep -qiP 'Telerik.*WebResource' && \
                 ! echo "$line" | grep -qiP '(EXPLOITABLE|RCE|UPLOAD|CVE.*confirmed)'; then
                is_recon_only=true  # Telerik handler presence without exploitation proof
            elif echo "$line" | grep -qiP '(fingerprint|banner|version)' && \
                 ! echo "$line" | grep -qiP '(CVE-|critical|high|exploit)'; then
                is_recon_only=true  # Version/banner disclosure without CVE chain
            # ── Rejection-learned patterns (19 Bugcrowd rejections 2026-03) ──
            elif echo "$line" | grep -qiP 'CORS' && \
                 ! echo "$line" | grep -qiP '(steal|exfiltrate|session_data|pii_theft|poc\.html)'; then
                is_recon_only=true  # CORS without data theft PoC (4 rejections)
            elif echo "$line" | grep -qiP '(\.js\.map|source.map|sourcemap)' && \
                 ! echo "$line" | grep -qiP '(api_key_works|credential_valid|secret_verified)'; then
                is_recon_only=true  # Source maps without working secrets (3 rejections)
            elif echo "$line" | grep -qiP '(dangling.cname|nxdomain.*cname|subdomain.takeover)' && \
                 ! echo "$line" | grep -qiP '(CLAIMABLE|claimed|proof_of_control|hosted)'; then
                is_recon_only=true  # Theoretical subdomain takeover (2 rejections)
            elif echo "$line" | grep -qiP '(origin.ip|internal.ip|x-powered-by|server.header.*version)' && \
                 ! echo "$line" | grep -qiP '(waf_bypass|direct_access|ssrf)'; then
                is_recon_only=true  # Header/IP info disclosure (2 rejections)
            elif echo "$line" | grep -qiP '(clickjack|frameable|x-frame-options.miss)' && \
                 ! echo "$line" | grep -qiP '(sensitive_action|disable_2fa|delete_account)'; then
                is_recon_only=true  # Clickjacking without sensitive action (1 rejection)
            elif echo "$line" | grep -qiP '(swagger|openapi|api.doc|developer.portal|backstage)' && \
                 ! echo "$line" | grep -qiP '(private_data|admin_access|write_access|auth_bypass)'; then
                is_recon_only=true  # Public API docs / dev portals (2 rejections)
            elif echo "$line" | grep -qiP '(graphql.*introspection|__schema)' && \
                 ! echo "$line" | grep -qiP '(data_access|mutation|pii|admin)'; then
                is_recon_only=true  # GraphQL introspection without data access
            # ── Additional rejection-learned patterns (25 submissions 2026-03) ──
            elif echo "$line" | grep -qiP '(splunk.*hec|collector/health|splunk-ingest)' && \
                 ! echo "$line" | grep -qiP '(search_api|admin_access|read_data)'; then
                is_recon_only=true  # Splunk HEC = write-only, CORS irrelevant (1 rejection)
            elif echo "$line" | grep -qiP '(sentry.dsn|amplitude|datadog.rum|launchdarkly.client|segment.write|readme.api|mui.license|posthog.api)' && \
                 ! echo "$line" | grep -qiP '(server_key|secret_key|admin_api|write_access)'; then
                is_recon_only=true  # Client-side analytics keys = public by design
            elif echo "$line" | grep -qiP '(open.redirect|redirect_found|url.redirect)' && \
                 ! echo "$line" | grep -qiP '(token_theft|oauth_hijack|ssrf|chain|session)'; then
                is_recon_only=true  # Open redirect without exploitation chain
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

    # Count recon-only findings
    local recon_only_count
    recon_only_count=$(grep -c '^\[DO_NOT_SUBMIT:RECON_ONLY\]' "$validated_file" 2>/dev/null || echo 0)

    # ── Apply Bugcrowd Universal Exclusion Filter ──
    # Tags P5/informational findings that are NEVER rewardable on any program
    local tmp_exclusion
    tmp_exclusion=$(mktemp)
    filter_standard_exclusions "$validated_file" "$tmp_exclusion"
    mv "$tmp_exclusion" "$validated_file"

    # ── Apply Scope Filter (if scope_targets.txt exists) ──
    local tmp_scope
    tmp_scope=$(mktemp)
    filter_oos_findings "$validated_file" "$tmp_scope"
    mv "$tmp_scope" "$validated_file"

    # ── Apply Impact Gate (text-mode filter for known-rejected patterns) ──
    if [[ -f "${HUNT_DIR}/scripts/impact_gate.py" ]]; then
        local gated_file="${OUT_DIR}/gated_findings.txt"
        python3 "${HUNT_DIR}/scripts/impact_gate.py" \
            --input "$validated_file" \
            --output "$gated_file" 2>/dev/null
        local gate_killed
        gate_killed=$(wc -l < "${gated_file%.txt}.killed.txt" 2>/dev/null | tr -d ' ' || echo 0)
        if [ "${gate_killed:-0}" -gt 0 ]; then
            warn "Impact gate killed ${gate_killed} findings (known-rejected patterns)"
        fi
    fi

    # Recount after all filters
    recon_only_count=$(grep -c '^\[DO_NOT_SUBMIT' "$validated_file" 2>/dev/null || echo 0)
    local std_excl_count
    std_excl_count=$(grep -c '^\[DO_NOT_SUBMIT:STANDARD_EXCLUSION\]' "$validated_file" 2>/dev/null || echo 0)
    local oos_count
    oos_count=$(grep -c '^\[DO_NOT_SUBMIT:OOS\]' "$validated_file" 2>/dev/null || echo 0)

    if [ "$total" -gt 0 ]; then
        log "Validation: ${confirmed}/${total} findings confirmed live"
        if [ "$recon_only_count" -gt 0 ]; then
            warn "DO_NOT_SUBMIT total: ${recon_only_count} (recon-only + standard exclusions + OOS)"
        fi
        if [ "$std_excl_count" -gt 0 ]; then
            warn "Bugcrowd standard exclusions (P5/informational): ${std_excl_count}"
        fi
        if [ "$oos_count" -gt 0 ]; then
            warn "Out-of-scope findings: ${oos_count} (target not in scope_targets.txt)"
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
    local finding_files=(nuclei xss sqli ssrf redirect admin secrets sweep misc takeover jwt idor proto race nextjs unicode pathtraversal ssti orm deserial h2c)
    local counts=""

    for ff in "${finding_files[@]}"; do
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

    local url_count all_url_count js_count param_count validated_count priority_count dangling_count cors_count
    url_count=$(wc -l < "${OUT_DIR}/urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
    all_url_count=$(wc -l < "${OUT_DIR}/all_urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
    js_count=$(wc -l < "${OUT_DIR}/js_files.txt" 2>/dev/null | tr -d ' ' || echo 0)
    param_count=$(wc -l < "${OUT_DIR}/parameterized_urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)
    priority_count=$(wc -l < "${OUT_DIR}/priority_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)
    dangling_count=$(wc -l < "${OUT_DIR}/dangling_cnames.txt" 2>/dev/null | tr -d ' ' || echo 0)
    cors_count=$(wc -l < "${OUT_DIR}/cors_findings.txt" 2>/dev/null | tr -d ' ' || echo 0)

    cat > "$MANIFEST_FILE" << JSONEOF
{
    "version": "${VERSION}",
    "target": "${TARGET_NAME}",
    "platform": "${PLATFORM}",
    "timestamp_start": "${HUNT_START_TIME}",
    "timestamp_end": "$(date -Iseconds)",
    "duration_seconds": $(( $(date +%s) - HUNT_START_EPOCH )),
    "threads": ${THREADS},
    "domains_file": "${DOMAINS_FILE}",
    "domains_count": $(wc -l < "$DOMAINS_FILE" | tr -d ' '),
    "output_dir": "${OUT_DIR}",
    "recon": {
        "live_urls": ${url_count},
        "total_urls": ${all_url_count},
        "js_files": ${js_count},
        "parameterized_urls": ${param_count},
        "dangling_cnames": ${dangling_count}
    },
    "findings": { ${counts} },
    "cors_findings": ${cors_count},
    "validated_confirmed": ${validated_count},
    "priority_findings": ${priority_count},
    "phase_durations": { ${phase_timings} },
    "report_file": "${OUT_DIR}/${SAFE_NAME}_REPORT.md"
}
JSONEOF
    log "Manifest: ${MANIFEST_FILE}"
}

# ══════════════════════════════════════════════════════════════
#                    REPORT GENERATION
# ══════════════════════════════════════════════════════════════
generate_report() {
    phase_header 24 "Report Generation"

    REPORT_FILE="${OUT_DIR}/${SAFE_NAME}_REPORT.md"
    info "Generating ${REPORT_FILE}..."

    # ── Dedup: filter out previously-submitted findings ──
    local sub_count
    sub_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    if [ "$sub_count" -gt 0 ]; then
        info "Filtering previously-submitted findings (${sub_count} patterns)..."
        for finding_file in \
            "${OUT_DIR}/nuclei_findings.txt" \
            "${OUT_DIR}/xss_findings.txt" \
            "${OUT_DIR}/sqli_findings.txt" \
            "${OUT_DIR}/ssrf_findings.txt" \
            "${OUT_DIR}/redirect_findings.txt" \
            "${OUT_DIR}/admin_findings.txt" \
            "${OUT_DIR}/secrets_findings.txt" \
            "${OUT_DIR}/sweep_findings.txt" \
            "${OUT_DIR}/misc_findings.txt" \
            "${OUT_DIR}/takeover_findings.txt" \
            "${OUT_DIR}/jwt_findings.txt" \
            "${OUT_DIR}/idor_findings.txt" \
            "${OUT_DIR}/proto_findings.txt" \
            "${OUT_DIR}/race_findings.txt" \
            "${OUT_DIR}/nextjs_findings.txt" \
            "${OUT_DIR}/unicode_findings.txt" \
            "${OUT_DIR}/pathtraversal_findings.txt" \
            "${OUT_DIR}/ssti_findings.txt" \
            "${OUT_DIR}/orm_findings.txt" \
            "${OUT_DIR}/deserial_findings.txt" \
            "${OUT_DIR}/h2c_findings.txt"; do
            if [ -s "$finding_file" ]; then
                filter_submitted "$finding_file" "${finding_file}.deduped"
                mv "${finding_file}.deduped" "$finding_file"
            fi
        done
    fi

    # Count findings
    local nuclei_count xss_count sqli_count ssrf_count redirect_count admin_count secrets_count sweep_count misc_count
    local takeover_count jwt_count idor_count proto_count race_count
    local nextjs_count unicode_count pathtraversal_count ssti_count orm_count deserial_count h2c_count
    nuclei_count=$(count_lines "${OUT_DIR}/nuclei_findings.txt" 2>/dev/null || echo 0)
    xss_count=$(count_lines "${OUT_DIR}/xss_findings.txt" 2>/dev/null || echo 0)
    sqli_count=$(count_lines "${OUT_DIR}/sqli_findings.txt" 2>/dev/null || echo 0)
    ssrf_count=$(count_lines "${OUT_DIR}/ssrf_findings.txt" 2>/dev/null || echo 0)
    redirect_count=$(count_lines "${OUT_DIR}/redirect_findings.txt" 2>/dev/null || echo 0)
    admin_count=$(count_lines "${OUT_DIR}/admin_findings.txt" 2>/dev/null || echo 0)
    secrets_count=$(count_lines "${OUT_DIR}/secrets_findings.txt" 2>/dev/null || echo 0)
    sweep_count=$(count_lines "${OUT_DIR}/sweep_findings.txt" 2>/dev/null || echo 0)
    misc_count=$(count_lines "${OUT_DIR}/misc_findings.txt" 2>/dev/null || echo 0)
    takeover_count=$(count_lines "${OUT_DIR}/takeover_findings.txt" 2>/dev/null || echo 0)
    jwt_count=$(count_lines "${OUT_DIR}/jwt_findings.txt" 2>/dev/null || echo 0)
    idor_count=$(count_lines "${OUT_DIR}/idor_findings.txt" 2>/dev/null || echo 0)
    proto_count=$(count_lines "${OUT_DIR}/proto_findings.txt" 2>/dev/null || echo 0)
    race_count=$(count_lines "${OUT_DIR}/race_findings.txt" 2>/dev/null || echo 0)
    nextjs_count=$(count_lines "${OUT_DIR}/nextjs_findings.txt" 2>/dev/null || echo 0)
    unicode_count=$(count_lines "${OUT_DIR}/unicode_findings.txt" 2>/dev/null || echo 0)
    pathtraversal_count=$(count_lines "${OUT_DIR}/pathtraversal_findings.txt" 2>/dev/null || echo 0)
    ssti_count=$(count_lines "${OUT_DIR}/ssti_findings.txt" 2>/dev/null || echo 0)
    orm_count=$(count_lines "${OUT_DIR}/orm_findings.txt" 2>/dev/null || echo 0)
    deserial_count=$(count_lines "${OUT_DIR}/deserial_findings.txt" 2>/dev/null || echo 0)
    h2c_count=$(count_lines "${OUT_DIR}/h2c_findings.txt" 2>/dev/null || echo 0)

    local url_count all_url_count js_count param_count
    url_count=$(count_lines "${OUT_DIR}/urls.txt" 2>/dev/null || echo 0)
    all_url_count=$(count_lines "${OUT_DIR}/all_urls.txt" 2>/dev/null || echo 0)
    js_count=$(count_lines "${OUT_DIR}/js_files.txt" 2>/dev/null || echo 0)
    param_count=$(count_lines "${OUT_DIR}/parameterized_urls.txt" 2>/dev/null || echo 0)

    local total_findings=$(( nuclei_count + xss_count + sqli_count + ssrf_count + redirect_count + admin_count + secrets_count + sweep_count + misc_count + takeover_count + jwt_count + idor_count + proto_count + race_count + nextjs_count + unicode_count + pathtraversal_count + ssti_count + orm_count + deserial_count + h2c_count ))
    local hunt_duration=$(( $(date +%s) - HUNT_START_EPOCH ))
    local validated_count recon_only_count
    validated_count=$(grep -c '^\[CONFIRMED' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)
    recon_only_count=$(grep -c '^\[DO_NOT_SUBMIT:RECON_ONLY\]' "${OUT_DIR}/validated_findings.txt" 2>/dev/null || echo 0)

    cat > "$REPORT_FILE" << REPORTEOF
# Bug Bounty Report: ${TARGET_NAME}

**Date**: $(date +%Y-%m-%d)
**Platform**: ${PLATFORM^}
**Researcher**: pythonomus-prime
**Max Critical Payout**: ${MAX_BOUNTY}
**Scanner**: hunt.sh v${VERSION}
**Hunt Duration**: $(format_duration $hunt_duration)

---

## Executive Summary

Automated security assessment of **${TARGET_NAME}** targeting $(count_lines "$DOMAINS_FILE") domain(s). The hunt discovered ${url_count} live URLs, ${all_url_count} total URLs, analyzed ${js_count} JavaScript files, and tested ${param_count} parameterized endpoints.

| Category | Count |
|----------|-------|
| Live URLs | ${url_count} |
| Total URLs (gau+katana) | ${all_url_count} |
| JS files analyzed | ${js_count} |
| Parameterized URLs | ${param_count} |

### Finding Summary

| Category | Count | Validated | Script |
|----------|-------|-----------|--------|
| Nuclei (crit/high/med/exposure) | ${nuclei_count} | — | nuclei_scan.sh |
| Quick Sweep | ${sweep_count} | — | quick_sweep.sh |
| XSS | ${xss_count} | — | vuln_xss.sh |
| SQLi | ${sqli_count} | — | vuln_sqli.sh |
| SSRF | ${ssrf_count} | — | vuln_ssrf.sh |
| Open Redirect | ${redirect_count} | — | vuln_redirect.sh |
| Admin Panels | ${admin_count} | — | admin_hunt.sh |
| Secrets/API Keys | ${secrets_count} | — | secrets.sh |
| Misc (CRLF/Nikto/Fuzz/403) | ${misc_count} | — | misc_scans.sh |
| Subdomain Takeover | ${takeover_count} | — | takeover_exploiter.sh |
| JWT Auth Bypass | ${jwt_count} | — | jwt_attack.sh |
| IDOR / Broken Access | ${idor_count} | — | idor_hunter.sh |
| Prototype Pollution | ${proto_count} | — | proto_polluter.sh |
| Race Condition | ${race_count} | — | race_condition.sh |
| Next.js Cache Poison | ${nextjs_count} | — | nextjs_poison.sh |
| Unicode WAF Bypass | ${unicode_count} | — | unicode_bypass.sh |
| Path Traversal | ${pathtraversal_count} | — | path_traversal.sh |
| SSTI | ${ssti_count} | — | ssti_scan.sh |
| ORM Injection | ${orm_count} | — | orm_leak.sh |
| Deserialization | ${deserial_count} | — | deserial_scan.sh |
| h2c Smuggling | ${h2c_count} | — | h2c_smuggle.sh |
| **Total** | **${total_findings}** | **${validated_count} confirmed** | |
| **Recon-Only (DO NOT SUBMIT)** | **${recon_only_count}** | — | — |

> **⚠ SUBMISSION GATE**: ${recon_only_count} findings are tagged RECON_ONLY — these lack demonstrated
> exploitation and will be closed as Informative. Only submit findings with proven data access,
> credential use, or auth bypass. See validated_findings.txt for [DO_NOT_SUBMIT] entries.

### Phase Timing

| Phase | Duration |
|-------|----------|
REPORTEOF

    for phase in recon waf_bypass quick_sweep nuclei_scan secrets vuln_xss vuln_sqli vuln_ssrf vuln_redirect admin_hunt misc_scans takeover_exploiter jwt_attack idor_hunter proto_polluter race_condition; do
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

    # ── Nuclei Findings ──
    if [ "$nuclei_count" -gt 0 ]; then
        echo '### Nuclei Findings' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        while IFS= read -r line; do
            local template url
            template=$(echo "$line" | grep -oP '\[\K[^\]]+' | head -1)
            url=$(echo "$line" | grep -oP 'https?://[^\s"<>]+')
            echo "- \`${template}\` — ${url}" >> "$REPORT_FILE"
        done < "${OUT_DIR}/nuclei_findings.txt"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Quick Sweep ──
    if [ "$sweep_count" -gt 0 ]; then
        echo '### Quick Sweep (TerminatorZ)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/sweep_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── XSS ──
    if [ "$xss_count" -gt 0 ]; then
        echo '### XSS (Cross-Site Scripting)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/xss_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── SQLi ──
    if [ "$sqli_count" -gt 0 ]; then
        echo '### SQL Injection' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/sqli_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── SSRF ──
    if [ "$ssrf_count" -gt 0 ]; then
        echo '### SSRF (Server-Side Request Forgery)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/ssrf_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Open Redirect ──
    if [ "$redirect_count" -gt 0 ]; then
        echo '### Open Redirect' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/redirect_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Admin Panels ──
    if [ "$admin_count" -gt 0 ]; then
        echo '### Admin Panels' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/admin_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Secrets ──
    if [ "$secrets_count" -gt 0 ]; then
        echo '### Exposed Secrets / API Keys' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/secrets_findings.txt" | while IFS= read -r line; do
            echo "- \`${line}\`" >> "$REPORT_FILE"
        done
        echo "" >> "$REPORT_FILE"
    fi

    # ── Misc ──
    if [ "$misc_count" -gt 0 ]; then
        echo '### Miscellaneous (CRLF, Nikto, Dir Fuzz, 403 Bypass)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        head -40 "${OUT_DIR}/misc_findings.txt" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Subdomain Takeover ──
    if [ "$takeover_count" -gt 0 ]; then
        echo '### Subdomain Takeover (P1-P3)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/takeover_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── JWT Auth Bypass ──
    if [ "$jwt_count" -gt 0 ]; then
        echo '### JWT Authentication Bypass (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/jwt_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── IDOR / Broken Access Control ──
    if [ "$idor_count" -gt 0 ]; then
        echo '### IDOR / Broken Access Control (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/idor_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Prototype Pollution ──
    if [ "$proto_count" -gt 0 ]; then
        echo '### Prototype Pollution (P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/proto_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Race Condition ──
    if [ "$race_count" -gt 0 ]; then
        echo '### Race Condition / TOCTOU (P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/race_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Next.js Cache Poisoning ──
    if [ "$nextjs_count" -gt 0 ]; then
        echo '### Next.js Cache Poisoning (P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/nextjs_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Unicode WAF Bypass ──
    if [ "$unicode_count" -gt 0 ]; then
        echo '### Unicode Normalization WAF Bypass (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/unicode_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Path Traversal ──
    if [ "$pathtraversal_count" -gt 0 ]; then
        echo '### Path Traversal (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/pathtraversal_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── SSTI ──
    if [ "$ssti_count" -gt 0 ]; then
        echo '### Server-Side Template Injection (P1)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/ssti_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── ORM Injection ──
    if [ "$orm_count" -gt 0 ]; then
        echo '### ORM Injection / Data Leak (P1-P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/orm_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Deserialization ──
    if [ "$deserial_count" -gt 0 ]; then
        echo '### Deserialization (P1)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/deserial_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── h2c Smuggling ──
    if [ "$h2c_count" -gt 0 ]; then
        echo '### HTTP/2 h2c Smuggling (P2)' >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -20 "${OUT_DIR}/h2c_findings.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Priority Findings (high-confidence, triage first) ──
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

    # ── Dangling CNAMEs (subdomain takeover) ──
    if [ -s "${OUT_DIR}/dangling_cnames.txt" ]; then
        local dc_count
        dc_count=$(wc -l < "${OUT_DIR}/dangling_cnames.txt" | tr -d ' ')
        echo "### Dangling CNAMEs — Subdomain Takeover Candidates (${dc_count})" >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        cat "${OUT_DIR}/dangling_cnames.txt" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── CORS Findings ──
    if [ -s "${OUT_DIR}/cors_findings.txt" ]; then
        echo "### CORS Misconfiguration" >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        cat "${OUT_DIR}/cors_findings.txt" | while IFS= read -r line; do
            echo "- \`${line}\`" >> "$REPORT_FILE"
        done
        echo "" >> "$REPORT_FILE"
    fi

    # ── Header Info Disclosure ──
    if [ -s "${OUT_DIR}/header_info_disclosure.txt" ]; then
        echo "### Response Header Info Disclosure" >> "$REPORT_FILE"
        echo '' >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -30 "${OUT_DIR}/header_info_disclosure.txt" >> "$REPORT_FILE"
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
        echo "No exploitable vulnerabilities were identified by automated scanning." >> "$REPORT_FILE"
        echo "Manual testing recommended for complex business logic flaws and chained exploits." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Nmap results ──
    if [ -s "${OUT_DIR}/nmap_results.txt" ]; then
        cat >> "$REPORT_FILE" << 'SECTION'
---

## Network Scan (Nmap)

SECTION
        echo '```' >> "$REPORT_FILE"
        grep -A2 "Nmap scan report\|open" "${OUT_DIR}/nmap_results.txt" | head -60 >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── Footer ──
    cat >> "$REPORT_FILE" << FOOTER

---

## Methodology

This report was generated using hunt.sh v${VERSION} — a modular 24-phase hunting pipeline:

1. **Recon** — subfinder, httpx (w/ header analysis), dnsx (CNAME takeover), gau, katana, arjun, nmap, ZoomeyeSearch
2. **WAF Detection** — EvilWAF, CF-GeoBypasser
3. **Quick Sweep** — TerminatorZ (24+ vuln types)
4. **Nuclei Scanning** — nuclei (crit/high/med/exposures + takeover + CORS + DNS + panels)
5. **Secrets** — SecretFinder, LinkFinder, cariddi, gitleaks, nuclei, regex (+ noise filtering)
6. **XSS** — dalfox, FormPoison
7. **SQLi** — SQLMutant, ghauri, sqlmap
8. **SSRF** — parameter extraction, internal IP probing, interactsh OOB callbacks
9. **Open Redirect** — parameter extraction, redirect probing
10. **Admin Panels** — ffuf + 60+ known misconfig endpoints (Vault, Metabase, Airflow, Actuator, etc.)
11. **Misc** — CORS scanning, header info disclosure, crlfuzz, nikto, ffuf, 403 bypass
12. **Subdomain Takeover** — CNAME verification, service fingerprinting, nuclei takeover templates (74 fingerprints)
13. **JWT Attack** — Token extraction from JS/URLs/responses, alg:none, HMAC brute-force, key confusion, claim analysis
14. **IDOR / Broken Access** — Auth removal, ID manipulation, horizontal access (token swap), method switching
15. **Prototype Pollution** — JSON body + query param injection, __proto__ + constructor, persistence verification
16. **Race Condition** — Concurrent request firing (aiohttp), duplicate success detection, timing analysis
17. **Next.js Cache Poison** — CVE-2024-46982 SSR→SSG, __nextDataReq, middleware prefetch, RSC, locale
18. **Unicode WAF Bypass** — Fullwidth chars, homoglyphs, overlong UTF-8 to bypass WAF filtering
19. **Path Traversal** — 20+ encoding variants (URL, double, overlong, null byte, PHP wrappers, Java semicolons)
20. **SSTI** — Polyglot detection, engine fingerprinting (Jinja2/Twig/Freemarker/Velocity/ERB/EJS), safe escalation
21. **ORM Injection** — Django/Rails Ransack/Prisma/Sequelize filter operators, differential response analysis
22. **Deserialization** — Java/PHP/.NET/Python serialized objects in responses/cookies/params, ViewState analysis
23. **h2c Smuggling** — HTTP/2 cleartext upgrade, CONNECT tunneling, WebSocket upgrade bypass, TE desync
17. **Report** — Markdown generation + type-aware validation + priority triage + JSON manifest

---

*Generated by hunt.sh v${VERSION} on $(date)*
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
    trap 'rm -f /tmp/hunt_$$ /tmp/hunt_$$_* 2>/dev/null' EXIT
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
        # Load config from previous run
        if [ -f "${OUT_DIR}/hunt_config.json" ]; then
            if ! python3 -c "import json,sys; json.load(open('${OUT_DIR}/hunt_config.json'))" 2>/dev/null; then
                err "Corrupt hunt_config.json in ${OUT_DIR} — cannot resume"
                exit 1
            fi
            TARGET_NAME=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['target'])" 2>/dev/null || echo "Unknown")
            PLATFORM=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['platform'])" 2>/dev/null || echo "other")
            DOMAINS_FILE=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['domains_file'])" 2>/dev/null || echo "")
            MAX_BOUNTY=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json'))['max_bounty'])" 2>/dev/null || echo "unknown")
            SCOPE_NOTES=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json')).get('scope_notes','none'))" 2>/dev/null || echo "none")
            OUT_OF_SCOPE=$(python3 -c "import json; print(json.load(open('${OUT_DIR}/hunt_config.json')).get('out_of_scope','none'))" 2>/dev/null || echo "none")
            SAFE_NAME=$(echo "$TARGET_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')
            log "Resuming hunt: ${TARGET_NAME} from ${OUT_DIR}"
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

    # Show previously submitted findings if any exist
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

    # Apply Flareprox proxy if configured
    if [ -n "$FLAREPROX_URL" ]; then
        export HTTP_PROXY="$FLAREPROX_URL"
        export HTTPS_PROXY="$FLAREPROX_URL"
        log "Flareprox active: routing traffic through ${FLAREPROX_URL}"
    fi

    log "Hunt started: $(date)"
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
    "version": "${VERSION}"
}
CFGEOF

    local primary_domain
    primary_domain=$(sed 's/\*\.//' "$DOMAINS_FILE" | head -1)

    # ═══════════════════════════════════════════════════════
    #  Phase 1: Recon
    # ═══════════════════════════════════════════════════════
    run_phase 1 "recon" "recon.sh" --domains "$DOMAINS_FILE" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 2: WAF Detection & Bypass
    # ═══════════════════════════════════════════════════════
    run_phase 2 "waf_bypass" "waf_bypass.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 3: Quick Sweep (TerminatorZ)
    # ═══════════════════════════════════════════════════════
    run_phase 3 "quick_sweep" "quick_sweep.sh" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 4: Nuclei Scanning
    # ═══════════════════════════════════════════════════════
    run_phase 4 "nuclei_scan" "nuclei_scan.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 5: Secrets
    # ═══════════════════════════════════════════════════════
    run_phase 5 "secrets" "secrets.sh" -u "${OUT_DIR}/urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 5b: Credential Validation
    # ═══════════════════════════════════════════════════════
    run_phase 5b "cred_validate" "credential_validator.sh" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 6: XSS
    # ═══════════════════════════════════════════════════════
    run_phase 6 "vuln_xss" "vuln_xss.sh" -u "${OUT_DIR}/parameterized_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 7: SQLi
    # ═══════════════════════════════════════════════════════
    run_phase 7 "vuln_sqli" "vuln_sqli.sh" -u "${OUT_DIR}/parameterized_urls.txt" -d "$primary_domain" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 8: SSRF
    # ═══════════════════════════════════════════════════════
    run_phase 8 "vuln_ssrf" "vuln_ssrf.sh" -d "$primary_domain" -u "${OUT_DIR}/all_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 9: Open Redirect
    # ═══════════════════════════════════════════════════════
    run_phase 9 "vuln_redirect" "vuln_redirect.sh" -d "$primary_domain" -u "${OUT_DIR}/all_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 10: Admin Panel Discovery
    # ═══════════════════════════════════════════════════════
    run_phase 10 "admin_hunt" "admin_hunt.sh" -d "$primary_domain" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 11: Misc (CRLF, nikto, dir fuzzing, 403 bypass)
    # ═══════════════════════════════════════════════════════
    run_phase 11 "misc_scans" "misc_scans.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 12: Subdomain Takeover Verification
    # ═══════════════════════════════════════════════════════
    run_phase 12 "takeover_exploiter" "takeover_exploiter.sh" -u "${OUT_DIR}/dangling_cnames.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 13: JWT Token Extraction & Attack
    # ═══════════════════════════════════════════════════════
    run_phase 13 "jwt_attack" "jwt_attack.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 14: IDOR / Broken Access Control
    # ═══════════════════════════════════════════════════════
    run_phase 14 "idor_hunter" "idor_hunter.sh" -u "${OUT_DIR}/all_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 15: Prototype Pollution
    # ═══════════════════════════════════════════════════════
    run_phase 15 "proto_polluter" "proto_polluter.sh" -u "${OUT_DIR}/all_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 16: Race Condition Testing
    # ═══════════════════════════════════════════════════════
    run_phase 16 "race_condition" "race_condition.sh" -u "${OUT_DIR}/all_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 17: Next.js Cache Poisoning
    # ═══════════════════════════════════════════════════════
    run_phase 17 "nextjs_poison" "nextjs_poison.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 18: Unicode Normalization WAF Bypass
    # ═══════════════════════════════════════════════════════
    run_phase 18 "unicode_bypass" "unicode_bypass.sh" -u "${OUT_DIR}/parameterized_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 19: Path Traversal
    # ═══════════════════════════════════════════════════════
    run_phase 19 "path_traversal" "path_traversal.sh" -u "${OUT_DIR}/parameterized_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 20: Server-Side Template Injection
    # ═══════════════════════════════════════════════════════
    run_phase 20 "ssti_scan" "ssti_scan.sh" -u "${OUT_DIR}/parameterized_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 21: ORM Injection / Data Leak
    # ═══════════════════════════════════════════════════════
    run_phase 21 "orm_leak" "orm_leak.sh" -u "${OUT_DIR}/all_urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 22: Deserialization Scanner
    # ═══════════════════════════════════════════════════════
    run_phase 22 "deserial_scan" "deserial_scan.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 23: HTTP/2 h2c Smuggling
    # ═══════════════════════════════════════════════════════
    run_phase 23 "h2c_smuggle" "h2c_smuggle.sh" -u "${OUT_DIR}/urls.txt" -o "$OUT_DIR" -t "$THREADS"

    # ═══════════════════════════════════════════════════════
    #  Phase 23.5: Auto-Validation
    # ═══════════════════════════════════════════════════════
    phase_header "23.5" "Auto-Validation"
    validate_findings

    # ═══════════════════════════════════════════════════════
    #  Phase 12: Report + Manifest
    # ═══════════════════════════════════════════════════════
    generate_report
    generate_manifest

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "${BOLD}       HUNT COMPLETE: $(date)${NC}"
    echo -e "${BOLD}       Duration: $(format_duration $(( $(date +%s) - HUNT_START_EPOCH )))${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  Report:    ${REPORT_FILE}"
    echo "  Manifest:  ${MANIFEST_FILE}"
    echo "  Data:      ${OUT_DIR}/"
    echo ""
}

main "$@"
