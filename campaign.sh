#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CAMPAIGN.SH — 24/7 Multi-Target Hunt Orchestrator           ║
# ║  Runs hunt.sh sequentially against multiple Bugcrowd targets  ║
# ║  Quality first: low threads, full phases, auto-validation     ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage:
#   ./campaign.sh              # Run all targets, loop forever
#   ./campaign.sh --once       # Run all targets once, then exit
#   ./campaign.sh --dry-run    # Show what would run without executing
#   ./campaign.sh --target 2   # Run only target #2 (Rapyd)
#
# Logs:  hunts/campaign_<date>.log
# Alerts: hunts/FINDINGS_ALERT.md  (appended on each finding)

set -uo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
cd "$SCRIPT_DIR"

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Config ────────────────────────────────────────────────────
THREADS=15                    # Low for quality/stealth
COOLDOWN=300                  # 5 min between targets
CYCLE_COOLDOWN=3600           # 1 hour between full cycles
HUNT="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/hunt.sh"
CAMPAIGN_LOG="./hunts/campaign_$(date +%Y%m%d).log"
FINDINGS_ALERT="./hunts/FINDINGS_ALERT.md"
VALIDATION_LOG="./hunts/validation_$(date +%Y%m%d).log"

mkdir -p ./hunts

# ── Target Definitions ───────────────────────────────────────
# Format: NAME|DOMAINS_FILE|PLATFORM|MAX_BOUNTY|SCOPE_NOTES|OUT_OF_SCOPE
declare -a TARGETS=(
    "Opera|Bugcrowd/Opera/domains.txt|bugcrowd|\$10000|13 wildcards, IP ranges in scope, gx.games + gamemaker.io also in scope|GameMaker Studio 2 desktop app"
    "Rapyd|Bugcrowd/Rapyd/domains.txt|bugcrowd|variable|Fintech payment platform, PCI findings get \$500+ bonus, 10 wildcards|none"
    "Cisco_Meraki|Bugcrowd/Cisco_Meraki/domains.txt|bugcrowd|\$10000|3 wildcards, hardware/firmware also in scope but skip|Meraki hardware devices, mobile apps"
    "SoundCloud|Bugcrowd/SoundCloud/domains.txt|bugcrowd|\$4500|3 wildcards + api-*.soundcloud.com pattern|Mobile apps, third-party integrations"
)

# ── Logging ───────────────────────────────────────────────────
log()   { echo -e "[$(date '+%H:%M:%S')] ${GREEN}[+]${NC} $*" | tee -a "$CAMPAIGN_LOG"; }
warn()  { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}[!]${NC} $*" | tee -a "$CAMPAIGN_LOG"; }
err()   { echo -e "[$(date '+%H:%M:%S')] ${RED}[✗]${NC} $*" | tee -a "$CAMPAIGN_LOG"; }
alert() { echo -e "[$(date '+%H:%M:%S')] ${BOLD}${RED}[ALERT]${NC} $*" | tee -a "$CAMPAIGN_LOG"; }

banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ╔═══════════════════════════════════════════╗
  ║   CAMPAIGN — 24/7 Multi-Target Hunter    ║
  ║   Quality First · Undeniable PoC         ║
  ╚═══════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# ── Parse Args ────────────────────────────────────────────────
LOOP=true
DRY_RUN=false
SINGLE_TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --once)       LOOP=false; shift ;;
        --dry-run)    DRY_RUN=true; shift ;;
        --target)     SINGLE_TARGET="$2"; shift 2 ;;
        --threads)    THREADS="$2"; shift 2 ;;
        --cooldown)   COOLDOWN="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: campaign.sh [--once] [--dry-run] [--target N] [--threads N] [--cooldown SECS]"
            echo ""
            echo "Targets:"
            for i in "${!TARGETS[@]}"; do
                IFS='|' read -r name _ _ _ _ _ <<< "${TARGETS[$i]}"
                echo "  $((i+1)). ${name}"
            done
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Validate Findings ────────────────────────────────────────
# Re-tests key findings with curl to confirm they're real
validate_finding() {
    local finding_file="$1"
    local out_dir="$2"
    local validated_file="${out_dir}/validated_findings.txt"

    [ ! -s "$finding_file" ] && return

    log "Validating findings from $(basename "$finding_file")..."
    local total=0 confirmed=0 failed=0

    while IFS= read -r line; do
        ((total++)) || true
        # Extract URL from finding line
        local url
        url=$(echo "$line" | grep -oP 'https?://[^\s\]\)]+' | head -1)
        [ -z "$url" ] && continue

        # Quick HTTP check — does the endpoint still respond?
        local status
        status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 "$url" 2>/dev/null)

        if [[ "$status" =~ ^(200|301|302|401|403|500)$ ]]; then
            echo "[CONFIRMED:${status}] ${line}" >> "$validated_file"
            ((confirmed++)) || true
        else
            echo "[UNCONFIRMED:${status}] ${line}" >> "$validated_file"
            ((failed++)) || true
        fi
    done < "$finding_file"

    log "Validation: ${confirmed}/${total} confirmed, ${failed} unconfirmed"
    echo "[$(date '+%Y-%m-%d %H:%M')] $(basename "$finding_file"): ${confirmed}/${total} confirmed" >> "$VALIDATION_LOG"
}

# ── Alert on Findings ─────────────────────────────────────────
check_and_alert() {
    local target_name="$1"
    local out_dir="$2"
    local found=false
    local finding_files=(
        nuclei_findings.txt
        xss_findings.txt
        sqli_findings.txt
        ssrf_findings.txt
        redirect_findings.txt
        admin_findings.txt
        secrets_findings.txt
        sweep_findings.txt
        misc_findings.txt
    )

    for ff in "${finding_files[@]}"; do
        local fpath="${out_dir}/${ff}"
        if [ -s "$fpath" ]; then
            local count
            count=$(wc -l < "$fpath" | tr -d ' ')
            if [ "$count" -gt 0 ]; then
                found=true

                # Validate each finding file
                validate_finding "$fpath" "$out_dir"

                # Append to alert file
                {
                    echo ""
                    echo "---"
                    echo "## ${target_name} — $(basename "$ff" .txt) (${count} findings)"
                    echo "**Time**: $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "**Run dir**: ${out_dir}"
                    echo ""
                    echo '```'
                    head -20 "$fpath"
                    echo '```'
                    echo ""

                    # Show validation results if available
                    if [ -s "${out_dir}/validated_findings.txt" ]; then
                        local v_confirmed v_total
                        v_confirmed=$(grep -c '^\[CONFIRMED' "${out_dir}/validated_findings.txt" 2>/dev/null || echo 0)
                        v_total=$(wc -l < "${out_dir}/validated_findings.txt" | tr -d ' ')
                        echo "**Validation**: ${v_confirmed}/${v_total} confirmed live"
                        echo ""
                    fi
                } >> "$FINDINGS_ALERT"
            fi
        fi
    done

    if $found; then
        alert "FINDINGS DETECTED for ${target_name}! Check ${FINDINGS_ALERT}"

        # Desktop notification if notify-send is available
        if command -v notify-send &>/dev/null; then
            notify-send -u critical "Campaign: Findings!" \
                "${target_name} — check ${FINDINGS_ALERT}" 2>/dev/null || true
        fi

        # Terminal bell
        echo -e '\a'
    else
        log "No findings for ${target_name} this run"
    fi
}

# ── Run Hunt Against One Target ──────────────────────────────
run_target() {
    local idx="$1"
    local entry="${TARGETS[$idx]}"

    IFS='|' read -r name domains_file platform max_bounty scope_notes out_of_scope <<< "$entry"

    local safe_name
    safe_name=$(echo "$name" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local run_dir="./hunts/${safe_name}_${timestamp}"

    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  TARGET: ${name}${NC}"
    echo -e "${BOLD}║  Domains: ${domains_file}${NC}"
    echo -e "${BOLD}║  Max Payout: ${max_bounty}${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════╝${NC}"

    log "Starting hunt: ${name}"
    log "Domains file: ${domains_file}"
    log "Output: ${run_dir}"
    log "Threads: ${THREADS}"

    if [ ! -f "$domains_file" ]; then
        err "Domains file not found: ${domains_file}"
        return 1
    fi

    if $DRY_RUN; then
        log "[DRY RUN] Would execute:"
        log "  ${HUNT} -t \"${name}\" -d \"${domains_file}\" -p ${platform} -o \"${run_dir}\" --bounty \"${max_bounty}\" --scope \"${scope_notes}\" --exclude \"${out_of_scope}\" --threads ${THREADS}"
        return 0
    fi

    local start_time
    start_time=$(date +%s)

    # Run hunt.sh with all params — non-interactive CLI mode
    if $HUNT \
        -t "$name" \
        -d "$domains_file" \
        -p "$platform" \
        -o "$run_dir" \
        --bounty "$max_bounty" \
        --scope "$scope_notes" \
        --exclude "$out_of_scope" \
        --threads "$THREADS" \
        2>&1 | tee -a "$CAMPAIGN_LOG"; then

        local end_time elapsed
        end_time=$(date +%s)
        elapsed=$(( end_time - start_time ))
        log "Hunt completed: ${name} ($(( elapsed / 60 ))m $(( elapsed % 60 ))s)"

        # Check for findings and validate
        check_and_alert "$name" "$run_dir"
    else
        err "Hunt FAILED for ${name} (exit code: $?)"
    fi
}

# ── Main Loop ─────────────────────────────────────────────────
main() {
    banner

    # Initialize alert file header if it doesn't exist
    if [ ! -f "$FINDINGS_ALERT" ]; then
        cat > "$FINDINGS_ALERT" << 'HEADER'
# Campaign Findings Alert Log
# Auto-populated by campaign.sh when hunt.sh discovers vulnerabilities
# Each entry includes validation status (CONFIRMED = endpoint still live)

HEADER
    fi

    log "Campaign started"
    log "Mode: $(if $LOOP; then echo '24/7 continuous'; else echo 'single pass'; fi)"
    log "Threads: ${THREADS}"
    log "Cooldown between targets: ${COOLDOWN}s"
    log "Cycle cooldown: ${CYCLE_COOLDOWN}s"
    log "Findings alert: ${FINDINGS_ALERT}"
    echo ""

    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        err "No targets defined in TARGETS array — edit campaign.sh to add targets"
        exit 1
    fi

    if [[ ! -x "$HUNT" ]]; then
        err "hunt.sh not found or not executable: ${HUNT}"
        exit 1
    fi

    # Show targets
    log "Targets:"
    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r name domains _ bounty _ _ <<< "${TARGETS[$i]}"
        local domain_count
        domain_count=$(wc -l < "$domains" 2>/dev/null | tr -d ' ' || echo '?')
        log "  $((i+1)). ${name} — ${domain_count} wildcards — max ${bounty}"
    done
    echo ""

    local cycle=0

    while true; do
        ((cycle++)) || true
        log "═══ CYCLE ${cycle} STARTED $(date '+%Y-%m-%d %H:%M:%S') ═══"

        if [ -n "$SINGLE_TARGET" ]; then
            local tidx=$(( SINGLE_TARGET - 1 ))
            if [ "$tidx" -ge 0 ] && [ "$tidx" -lt "${#TARGETS[@]}" ]; then
                run_target "$tidx"
            else
                err "Invalid target index: ${SINGLE_TARGET} (valid: 1-${#TARGETS[@]})"
                exit 1
            fi
        else
            for i in "${!TARGETS[@]}"; do
                run_target "$i"

                # Cooldown between targets (not after the last one, skip in dry run)
                if [ "$i" -lt $(( ${#TARGETS[@]} - 1 )) ] && ! $DRY_RUN; then
                    log "Cooling down ${COOLDOWN}s before next target..."
                    sleep "$COOLDOWN"
                fi
            done
        fi

        log "═══ CYCLE ${cycle} COMPLETE $(date '+%Y-%m-%d %H:%M:%S') ═══"

        # Summary
        if [ -f "$FINDINGS_ALERT" ]; then
            local alert_count
            alert_count=$(grep -c '^## ' "$FINDINGS_ALERT" 2>/dev/null || echo 0)
            log "Total findings alerts across all cycles: ${alert_count}"
        fi

        if ! $LOOP; then
            log "Single pass mode — exiting"
            break
        fi

        log "Next cycle in ${CYCLE_COOLDOWN}s ($(( CYCLE_COOLDOWN / 60 ))m)..."
        log "Press Ctrl+C to stop gracefully"
        [[ "$CYCLE_COOLDOWN" =~ ^[0-9]+$ ]] && sleep "$CYCLE_COOLDOWN"
    done

    log "Campaign ended"
}

# ── Graceful Shutdown ─────────────────────────────────────────
cleanup() {
    echo ""
    warn "Caught interrupt — shutting down gracefully..."
    warn "Current hunt.sh process may still be running. Check with: ps aux | grep hunt.sh"
    log "Campaign stopped by user at $(date)"
    exit 0
}
trap cleanup SIGINT SIGTERM

main
