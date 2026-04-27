#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  monitor.sh — Persistent Recon: Daily Change Detection       ║
# ║  Run via cron: 0 6 * * * ~/operator_toolbox/Bug_Bounty/scripts/monitor.sh
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

MONITOR_DIR="${HOME}/operator_toolbox/Bug_Bounty/monitor"
TARGETS_DIR="${HOME}/operator_toolbox/Bug_Bounty/Bugcrowd"
LOG="${MONITOR_DIR}/monitor.log"
ALERT_FILE="${MONITOR_DIR}/alerts_$(date +%Y%m%d).txt"

mkdir -p "${MONITOR_DIR}/state"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
alert() { echo "[ALERT $(date '+%H:%M:%S')] $*" | tee -a "$ALERT_FILE" "$LOG"; }

log "=== Monitor run: $(date) ==="

# Collect all domains.txt files from active programs
> "${MONITOR_DIR}/_all_domains.txt"
for f in "${TARGETS_DIR}"/*/domains.txt; do
    [ -f "$f" ] && cat "$f" >> "${MONITOR_DIR}/_all_domains.txt"
done
sort -u -o "${MONITOR_DIR}/_all_domains.txt" "${MONITOR_DIR}/_all_domains.txt"
DOMAINS=$(sed 's/\*\.//' "${MONITOR_DIR}/_all_domains.txt" | sort -u)
domain_count=$(echo "$DOMAINS" | wc -l)
log "Monitoring ${domain_count} domains across all programs"

# ═══ 1. New Subdomain Detection ═══
log "Phase 1: Subdomain enumeration..."
echo "$DOMAINS" | subfinder -silent -all 2>/dev/null | sort -u > "${MONITOR_DIR}/subs_today.txt"

if [ -f "${MONITOR_DIR}/state/subs_previous.txt" ]; then
    comm -13 "${MONITOR_DIR}/state/subs_previous.txt" "${MONITOR_DIR}/subs_today.txt" \
        > "${MONITOR_DIR}/subs_new.txt"
    new_count=$(wc -l < "${MONITOR_DIR}/subs_new.txt" | tr -d ' ')
    if [ "$new_count" -gt 0 ]; then
        alert "NEW SUBDOMAINS DETECTED: ${new_count}"
        while read -r sub; do
            alert "  + ${sub}"
        done < "${MONITOR_DIR}/subs_new.txt"

        # Probe new subdomains for live hosts
        httpx-pd -l "${MONITOR_DIR}/subs_new.txt" -silent \
            -status-code -title -tech-detect \
            -o "${MONITOR_DIR}/new_live.txt" 2>/dev/null || true
        live_new=$(wc -l < "${MONITOR_DIR}/new_live.txt" 2>/dev/null | tr -d ' ' || echo 0)
        if [ "$live_new" -gt 0 ]; then
            alert "NEW LIVE HOSTS: ${live_new} — HUNT THESE"
            cat "${MONITOR_DIR}/new_live.txt" >> "$ALERT_FILE"
        fi

        # Quick nuclei scan on new hosts
        if [ "$live_new" -gt 0 ]; then
            log "Running nuclei on new hosts..."
            grep -oP 'https?://[^\s\[\]]+' "${MONITOR_DIR}/new_live.txt" 2>/dev/null | \
                nuclei -severity critical,high -silent \
                -o "${MONITOR_DIR}/new_nuclei.txt" 2>/dev/null || true
            nuclei_hits=$(wc -l < "${MONITOR_DIR}/new_nuclei.txt" 2>/dev/null | tr -d ' ' || echo 0)
            if [ "$nuclei_hits" -gt 0 ]; then
                alert "NUCLEI HITS ON NEW HOSTS: ${nuclei_hits}"
                cat "${MONITOR_DIR}/new_nuclei.txt" >> "$ALERT_FILE"
            fi
        fi
    else
        log "No new subdomains detected"
    fi
else
    log "First run — establishing baseline"
fi
cp "${MONITOR_DIR}/subs_today.txt" "${MONITOR_DIR}/state/subs_previous.txt"

# ═══ 2. Secret Scanning (public repos) ═══
# Only run if trufflehog is available and we have GitHub org targets
if command -v trufflehog &>/dev/null; then
    log "Phase 2: Secret scanning (trufflehog on public repos)..."
    # Scan any GitHub orgs listed in program READMEs
    for readme in "${TARGETS_DIR}"/*/README.md; do
        [ -f "$readme" ] || continue
        program=$(basename "$(dirname "$readme")")
        # Extract GitHub org URLs from READMEs
        github_orgs=$(grep -oP 'github\.com/[a-zA-Z0-9_-]+' "$readme" 2>/dev/null | sort -u | head -3)
        for org_url in $github_orgs; do
            log "  Scanning https://${org_url} ..."
            trufflehog github --org "$(basename "$org_url")" --only-verified \
                --json 2>/dev/null | head -20 > "${MONITOR_DIR}/secrets_${program}.json" || true
            secret_count=$(wc -l < "${MONITOR_DIR}/secrets_${program}.json" 2>/dev/null | tr -d ' ' || echo 0)
            if [ "$secret_count" -gt 0 ]; then
                alert "VERIFIED SECRETS in ${program} GitHub: ${secret_count}"
            fi
        done
    done
fi

# ═══ 3. Summary ═══
total_alerts=$(wc -l < "$ALERT_FILE" 2>/dev/null | tr -d ' ' || echo 0)
log "Monitor complete. Alerts: ${total_alerts}"
if [ "$total_alerts" -gt 0 ]; then
    log "Alert file: ${ALERT_FILE}"
    # If notify is configured, send alerts
    if command -v notify &>/dev/null && [ -f "${HOME}/.config/notify/provider-config.yaml" ]; then
        cat "$ALERT_FILE" | notify -silent 2>/dev/null || true
    fi
fi
