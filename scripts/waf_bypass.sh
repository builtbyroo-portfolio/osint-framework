#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  waf_bypass.sh — WAF Detection & Bypass Analysis             ║
# ║  EvilWAF fingerprinting + CF-GeoBypasser                     ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="waf_bypass.sh"
SCRIPT_DESC="WAF Detection & Bypass"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Detect WAFs and test bypass techniques."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE      File with URLs to scan"
    echo "  -d, --domain DOMAIN  Single target domain"
    echo "  -o, --out DIR        Output directory (default: ./out)"
    echo "  -t, --threads N      Concurrency (default: 30)"
    echo "  -h, --help           Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "WAF" "$SCRIPT_DESC"

# Determine input URLs
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    urls_input="$URLS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    echo "https://${DOMAIN}" > "${OUT_DIR}/_waf_targets.txt"
    urls_input="${OUT_DIR}/_waf_targets.txt"
else
    err "Provide --urls or --domain"
    script_usage
    exit 1
fi

WAF_DETECTED=0
mkdir -p "${OUT_DIR}/waf"

# ── EvilWAF ──
if check_bheh "evilwaf/evilwaf.py"; then
    info "Running EvilWAF (WAF fingerprinting + bypass analysis)..."
    while IFS= read -r url; do
        host=$(echo "$url" | sed 's|https\?://||;s|/.*||')
        info "EvilWAF scanning: ${host}..."
        python3 "${BHEH_DIR}/evilwaf/evilwaf.py" -d "$url" \
            -o "${OUT_DIR}/waf/${host}.json" 2>/dev/null || true
        if [ -s "${OUT_DIR}/waf/${host}.json" ]; then
            ((WAF_DETECTED++)) || true
        fi
    done < <(head -10 "$urls_input")
    log "EvilWAF: scanned $(head -10 "$urls_input" | wc -l) hosts, ${WAF_DETECTED} with WAF detected"
else
    warn "EvilWAF not installed — skipping WAF fingerprinting"
fi

# ── CF-GeoBypasser (Cloudflare bypass) ──
# NOTE: CF-GeoBypasser is fully interactive (menus, lolcat, sleep).
# It cannot run in non-interactive/piped mode (hunt.sh, campaign.sh).
# Skip it in automated runs — only use manually.
if [ -t 0 ] && check_bheh "CF-GeoBypasser-Cyberpunk-Framework/CF-GeoBypasser-Cyberpunk-Framework.sh"; then
    # Check if any hosts have Cloudflare
    cf_hosts=""
    if [ -f "${OUT_DIR}/live_hosts_raw.txt" ]; then
        cf_hosts=$(grep -i "cloudflare" "${OUT_DIR}/live_hosts_raw.txt" 2>/dev/null || true)
    fi

    if [ -n "$cf_hosts" ]; then
        info "Cloudflare detected — running CF-GeoBypasser..."
        mkdir -p "${OUT_DIR}/cf_bypass"
        echo "$cf_hosts" | grep -oP 'https?://[^\s\[\]]+' | head -10 > "${OUT_DIR}/cf_bypass/cf_targets.txt" 2>/dev/null || true

        if [ -s "${OUT_DIR}/cf_bypass/cf_targets.txt" ]; then
            while IFS= read -r url; do
                host=$(echo "$url" | sed 's|https\?://||;s|/.*||')
                bash "${BHEH_DIR}/CF-GeoBypasser-Cyberpunk-Framework/CF-GeoBypasser-Cyberpunk-Framework.sh" \
                    --target "$host" --output "${OUT_DIR}/cf_bypass/" \
                    2>/dev/null || true
            done < "${OUT_DIR}/cf_bypass/cf_targets.txt"
            cf_count=$(find "${OUT_DIR}/cf_bypass" -name "*.txt" ! -name "cf_targets.txt" -size +0 2>/dev/null | wc -l || echo 0)
            log "CF-GeoBypasser: ${cf_count} bypass result files"
        fi
    else
        info "No Cloudflare hosts detected, skipping CF-GeoBypasser"
    fi
elif [ ! -t 0 ]; then
    warn "CF-GeoBypasser skipped (interactive-only, not available in piped/automated mode)"
else
    warn "CF-GeoBypasser not installed — skipping Cloudflare bypass"
fi

# ── Consolidate results ──
cat "${OUT_DIR}"/waf/*.json "${OUT_DIR}"/cf_bypass/*.txt 2>/dev/null | \
    grep -v '^$' > "${OUT_DIR}/waf_findings.txt" 2>/dev/null || true

# Set WAF evasion flag for downstream scripts
if [ "$WAF_DETECTED" -gt 0 ]; then
    warn "WAFs detected — downstream scripts will use evasion mode"
    touch "${OUT_DIR}/.waf_evasion"
    export WAF_EVASION=1
else
    export WAF_EVASION=0
fi

log "WAF results: ${OUT_DIR}/waf_findings.txt"
