#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  quick_sweep.sh — Fast Multi-Vuln Sweep (TerminatorZ)       ║
# ║  24+ vulnerability types in one pass                         ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="quick_sweep.sh"
SCRIPT_DESC="Quick Vulnerability Sweep (TerminatorZ)"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Fast 24+ vulnerability type sweep using TerminatorZ."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with URLs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "SWEEP" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

> "${OUT_DIR}/sweep_findings.txt"

# ── TerminatorZ (BHEH) ──
if check_bheh "TerminatorZ/TerminatorZ.sh"; then
    info "Running TerminatorZ (24+ vuln type sweep)..."

    if [ -n "${DOMAIN:-}" ]; then
        # TerminatorZ is interactive — pipe domain
        echo "$DOMAIN" | bash "${BHEH_DIR}/TerminatorZ/TerminatorZ.sh" \
            > "${OUT_DIR}/terminatorz_raw.txt" 2>/dev/null || true
    elif [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
        # Run per domain extracted from URLs
        sed 's|https\?://||;s|/.*||' "$URLS_FILE" | sort -u | head -5 | while IFS= read -r domain; do
            echo "$domain" | bash "${BHEH_DIR}/TerminatorZ/TerminatorZ.sh" \
                >> "${OUT_DIR}/terminatorz_raw.txt" 2>/dev/null || true
        done
    fi

    if [ -s "${OUT_DIR}/terminatorz_raw.txt" ]; then
        # Extract findings (TerminatorZ outputs colorized text — strip ANSI)
        sed 's/\x1b\[[0-9;]*m//g' "${OUT_DIR}/terminatorz_raw.txt" | \
            grep -iP '(vuln|found|inject|xss|sqli|ssrf|redirect|lfi|rfi|rce|idor|open|exposed|leak)' \
            > "${OUT_DIR}/sweep_findings.txt" 2>/dev/null || true
        log "TerminatorZ: $(count_lines "${OUT_DIR}/sweep_findings.txt") potential findings"
    else
        warn "TerminatorZ produced no output"
    fi
else
    warn "TerminatorZ not installed — falling back to basic checks"

    # Basic sweep fallback using available tools
    target="${DOMAIN:-}"
    if [ -z "$target" ] && [ -f "${URLS_FILE:-}" ]; then
        target=$(head -1 "$URLS_FILE" | sed 's|https\?://||;s|/.*||')
    fi

    if [ -n "$target" ] && check_tool waybackurls 2>/dev/null; then
        info "Running waybackurls fallback sweep..."
        echo "$target" | waybackurls 2>/dev/null | sort -u | head -500 | while IFS= read -r url; do
            status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
            if [[ "$status" =~ ^(200|301|302|403|500)$ ]]; then
                echo "${status} ${url}" >> "${OUT_DIR}/sweep_findings.txt"
            fi
        done
        log "Basic sweep: $(count_lines "${OUT_DIR}/sweep_findings.txt") responsive URLs"
    fi
fi

log "Sweep results: ${OUT_DIR}/sweep_findings.txt"
