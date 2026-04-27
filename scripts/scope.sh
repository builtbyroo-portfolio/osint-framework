#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  scope.sh — Bug Bounty Scope Discovery                      ║
# ║  Find programs from H1/Bugcrowd/Intigriti/YesWeHack         ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="scope.sh"
SCRIPT_DESC="Bug Bounty Scope Discovery"
PLATFORM="${PLATFORM:-all}"
KEYWORD="${KEYWORD:-}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Find bug bounty programs and extract in-scope domains."
    echo ""
    echo "Options:"
    echo "  --platform NAME    Platform: hackerone, bugcrowd, intigriti, yeswehack, all (default: all)"
    echo "  --keyword TERM     Search keyword (e.g., 'fintech', 'payments')"
    echo "  -o, --out DIR      Output directory (default: ./out)"
    echo "  -t, --threads N    Concurrency (default: 30)"
    echo "  -h, --help         Show this help"
}

# Source shared library
LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

info "=== ${SCRIPT_DESC} ==="

# ── ScopeHunter (BHEH) ──
if check_bheh "ScopeHunter/ScopeHunter.sh"; then
    info "Running ScopeHunter..."

    local_args=""
    [ -n "$KEYWORD" ] && local_args="$KEYWORD"

    # ScopeHunter is interactive — pipe inputs
    if [ -n "$KEYWORD" ]; then
        echo "$KEYWORD" | bash "${BHEH_DIR}/ScopeHunter/ScopeHunter.sh" \
            > "${OUT_DIR}/scopehunter_raw.txt" 2>/dev/null || true
    else
        bash "${BHEH_DIR}/ScopeHunter/ScopeHunter.sh" \
            > "${OUT_DIR}/scopehunter_raw.txt" 2>/dev/null || {
            warn "ScopeHunter requires interactive input or a keyword"
        }
    fi

    # Extract domains from output
    if [ -s "${OUT_DIR}/scopehunter_raw.txt" ]; then
        grep -oP '[\w.-]+\.\w{2,}' "${OUT_DIR}/scopehunter_raw.txt" 2>/dev/null | \
            sort -u > "${OUT_DIR}/scope_domains.txt"
        log "ScopeHunter domains: $(count_lines "${OUT_DIR}/scope_domains.txt")"
    fi
else
    warn "ScopeHunter not installed (run bheh_tools/install.sh)"
fi

# ── Manual platform scraping fallback ──
if [ ! -s "${OUT_DIR}/scope_domains.txt" ]; then
    > "${OUT_DIR}/scope_domains.txt"

    if [[ "$PLATFORM" == "all" || "$PLATFORM" == "hackerone" ]]; then
        info "Querying HackerOne directory..."
        curl -sk "https://hackerone.com/directory/programs" \
            -H "Accept: application/json" 2>/dev/null | \
            python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for p in data.get('data', []):
        attrs = p.get('attributes', {})
        name = attrs.get('name', '')
        if '${KEYWORD}'.lower() in name.lower() or not '${KEYWORD}':
            print(name)
except: pass
" >> "${OUT_DIR}/scope_programs.txt" 2>/dev/null || true
    fi
fi

# ── Output summary ──
if [ -s "${OUT_DIR}/scope_domains.txt" ]; then
    log "Scope domains saved: ${OUT_DIR}/scope_domains.txt ($(count_lines "${OUT_DIR}/scope_domains.txt") entries)"
else
    warn "No scope domains found. Try running ScopeHunter interactively or specifying --keyword"
fi

if [ -s "${OUT_DIR}/scope_programs.txt" ]; then
    log "Programs list: ${OUT_DIR}/scope_programs.txt"
fi
