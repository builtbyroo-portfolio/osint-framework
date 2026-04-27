#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  race_condition.sh — Race Condition / TOCTOU Tester           ║
# ║  Fire concurrent identical requests to detect race conditions ║
# ║  VRT: Business Logic Errors (P2)                              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="race_condition.sh"
SCRIPT_DESC="Race Condition / TOCTOU Tester"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Auto-discover race-prone endpoints and fire concurrent"
    echo "  requests to detect TOCTOU / race condition flaws."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrent requests per test (default: 20)"
    echo "  --dry-run              Show targets without testing"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"

DRY_RUN=false
PASSTHROUGH_ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        DRY_RUN=true
    else
        PASSTHROUGH_ARGS+=("$arg")
    fi
done
parse_common_args "${PASSTHROUGH_ARGS[@]}"

phase_header "RACE" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/race_findings.txt"
targets_file="${OUT_DIR}/race_targets.txt"
> "$findings_file"
> "$targets_file"

# ── Race-prone endpoint patterns ──
RACE_PATTERNS=(
    '/redeem'   '/claim'    '/transfer' '/withdraw'
    '/purchase' '/buy'      '/checkout' '/pay'
    '/vote'     '/like'     '/follow'   '/subscribe'
    '/coupon'   '/discount' '/promo'    '/reward'
    '/invite'   '/refer'    '/bonus'    '/credit'
    '/activate' '/register' '/signup'   '/enroll'
    '/confirm'  '/approve'  '/accept'   '/apply'
    '/submit'   '/process'  '/execute'  '/trigger'
    '/send'     '/create'   '/add'      '/insert'
    '/delete'   '/remove'   '/cancel'   '/revoke'
)

# ── Discover race-prone endpoints ──
info "Discovering race-prone endpoints..."

urls_input="${URLS_FILE:-${OUT_DIR}/all_urls.txt}"

# Build grep pattern
race_grep=$(printf "%s\n" "${RACE_PATTERNS[@]}" | tr '\n' '|' | sed 's/|$//')

if [ -f "$urls_input" ]; then
    grep -iP "(${race_grep})" "$urls_input" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/urls.txt" ]; then
    grep -iP "(${race_grep})" "${OUT_DIR}/urls.txt" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/parameterized_urls.txt" ]; then
    grep -iP "(${race_grep})" "${OUT_DIR}/parameterized_urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# Also include API endpoints (race conditions on API create/update)
if [ -f "${OUT_DIR}/idor_api_urls.txt" ]; then
    grep -iP "(${race_grep})" "${OUT_DIR}/idor_api_urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# Deduplicate
if [ -s "$targets_file" ]; then
    sort -u "$targets_file" -o "$targets_file"
fi

total=$(count_lines "$targets_file")
log "Discovered ${total} race-prone endpoint(s)"

if [ "$total" -eq 0 ]; then
    warn "No race-prone endpoints found — skipping race condition testing"
    exit 0
fi

if $DRY_RUN; then
    info "[DRY-RUN] Race-prone targets:"
    cat "$targets_file"
    exit 0
fi

# ── Run Python race tester ──
ANALYZER="${LIB_DIR}/scripts/race_condition.py"
if [ ! -f "$ANALYZER" ]; then
    err "race_condition.py not found at ${ANALYZER}"
    exit 1
fi

info "Running race condition tests on ${total} endpoint(s) (${THREADS} concurrent requests each)..."
python3 "$ANALYZER" \
    -i "$targets_file" \
    -o "$findings_file" \
    -t "$THREADS" \
    || { err "race_condition.py failed"; exit 1; }

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Race condition scan complete: ${total} endpoints tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Race condition findings detected — verify for business impact:"
    cat "$findings_file"
fi
