#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  idor_hunter.sh — IDOR / Broken Access Control Scanner       ║
# ║  Extracts API-like URLs from hunt data, tests for auth bypass ║
# ║  VRT: Broken Access Control (P1)                              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="idor_hunter.sh"
SCRIPT_DESC="IDOR / Broken Access Control Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Extract API-like URLs and test for broken access control:"
    echo "  auth removal, ID manipulation, method switching."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --token-a TOKEN        Auth token for user A (optional)"
    echo "  --token-b TOKEN        Auth token for user B (optional)"
    echo "  --dry-run              Show extracted API endpoints without testing"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"

DRY_RUN=false
TOKEN_A=""
TOKEN_B=""
PASSTHROUGH_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)    DRY_RUN=true; shift ;;
        --token-a)    TOKEN_A="$2"; shift 2 ;;
        --token-b)    TOKEN_B="$2"; shift 2 ;;
        *)            PASSTHROUGH_ARGS+=("$1"); shift ;;
    esac
done
parse_common_args "${PASSTHROUGH_ARGS[@]}"

phase_header "IDOR" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/idor_findings.txt"
api_urls_file="${OUT_DIR}/idor_api_urls.txt"
> "$findings_file"
> "$api_urls_file"

# ── Extract API-like URLs ──
# Patterns: /api/, /v1/, /v2/, /v3/, numeric segments, UUID segments
info "Extracting API-like URLs from hunt data..."

# Source files for API URL extraction
url_sources=(
    "${URLS_FILE:-${OUT_DIR}/all_urls.txt}"
    "${OUT_DIR}/urls.txt"
    "${OUT_DIR}/parameterized_urls.txt"
)

UUID_REGEX='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
NUMERIC_SEGMENT='/[0-9]{1,10}(/|$|\?)'
API_PATH_REGEX='/(api|v[0-9]+|rest|graphql|internal|service)/'

for src in "${url_sources[@]}"; do
    [ -f "$src" ] || continue
    # Match URLs with API paths or numeric/UUID segments
    grep -iP "(${API_PATH_REGEX}|${UUID_REGEX}|${NUMERIC_SEGMENT})" "$src" >> "$api_urls_file" 2>/dev/null || true
done

# Also check gau/katana output
if [ -d "${OUT_DIR}" ]; then
    for gau_file in "${OUT_DIR}"/gau_*.txt "${OUT_DIR}"/katana_*.txt; do
        [ -f "$gau_file" ] || continue
        grep -iP "(${API_PATH_REGEX}|${UUID_REGEX}|${NUMERIC_SEGMENT})" "$gau_file" >> "$api_urls_file" 2>/dev/null || true
    done
fi

# Deduplicate
if [ -s "$api_urls_file" ]; then
    sort -u "$api_urls_file" -o "$api_urls_file"
fi

total=$(count_lines "$api_urls_file")
log "Extracted ${total} API-like URL(s)"

if [ "$total" -eq 0 ]; then
    warn "No API-like URLs found — skipping IDOR testing"
    exit 0
fi

if $DRY_RUN; then
    info "[DRY-RUN] API endpoints to test:"
    cat "$api_urls_file"
    exit 0
fi

# ── Extract JWTs from previous phase if available ──
jwt_file="${OUT_DIR}/extracted_jwts.txt"
if [ -f "$jwt_file" ] && [ -s "$jwt_file" ] && [ -z "$TOKEN_A" ]; then
    TOKEN_A=$(head -1 "$jwt_file")
    info "Using JWT from extraction phase as token-a"
    if [ -z "$TOKEN_B" ] && [ "$(wc -l < "$jwt_file")" -ge 2 ]; then
        TOKEN_B=$(sed -n '2p' "$jwt_file")
        info "Using second JWT as token-b"
    fi
fi

# ── Build Python args ──
ANALYZER="${LIB_DIR}/scripts/idor_hunter.py"
if [ ! -f "$ANALYZER" ]; then
    err "idor_hunter.py not found at ${ANALYZER}"
    exit 1
fi

PYTHON_ARGS=(-i "$api_urls_file" -o "$findings_file" -t "$THREADS")
[ -n "$TOKEN_A" ] && PYTHON_ARGS+=(--token-a "$TOKEN_A")
[ -n "$TOKEN_B" ] && PYTHON_ARGS+=(--token-b "$TOKEN_B")

info "Running IDOR analysis on ${total} endpoint(s)..."
python3 "$ANALYZER" "${PYTHON_ARGS[@]}" \
    || { err "idor_hunter.py failed"; exit 1; }

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "IDOR scan complete: ${total} endpoints tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Broken access control findings detected:"
    cat "$findings_file"
fi
