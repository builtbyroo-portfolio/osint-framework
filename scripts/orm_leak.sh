#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  orm_leak.sh — ORM Injection / Leak Scanner                  ║
# ║  Detect ORM filter injection across Django, Rails, Prisma,   ║
# ║  Sequelize via differential analysis + relation traversal    ║
# ║  VRT: Server-Side Injection > ORM Injection (P1-P3)         ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="orm_leak.sh"
SCRIPT_DESC="ORM Injection / Leak Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test API endpoints for ORM injection via framework-specific"
    echo "  filter operators (Django, Rails Ransack, Prisma, Sequelize)."
    echo "  Detects data leaks via differential response analysis and"
    echo "  char-by-char extraction probes."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 10)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "ORM_LEAK" "$SCRIPT_DESC"

# ── Determine input ──
urls_input="${URLS_FILE:-${OUT_DIR}/all_urls.txt}"

if [ ! -f "$urls_input" ]; then
    err "Provide --urls or ensure ${OUT_DIR}/all_urls.txt exists"
    script_usage
    exit 1
fi

# ── Filter to API-like URLs ──
API_PATTERN='(/api/|/v[0-9]+/|/graphql|/rest/|/query|/search|/filter|/list|\.json(\?|$))'
PARAM_PATTERN='\?'

info "Filtering URLs to API-like endpoints and parameterized URLs..."

api_urls="${OUT_DIR}/orm_api_urls.txt"
> "$api_urls"

# Grab API-path URLs
grep -iP "$API_PATTERN" "$urls_input" >> "$api_urls" 2>/dev/null || true

# Grab any URL with query parameters
grep -P "$PARAM_PATTERN" "$urls_input" >> "$api_urls" 2>/dev/null || true

# ── Deduplicate by base endpoint (strip param values, keep param names) ──
sort -u "$api_urls" | awk -F'?' '{
    base = $1
    if ($2 != "") {
        n = split($2, pairs, "&")
        for (i = 1; i <= n; i++) {
            split(pairs[i], kv, "=")
            names[i] = kv[1]
        }
        # Sort param names for consistent dedup key
        key = base "?"
        for (i = 1; i <= n; i++) key = key (i>1 ? "&" : "") names[i]
    } else {
        key = base
    }
    if (!seen[key]++) print
}' > "${OUT_DIR}/orm_candidate_urls.txt"

candidate_count=$(count_lines "${OUT_DIR}/orm_candidate_urls.txt")

if [ "$candidate_count" -eq 0 ]; then
    warn "No API-like or parameterized URLs found for ORM testing"
    log "ORM findings: 0"
    exit 0
fi

info "Testing ${candidate_count} candidate URLs for ORM injection..."

# ── Build python args ──
py_args=(
    -i "${OUT_DIR}/orm_candidate_urls.txt"
    -o "${OUT_DIR}/orm_findings.txt"
    -t "${THREADS}"
    --timeout 10
)

if [ -n "${HUNT_UA:-}" ]; then
    py_args+=(--user-agent "${HUNT_UA}")
fi

# ── Run Python scanner ──
python3 "${SCRIPTS_DIR}/orm_leak.py" "${py_args[@]}"

findings_count=$(count_lines "${OUT_DIR}/orm_findings.txt")
log "ORM leak scan complete: ${candidate_count} URLs tested, ${findings_count} finding(s)"

if [ "$findings_count" -gt 0 ]; then
    warn "ORM injection findings detected:"
    cat "${OUT_DIR}/orm_findings.txt"
    log "Results: ${OUT_DIR}/orm_findings.txt"
fi
