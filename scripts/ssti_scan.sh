#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ssti_scan.sh — Server-Side Template Injection Scanner       ║
# ║  Detect SSTI via polyglot probes + engine fingerprinting     ║
# ║  VRT: Server-Side Injection > Template Injection (P1)        ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ssti_scan.sh"
SCRIPT_DESC="Server-Side Template Injection Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Detect SSTI via reflection checks, polyglot detection,"
    echo "  math-based confirmation, engine fingerprinting, and"
    echo "  safe escalation probes (config reads, not destructive)."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with parameterized URLs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 10)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "SSTI" "$SCRIPT_DESC"

# ── Determine input ──
urls_input="${URLS_FILE:-${OUT_DIR}/parameterized_urls.txt}"

if [ ! -f "$urls_input" ]; then
    err "Provide --urls or ensure ${OUT_DIR}/parameterized_urls.txt exists"
    script_usage
    exit 1
fi

# ── Filter to params likely to reflect in templates ──
SSTI_PARAMS='[?&](name|search|q|template|msg|message|text|title|comment|input|value|query|email|lang|redirect|page|preview|subject|body|content|description|label|greeting|render|view|layout|format|path|file|doc|item|field|display|output|data|html|snippet)='

info "Filtering URLs to SSTI-candidate parameters..."
grep -iP "$SSTI_PARAMS" "$urls_input" | sort -u > "${OUT_DIR}/ssti_candidate_urls.txt" 2>/dev/null || true
candidate_count=$(count_lines "${OUT_DIR}/ssti_candidate_urls.txt")

if [ "$candidate_count" -eq 0 ]; then
    warn "No parameterized URLs matching SSTI-candidate params found"
    log "SSTI findings: 0"
    exit 0
fi

info "Testing ${candidate_count} candidate URLs for SSTI..."

# ── Build python args ──
py_args=(
    -i "${OUT_DIR}/ssti_candidate_urls.txt"
    -o "${OUT_DIR}/ssti_findings.txt"
    -t "${THREADS}"
    --timeout 10
)

if [ -n "${HUNT_UA:-}" ]; then
    py_args+=(--user-agent "${HUNT_UA}")
fi

# ── Run Python scanner ──
python3 "${SCRIPTS_DIR}/ssti_scan.py" "${py_args[@]}"

findings_count=$(count_lines "${OUT_DIR}/ssti_findings.txt")
log "SSTI scan complete: ${candidate_count} URLs tested, ${findings_count} finding(s)"

if [ "$findings_count" -gt 0 ]; then
    warn "SSTI findings detected:"
    cat "${OUT_DIR}/ssti_findings.txt"
    log "Results: ${OUT_DIR}/ssti_findings.txt"
fi
