#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  proto_polluter.sh — Prototype Pollution Scanner              ║
# ║  Detect server-side prototype pollution in JSON APIs          ║
# ║  VRT: Server-Side Injection (P2)                              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="proto_polluter.sh"
SCRIPT_DESC="Prototype Pollution Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Find JSON-accepting endpoints and test for server-side"
    echo "  prototype pollution via __proto__ and constructor injection."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --dry-run              Show targets without injecting"
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

phase_header "PROTO" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/proto_findings.txt"
targets_file="${OUT_DIR}/proto_targets.txt"
> "$findings_file"
> "$targets_file"

# ── Find JSON-accepting endpoints ──
info "Identifying JSON-accepting endpoints..."

urls_input="${URLS_FILE:-${OUT_DIR}/all_urls.txt}"

# 1. Grep for API/JSON endpoints from URL lists
API_PATTERNS='/(api|v[0-9]+|rest|graphql|json|data|endpoint|service|webhook|callback)/'
if [ -f "$urls_input" ]; then
    grep -iP "$API_PATTERNS" "$urls_input" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/urls.txt" ]; then
    grep -iP "$API_PATTERNS" "${OUT_DIR}/urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# 2. Extract from parameterized URLs (endpoints that accept data)
if [ -f "${OUT_DIR}/parameterized_urls.txt" ]; then
    grep -iP '(json|data|body|payload|config|settings|update|create|submit)' \
        "${OUT_DIR}/parameterized_urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# 3. Look for endpoints that returned JSON in responses
if [ -f "${OUT_DIR}/urls.txt" ]; then
    # URLs from httpx with content-type json
    grep -i 'application/json' "${OUT_DIR}/urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# ── Scan JS files for vulnerable patterns ──
js_vulnerable_patterns="${OUT_DIR}/proto_vulnerable_js.txt"
> "$js_vulnerable_patterns"

info "Scanning JS files for prototype pollution sinks..."
js_dir="${OUT_DIR}/js_downloads"
if [ -d "$js_dir" ] && [ "$(ls -A "$js_dir" 2>/dev/null)" ]; then
    for jsfile in "$js_dir"/*; do
        [ -f "$jsfile" ] || continue
        if grep -qiP '(lodash\.merge|_\.merge|Object\.assign|jQuery\.extend|\$\.extend|deepmerge|_.defaultsDeep|_.set|flat\()' "$jsfile" 2>/dev/null; then
            local_patterns=$(grep -ciP '(lodash\.merge|_\.merge|Object\.assign|jQuery\.extend|\$\.extend|deepmerge|_.defaultsDeep|_.set|flat\()' "$jsfile" 2>/dev/null || echo 0)
            echo "$(basename "$jsfile"): ${local_patterns} vulnerable pattern(s)" >> "$js_vulnerable_patterns"
        fi
    done
    vuln_js_count=$(count_lines "$js_vulnerable_patterns")
    if [ "$vuln_js_count" -gt 0 ]; then
        warn "Found ${vuln_js_count} JS file(s) with prototype pollution sinks"
        cat "$js_vulnerable_patterns"
    fi
else
    info "No JS downloads directory — skipping sink analysis"
fi

# Deduplicate targets
if [ -s "$targets_file" ]; then
    sort -u "$targets_file" -o "$targets_file"
fi

total=$(count_lines "$targets_file")
log "Identified ${total} JSON-accepting endpoint(s)"

if [ "$total" -eq 0 ]; then
    warn "No JSON endpoints found — skipping prototype pollution testing"
    exit 0
fi

if $DRY_RUN; then
    info "[DRY-RUN] Targets to test:"
    cat "$targets_file"
    if [ -s "$js_vulnerable_patterns" ]; then
        info "[DRY-RUN] Vulnerable JS patterns:"
        cat "$js_vulnerable_patterns"
    fi
    exit 0
fi

# ── Run Python analyzer ──
ANALYZER="${LIB_DIR}/scripts/proto_polluter.py"
if [ ! -f "$ANALYZER" ]; then
    err "proto_polluter.py not found at ${ANALYZER}"
    exit 1
fi

info "Running prototype pollution tests on ${total} endpoint(s)..."
python3 "$ANALYZER" \
    -i "$targets_file" \
    -o "$findings_file" \
    -t "$THREADS" \
    || { err "proto_polluter.py failed"; exit 1; }

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Prototype pollution scan complete: ${total} endpoints tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Prototype pollution findings detected:"
    cat "$findings_file"
fi
