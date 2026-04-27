#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  unicode_bypass.sh — Unicode Normalization WAF Bypass Scanner ║
# ║  Fullwidth, homoglyph & combining char payloads vs WAFs       ║
# ║  VRT: Server Security Misconfiguration > WAF Bypass (P1-P3)   ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="unicode_bypass.sh"
SCRIPT_DESC="Unicode Normalization WAF Bypass Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test parameterized URLs for WAF bypass via Unicode normalization."
    echo "  Sends standard payloads to confirm WAF blocks, then retries with"
    echo "  fullwidth, homoglyph, and combining-character variants."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with parameterized URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
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

phase_header "UNICODE_BYPASS" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/unicode_bypass_findings.txt"
targets_file="${OUT_DIR}/unicode_bypass_targets.txt"
> "$findings_file"
> "$targets_file"

# ── Collect parameterized URLs ──
info "Identifying parameterized URLs for Unicode WAF bypass testing..."

urls_input="${URLS_FILE:-${OUT_DIR}/parameterized_urls.txt}"

if [ -f "$urls_input" ]; then
    cat "$urls_input" >> "$targets_file" 2>/dev/null || true
fi

if [ -f "${OUT_DIR}/all_urls.txt" ]; then
    grep -P '\?' "${OUT_DIR}/all_urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# Optionally prioritize WAF-identified targets
if [ -f "${OUT_DIR}/waf_results.txt" ]; then
    info "WAF results found — prioritizing WAF-protected targets"
    waf_priority_tmp="${OUT_DIR}/unicode_bypass_waf_priority.txt"
    > "$waf_priority_tmp"
    while IFS= read -r line; do
        domain=$(echo "$line" | grep -oP 'https?://[^/\s]+' || true)
        if [ -n "$domain" ]; then
            grep -F "$domain" "$targets_file" >> "$waf_priority_tmp" 2>/dev/null || true
        fi
    done < "${OUT_DIR}/waf_results.txt"
    if [ -s "$waf_priority_tmp" ]; then
        cat "$waf_priority_tmp" "$targets_file" > "${OUT_DIR}/unicode_bypass_merged.txt"
        mv "${OUT_DIR}/unicode_bypass_merged.txt" "$targets_file"
    fi
    rm -f "$waf_priority_tmp"
fi

# Deduplicate
if [ -s "$targets_file" ]; then
    sort -u "$targets_file" -o "$targets_file"
fi

total=$(count_lines "$targets_file")
log "Identified ${total} parameterized URL(s) to test"

if [ "$total" -eq 0 ]; then
    warn "No parameterized URLs found — skipping Unicode bypass testing"
    exit 0
fi

if $DRY_RUN; then
    info "[DRY-RUN] Targets to test:"
    cat "$targets_file"
    exit 0
fi

# ── Run Python scanner ──
SCANNER="${LIB_DIR}/scripts/unicode_bypass.py"
if [ ! -f "$SCANNER" ]; then
    err "unicode_bypass.py not found at ${SCANNER}"
    exit 1
fi

py_args=(
    -i "$targets_file"
    -o "$findings_file"
    -t "$THREADS"
    --timeout 10
)

if [ -n "${HUNT_UA:-}" ]; then
    py_args+=(--user-agent "${HUNT_UA}")
fi

info "Running Unicode WAF bypass tests on ${total} URL(s)..."
python3 "$SCANNER" "${py_args[@]}" \
    || { err "unicode_bypass.py failed"; exit 1; }

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Unicode bypass scan complete: ${total} URLs tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Unicode WAF bypass findings detected:"
    cat "$findings_file"
fi
