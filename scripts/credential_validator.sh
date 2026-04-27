#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  credential_validator.sh — Validate Extracted Credentials    ║
# ║  Tests API keys, tokens, secrets for actual exploitability   ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="credential_validator.sh"
SCRIPT_DESC="Credential Validation"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Validates extracted credentials against live APIs."
    echo "  Converts P5 'key found in code' → P2+ 'key exploited'."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs (used to find hunt dir)"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 10)"
    echo "  --dry-run              Extract only, don't validate"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "CRED_VALIDATE" "$SCRIPT_DESC"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DRY_RUN=""
for arg in "$@"; do
    [ "$arg" = "--dry-run" ] && DRY_RUN="--dry-run"
done

# ── Find credential sources ──
cred_sources=()

# Priority: hunt output directory (has all extracted secrets)
if [ -d "${OUT_DIR}" ]; then
    for sf in secretfinder_results.txt nuclei_js_secrets.txt cariddi_results.txt grep_secrets.txt; do
        [ -f "${OUT_DIR}/${sf}" ] && [ -s "${OUT_DIR}/${sf}" ] && cred_sources+=("${OUT_DIR}/${sf}")
    done
fi

# Also scan JS downloads if available
js_dir="${OUT_DIR}/js_downloads"
[ -d "$js_dir" ] && js_count=$(ls "$js_dir"/*.js 2>/dev/null | wc -l || echo 0) || js_count=0

if [ ${#cred_sources[@]} -eq 0 ] && [ "$js_count" -eq 0 ]; then
    warn "No credential sources found in ${OUT_DIR}"
    warn "Expected files: secretfinder_results.txt, nuclei_js_secrets.txt, etc."
    warn "Run the secrets phase first, or point --out to a completed hunt directory"
    exit 0
fi

info "Found ${#cred_sources[@]} credential files + ${js_count} JS files"

# ── Run credential validator ──
findings_file="${OUT_DIR}/validated_credentials.txt"

info "Running credential validator..."
python3 "${SCRIPT_DIR}/credential_validator.py" \
    --scan-dir "${OUT_DIR}" \
    -o "${findings_file}" \
    -t "${THREADS:-10}" \
    ${DRY_RUN} 2>&1 | while read -r line; do
        # Pass through stderr output with our logging format
        echo "$line" | grep -qE '^\[' && log "$line" || echo "$line"
    done

# ── Process findings ──
if [ -f "$findings_file" ] && [ -s "$findings_file" ]; then
    total=$(wc -l < "$findings_file")
    valid=$(grep -c "VALID" "$findings_file" 2>/dev/null || echo 0)
    p1=$(grep -c "P1:" "$findings_file" 2>/dev/null || echo 0)
    p2=$(grep -c "P2:" "$findings_file" 2>/dev/null || echo 0)

    if [ "$valid" -gt 0 ]; then
        success "Found ${valid} VALID credentials (${p1} P1, ${p2} P2)"
        echo ""
        echo "══ VALID CREDENTIALS ══"
        grep "VALID" "$findings_file"
        echo "═══════════════════════"
    else
        info "No valid credentials found (${total} total findings)"
    fi

    # Write to main findings file
    if [ -f "${OUT_DIR}/all_findings.txt" ]; then
        grep -E "P[1-3]:" "$findings_file" >> "${OUT_DIR}/all_findings.txt" 2>/dev/null || true
    fi
else
    info "No findings generated"
fi

phase_footer "CRED_VALIDATE"
