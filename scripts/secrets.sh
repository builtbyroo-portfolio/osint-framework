#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  secrets.sh — JavaScript Secret & Endpoint Analysis          ║
# ║  SecretFinder + LinkFinder + nuclei + regex grep              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="secrets.sh"
SCRIPT_DESC="Secret & Endpoint Discovery"
MAX_JS="${MAX_JS:-300}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Analyze JS files for secrets, endpoints, API keys."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs (or JS file URLs)"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "SECRETS" "$SCRIPT_DESC"

# Determine JS file list
js_file_list=""
if [ -f "${OUT_DIR}/js_files.txt" ] && [ -s "${OUT_DIR}/js_files.txt" ]; then
    js_file_list="${OUT_DIR}/js_files.txt"
elif [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    grep -iP '\.(js|mjs)(\?|$)' "$URLS_FILE" 2>/dev/null | sort -u > "${OUT_DIR}/js_files.txt"
    js_file_list="${OUT_DIR}/js_files.txt"
fi

js_count=0
[ -n "$js_file_list" ] && [ -f "$js_file_list" ] && js_count=$(count_lines "$js_file_list")

# ── Download JS files (parallel) ──
mkdir -p "${OUT_DIR}/js_downloads"
if [ "$js_count" -gt 0 ]; then
    info "Downloading JS files in parallel (max ${MAX_JS}, ${THREADS} concurrent)..."
    head -"${MAX_JS}" "$js_file_list" | xargs -P "${THREADS}" -I{} bash -c '
        url="$1"; fname=$(echo "$url" | md5sum | cut -c1-8).js
        curl -sk --max-time 10 "$url" -o "'"${OUT_DIR}"'/js_downloads/${fname}" 2>/dev/null || true
    ' _ {} 2>/dev/null || true
    dl_count=$(ls "${OUT_DIR}/js_downloads/"*.js 2>/dev/null | wc -l || echo 0)
    log "Downloaded ${dl_count} JS files"
fi

# ── SecretFinder ──
if check_tool secretfinder 2>/dev/null && [ "$js_count" -gt 0 ]; then
    info "Running SecretFinder on JS URLs..."
    head -"${MAX_JS}" "$js_file_list" | while read -r url; do
        [ -z "$url" ] && continue
        secretfinder -i "$url" -o cli 2>/dev/null || true
    done | grep -v '^Usage:\|^Error:' | sort -u > "${OUT_DIR}/secretfinder_results.txt" 2>/dev/null || true
    log "SecretFinder: $(count_lines "${OUT_DIR}/secretfinder_results.txt") results"
fi

# ── LinkFinder ──
if check_tool linkfinder 2>/dev/null && [ "$js_count" -gt 0 ]; then
    info "Running LinkFinder on JS URLs..."
    head -"${MAX_JS}" "$js_file_list" | while read -r url; do
        [ -z "$url" ] && continue
        python3 /usr/share/linkfinder/linkfinder.py -i "$url" -o cli 2>/dev/null || true
    done | sort -u > "${OUT_DIR}/linkfinder_endpoints.txt" 2>/dev/null || true
    log "LinkFinder endpoints: $(count_lines "${OUT_DIR}/linkfinder_endpoints.txt")"
fi

# ── Cariddi (crawl + secret scan) ──
if check_tool cariddi 2>/dev/null; then
    urls_input="${URLS_FILE:-${OUT_DIR}/urls.txt}"
    if [ -f "$urls_input" ]; then
        info "Running cariddi (crawl + secrets + endpoints)..."
        head -20 "$urls_input" | cariddi -s -e -plain \
            2>/dev/null > "${OUT_DIR}/cariddi_results.txt" || true
        log "Cariddi: $(count_lines "${OUT_DIR}/cariddi_results.txt") results"
    fi
fi

# ── Nuclei token/config scan ──
if [ "$js_count" -gt 0 ]; then
    info "Nuclei token/config scan on JS URLs..."
    nuclei -l "$js_file_list" \
        -t "${NUCLEI_TEMPLATES}/http/exposures/tokens/" \
        -t "${NUCLEI_TEMPLATES}/http/exposures/configs/" \
        -c "${THREADS}" -silent \
        -o "${OUT_DIR}/nuclei_js_secrets.txt" 2>/dev/null || true
    log "Nuclei JS secrets: $(count_lines "${OUT_DIR}/nuclei_js_secrets.txt")"
fi

# ── Regex grep for secrets ──
if [ -d "${OUT_DIR}/js_downloads" ] && [ "$(ls -A "${OUT_DIR}/js_downloads" 2>/dev/null)" ]; then
    info "Grepping for hardcoded secrets..."
    grep -rPi '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password\s*[:=]|aws_access|AKIA[0-9A-Z]{16}|sk_live_|pk_live_|AIzaSy|ghp_|gho_|glpat-|xox[bpras]-|slack[_-]?token|firebase|mongodb(\+srv)?://|postgres://|mysql://)' \
        "${OUT_DIR}/js_downloads/" 2>/dev/null | \
        grep -v 'node_modules\|\.min\.js.*example' | sort -u > "${OUT_DIR}/js_secrets_grep.txt" || true
    log "Hardcoded secrets: $(count_lines "${OUT_DIR}/js_secrets_grep.txt")"
fi

# ── Gitleaks (scan downloaded JS for leaked secrets) ──
if check_tool gitleaks 2>/dev/null && [ -d "${OUT_DIR}/js_downloads" ]; then
    info "Running gitleaks on downloaded JS files..."
    gitleaks detect --source "${OUT_DIR}/js_downloads" --no-git \
        --report-path "${OUT_DIR}/gitleaks_results.json" \
        --report-format json 2>/dev/null || true
    if [ -s "${OUT_DIR}/gitleaks_results.json" ]; then
        python3 -c "
import json
try:
    data = json.load(open('${OUT_DIR}/gitleaks_results.json'))
    for r in data:
        desc = r.get('Description','')
        match = r.get('Match','')[:80]
        f = r.get('File','')
        print(f'GITLEAKS: {desc} | {match} | {f}')
except: pass
" > "${OUT_DIR}/gitleaks_findings.txt" 2>/dev/null || true
        log "Gitleaks: $(count_lines "${OUT_DIR}/gitleaks_findings.txt") findings"
    fi
fi

# ── Consolidate ──
cat "${OUT_DIR}"/secretfinder_results.txt "${OUT_DIR}"/js_secrets_grep.txt \
    "${OUT_DIR}"/nuclei_js_secrets.txt "${OUT_DIR}"/gitleaks_findings.txt \
    2>/dev/null | sort -u > "${OUT_DIR}/secrets_raw.txt"

# ── Filter noise (public-by-design keys, analytics, known false positives) ──
if [ -s "${OUT_DIR}/secrets_raw.txt" ]; then
    info "Filtering known false positives from secrets..."
    grep -viP '(amplitude|readme\.io|segment\.io|bugsnag|datadog-rum|logrocket|fullstory|hotjar|google-analytics|googletagmanager|gtag|fbq|_fbp|intercom|zendesk|statuspage|sentry.*public|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare)' \
        "${OUT_DIR}/secrets_raw.txt" 2>/dev/null > "${OUT_DIR}/secrets_findings.txt" || true
    raw_count=$(count_lines "${OUT_DIR}/secrets_raw.txt")
    filtered_count=$(count_lines "${OUT_DIR}/secrets_findings.txt")
    filtered_out=$((raw_count - filtered_count))
    if [ "$filtered_out" -gt 0 ]; then
        log "Filtered ${filtered_out} known false positives (analytics/public keys)"
    fi
else
    > "${OUT_DIR}/secrets_findings.txt"
fi

log "Total secret findings: $(count_lines "${OUT_DIR}/secrets_findings.txt")"
log "Secrets results: ${OUT_DIR}/secrets_findings.txt"
