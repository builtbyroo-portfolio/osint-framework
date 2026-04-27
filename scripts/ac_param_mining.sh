#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_param_mining.sh — Hidden Parameter Discovery             ║
# ║  Arjun + ffuf GET fuzzing + header parameter testing         ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_param_mining.sh"
SCRIPT_DESC="Hidden Parameter Discovery"
MAX_ENDPOINTS=30

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover hidden GET parameters and header-based parameters on interesting"
    echo "  endpoints. Uses arjun, ffuf GET param fuzzing, and header injection testing."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "8" "$SCRIPT_DESC"

# ── Locate endpoint list ──────────────────────────────────────
ENDPOINTS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    ENDPOINTS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_interesting_endpoints.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ac_interesting_endpoints.txt"
else
    err "No endpoints file found. Provide -u/--urls or ensure ac_interesting_endpoints.txt exists in OUT_DIR"
    script_usage
    exit 1
fi

if [ ! -s "$ENDPOINTS_FILE" ]; then
    warn "Endpoints file is empty: ${ENDPOINTS_FILE}"
    log "Phase 8 complete — no endpoints to test"
    exit 0
fi

total_endpoints=$(count_lines "$ENDPOINTS_FILE")
info "Source: ${ENDPOINTS_FILE} (${total_endpoints} endpoints)"

# Cap endpoints
CAPPED_FILE="${OUT_DIR}/_param_mining_endpoints.txt"
head -n "$MAX_ENDPOINTS" "$ENDPOINTS_FILE" > "$CAPPED_FILE"
endpoint_count=$(count_lines "$CAPPED_FILE")
if [ "$total_endpoints" -gt "$MAX_ENDPOINTS" ]; then
    warn "Capped to ${MAX_ENDPOINTS} endpoints (had ${total_endpoints})"
fi

# ── Output setup ──────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ac_param_findings.txt"
> "$FINDINGS_FILE"
mkdir -p "${OUT_DIR}/arjun" "${OUT_DIR}/ffuf_params"

PARAM_WORDLIST="${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt"

# ── Helper: get baseline response size ────────────────────────
get_baseline_size() {
    local url="$1"
    local size
    size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 10 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "0")
    echo "$size"
}

# ── Helper: extract host from URL ─────────────────────────────
url_to_host() {
    echo "$1" | sed 's|https\?://||;s|/.*||;s|:.*||'
}

# ── Helper: sanitize filename from URL ────────────────────────
url_to_filename() {
    echo "$1" | sed 's|https\?://||;s|[/:?&=]|_|g' | cut -c1-120
}

found_count=0

# ══════════════════════════════════════════════════════════════
#  METHOD 1: Arjun — automated parameter discovery
# ══════════════════════════════════════════════════════════════
if check_tool arjun 2>/dev/null; then
    info "Method 1: arjun parameter discovery (top 15 endpoints)"

    arjun_idx=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        ((arjun_idx++)) || true
        [ "$arjun_idx" -gt 15 ] && break

        host=$(url_to_host "$url")
        fname=$(url_to_filename "$url")
        arjun_out="${OUT_DIR}/arjun/${fname}_params.json"

        info "  [${arjun_idx}/15] arjun: ${url}"
        timeout 120 arjun -u "$url" -oJ "$arjun_out" -t "$THREADS" --stable 2>/dev/null || true

        # Parse arjun JSON output
        if [ -s "$arjun_out" ]; then
            python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    # arjun output: {url: {method: [params]}} or {url: [params]}
    for target_url, methods in data.items():
        if isinstance(methods, dict):
            for method, params in methods.items():
                for p in params:
                    print(f'{target_url}|{p}|{method.upper()}|arjun')
        elif isinstance(methods, list):
            for p in methods:
                print(f'{target_url}|{p}|GET|arjun')
except Exception:
    pass
" "$arjun_out" 2>/dev/null | while IFS='|' read -r ep param method source; do
                log "  FOUND: [${ep}] ${param} [method: ${method}] [source: ${source}]"
                echo "[${ep}] ${param} [method: ${method}] [source: arjun]" >> "$FINDINGS_FILE"
                ((found_count++)) || true
            done
        fi
    done < "$CAPPED_FILE"
else
    warn "Method 1: arjun not installed — skipping (install: sudo pacman -S arjun)"
fi

# ══════════════════════════════════════════════════════════════
#  METHOD 2: ffuf GET parameter fuzzing
# ══════════════════════════════════════════════════════════════
if check_tool ffuf 2>/dev/null; then
    if [ -f "$PARAM_WORDLIST" ]; then
        wl_lines=$(wc -l < "$PARAM_WORDLIST" | tr -d ' ')
        info "Method 2: ffuf GET param fuzzing (${wl_lines} params, ${endpoint_count} endpoints)"

        ffuf_idx=0
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            ((ffuf_idx++)) || true

            fname=$(url_to_filename "$url")
            ffuf_out="${OUT_DIR}/ffuf_params/${fname}_params.json"

            # Get baseline response size for filtering
            baseline=$(get_baseline_size "$url")
            info "  [${ffuf_idx}/${endpoint_count}] ffuf: ${url} (baseline: ${baseline}B)"

            # Skip if baseline is 0 (unreachable)
            if [ "$baseline" -eq 0 ] 2>/dev/null; then
                warn "    Unreachable — skipping"
                continue
            fi

            # Run ffuf with size filter to exclude responses matching baseline
            ffuf -u "${url}?FUZZ=test" -w "$PARAM_WORDLIST" \
                "${HUNT_UA_ARGS[@]}" \
                -fs "$baseline" \
                -mc 200,201,301,302,400,401,403,405,500 -fc 404 \
                -t "$THREADS" -o "$ffuf_out" -of json \
                -timeout 10 2>/dev/null || true

            # Parse ffuf JSON results
            if [ -s "$ffuf_out" ]; then
                python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    base_url = sys.argv[2]
    baseline = int(sys.argv[3])
    for r in data.get('results', []):
        param = r.get('input', {}).get('FUZZ', '')
        status = r.get('status', 0)
        length = r.get('length', 0)
        diff = length - baseline
        sign = '+' if diff >= 0 else ''
        print(f'{base_url}|{param}=test|GET|{sign}{diff}')
except Exception:
    pass
" "$ffuf_out" "$url" "$baseline" 2>/dev/null | while IFS='|' read -r ep param method size_diff; do
                    log "  FOUND: [${ep}] ${param} [method: ${method}] [size_diff: ${size_diff}]"
                    echo "[${ep}] ${param} [method: ${method}] [size_diff: ${size_diff}]" >> "$FINDINGS_FILE"
                    ((found_count++)) || true
                done
            fi
        done < "$CAPPED_FILE"
    else
        warn "Method 2: wordlist not found: ${PARAM_WORDLIST}"
    fi
else
    warn "Method 2: ffuf not installed — skipping (install: sudo pacman -S ffuf)"
fi

# ══════════════════════════════════════════════════════════════
#  METHOD 3: Header parameter testing
# ══════════════════════════════════════════════════════════════
info "Method 3: Header parameter testing (top 15 endpoints)"

# Headers to test — name:value pairs
declare -a TEST_HEADERS=(
    "X-Forwarded-For:127.0.0.1"
    "X-Api-Key:test"
    "X-Debug:true"
    "X-Debug-Mode:1"
    "Authorization:Bearer test"
    "X-Token:test"
    "X-Custom-Header:test"
    "Debug:1"
)

DIFF_THRESHOLD=20  # percentage change to flag as interesting

header_idx=0
while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((header_idx++)) || true
    [ "$header_idx" -gt 15 ] && break

    # Get baseline response size
    baseline=$(get_baseline_size "$url")
    if [ "$baseline" -eq 0 ] 2>/dev/null; then
        warn "  [${header_idx}/15] Unreachable: ${url} — skipping"
        continue
    fi

    info "  [${header_idx}/15] headers: ${url} (baseline: ${baseline}B)"

    for header_pair in "${TEST_HEADERS[@]}"; do
        header_name="${header_pair%%:*}"
        header_value="${header_pair#*:}"

        # Send request with injected header
        resp_size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 10 \
            "${HUNT_UA_CURL[@]}" \
            -H "${header_name}: ${header_value}" \
            "$url" 2>/dev/null || echo "0")

        # Calculate percentage difference
        if [ "$baseline" -gt 0 ] && [ "$resp_size" -gt 0 ] 2>/dev/null; then
            # Use python3 for reliable float math
            is_significant=$(python3 -c "
baseline = $baseline
resp = $resp_size
threshold = $DIFF_THRESHOLD
diff = abs(resp - baseline)
pct = (diff / baseline) * 100 if baseline > 0 else 0
if pct >= threshold:
    sign = '+' if resp > baseline else '-'
    print(f'YES|{sign}{diff}|{pct:.1f}%')
else:
    print('NO')
" 2>/dev/null || echo "NO")

            if [[ "$is_significant" == YES* ]]; then
                size_diff=$(echo "$is_significant" | cut -d'|' -f2)
                pct_diff=$(echo "$is_significant" | cut -d'|' -f3)
                log "  FOUND: [${url}] ${header_name}=${header_value} [method: HEADER] [size_diff: ${size_diff} (${pct_diff})]"
                echo "[${url}] ${header_name}=${header_value} [method: HEADER] [size_diff: ${size_diff} (${pct_diff})]" >> "$FINDINGS_FILE"
                ((found_count++)) || true
            fi
        fi
    done
done < "$CAPPED_FILE"

# ── Cleanup temp files ────────────────────────────────────────
rm -f "$CAPPED_FILE"

# ── Dedup findings ────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
fi

# ── Summary ───────────────────────────────────────────────────
final_count=$(count_lines "$FINDINGS_FILE")
log "Phase 8 complete — ${final_count} hidden parameters discovered"
log "Findings: ${FINDINGS_FILE}"
if [ "$final_count" -gt 0 ]; then
    info "Top findings:"
    head -20 "$FINDINGS_FILE" | while IFS= read -r line; do
        echo "  ${line}"
    done
fi
