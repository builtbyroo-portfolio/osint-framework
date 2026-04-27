#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  deserial_scan.sh — Deserialization Vulnerability Scanner    ║
# ║  Detect Java/PHP/.NET/Python serialized objects in traffic   ║
# ║  VRT: Server-Side Injection > Deserialization (P1)           ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="deserial_scan.sh"
SCRIPT_DESC="Deserialization Vulnerability Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Scan responses, cookies, and parameters for serialized objects"
    echo "  (Java, .NET, PHP, Python pickle). Pre-filter with marker grep,"
    echo "  then deep-scan with deserial_scan.py using DNS callbacks."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "DESERIAL" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/deserial_findings.txt"
targets_file="${OUT_DIR}/deserial_targets.txt"
marker_hits="${OUT_DIR}/deserial_marker_hits.txt"
> "$findings_file"
> "$targets_file"
> "$marker_hits"

# ── Determine input ──
urls_input="${URLS_FILE:-${OUT_DIR}/urls.txt}"

if [ ! -f "$urls_input" ]; then
    err "Provide --urls or ensure ${OUT_DIR}/urls.txt exists"
    script_usage
    exit 1
fi

total_urls=$(count_lines "$urls_input")
info "Pass 1: Scanning ${total_urls} URLs for serialization markers..."

# ── Pass 1: curl each URL and grep for serialization markers ──
while IFS= read -r url; do
    [ -z "$url" ] && continue
    [[ "$url" != http* ]] && continue

    resp=$(curl -sk --max-time 8 -D- "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null) || continue

    hit=false

    # Java serialization: rO0AB (base64), aced0005 (hex), H4sIAAAA (gzip+base64)
    if echo "$resp" | grep -qP '(rO0AB|aced0005|H4sIAAAA)'; then
        echo "JAVA_SERIAL $url" >> "$marker_hits"
        hit=true
    fi

    # .NET serialization: AAEAAAD (BinaryFormatter), __VIEWSTATE, __EVENTVALIDATION
    if echo "$resp" | grep -qP '(AAEAAAD|__VIEWSTATE|__EVENTVALIDATION)'; then
        echo "DOTNET_SERIAL $url" >> "$marker_hits"
        hit=true
    fi

    # PHP serialization: O:<len>:"class", a:<len>:{, s:<len>:"
    if echo "$resp" | grep -qP 'O:\d+:"|a:\d+:\{|s:\d+:"'; then
        echo "PHP_SERIAL $url" >> "$marker_hits"
        hit=true
    fi

    # Python pickle: base64 that decodes to pickle protocol bytes (\x80\x03-\x05)
    echo "$resp" | grep -oP '[A-Za-z0-9+/]{20,}={0,2}' | head -10 | while IFS= read -r b64; do
        decoded=$(echo "$b64" | base64 -d 2>/dev/null | xxd -p -l 2 2>/dev/null)
        if [[ "$decoded" =~ ^(8003|8004|8005)$ ]]; then
            echo "PICKLE_SERIAL $url" >> "$marker_hits"
            echo "$url" >> "$targets_file"
            break
        fi
    done

    if $hit; then
        echo "$url" >> "$targets_file"
    fi
done < "$urls_input"

marker_count=$(count_lines "$marker_hits")
log "Pass 1 complete: ${marker_count} serialization marker(s) found"

# ── Pass 2: add URLs with deserialization-prone parameters ──
info "Pass 2: Collecting URLs with deserialization-prone parameters..."
DESER_PARAMS='[?&](data|token|session|object|payload|viewstate|__VIEWSTATE|__EVENTVALIDATION|state|serialized|obj|pickle|b64|encoded)='

if [ -f "$urls_input" ]; then
    grep -iP "$DESER_PARAMS" "$urls_input" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/parameterized_urls.txt" ]; then
    grep -iP "$DESER_PARAMS" "${OUT_DIR}/parameterized_urls.txt" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/all_urls.txt" ]; then
    grep -iP "$DESER_PARAMS" "${OUT_DIR}/all_urls.txt" >> "$targets_file" 2>/dev/null || true
    # Also add .NET pages (aspx, ashx, asmx)
    grep -iP '\.(aspx?|ashx|asmx)' "${OUT_DIR}/all_urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# Deduplicate
if [ -s "$targets_file" ]; then
    sort -u "$targets_file" -o "$targets_file"
fi

target_count=$(count_lines "$targets_file")
log "Total targets for deep scan: ${target_count}"

if [ "$target_count" -eq 0 ]; then
    warn "No serialization indicators or prone parameters found — skipping deep scan"
    exit 0
fi

# ── Interactsh callback setup ──
CALLBACK_ARGS=()
INTERACT_PID=""
INTERACT_LOG="${OUT_DIR}/interactsh_deserial.log"

if check_tool interactsh-client 2>/dev/null; then
    info "Starting interactsh for OOB deserialization callbacks..."
    interactsh-client -json -o "$INTERACT_LOG" &
    INTERACT_PID=$!
    sleep 3

    INTERACT_URL=$(grep -oP '[a-z0-9]+\.[a-z0-9]+\.interactsh\.(com|sh)' "$INTERACT_LOG" 2>/dev/null | head -1)
    if [ -n "$INTERACT_URL" ]; then
        info "Callback domain: ${INTERACT_URL}"
        CALLBACK_ARGS=(--callback-domain "$INTERACT_URL")
    else
        warn "Could not extract interactsh domain — running detection-only mode"
        kill $INTERACT_PID 2>/dev/null || true
        INTERACT_PID=""
    fi
else
    info "interactsh-client not available — running detection-only mode"
fi

# ── Build python args ──
py_args=(
    -i "$targets_file"
    -o "$findings_file"
    -t "${THREADS}"
    --timeout 10
    "${CALLBACK_ARGS[@]}"
)

if [ -n "${HUNT_UA:-}" ]; then
    py_args+=(--user-agent "${HUNT_UA}")
fi

# ── Run Python scanner ──
SCANNER="${LIB_DIR}/scripts/deserial_scan.py"
if [ ! -f "$SCANNER" ]; then
    err "deserial_scan.py not found at ${SCANNER}"
    exit 1
fi

info "Running deserialization deep scan on ${target_count} target(s)..."
python3 "$SCANNER" "${py_args[@]}" || { err "deserial_scan.py failed"; }

# ── Cleanup interactsh ──
if [ -n "$INTERACT_PID" ]; then
    info "Waiting for OOB callbacks..."
    sleep 5
    kill $INTERACT_PID 2>/dev/null || true
    wait $INTERACT_PID 2>/dev/null || true

    # Check for callbacks
    if [ -f "$INTERACT_LOG" ]; then
        oob_hits=$(grep -c '"protocol"' "$INTERACT_LOG" 2>/dev/null || echo 0)
        if [ "$oob_hits" -gt 0 ]; then
            warn "OOB deserialization callbacks received: ${oob_hits}"
            grep '"protocol"' "$INTERACT_LOG" >> "$findings_file" 2>/dev/null || true
        fi
    fi
fi

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Deserialization scan complete: ${target_count} targets tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Deserialization findings detected:"
    cat "$findings_file"
    log "Results: ${OUT_DIR}/deserial_findings.txt"
fi
