#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_websocket.sh — WebSocket Testing                         ║
# ║  WS discovery · JS parsing · auth bypass · CSWSH ·           ║
# ║  message injection · websocat probing                        ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_websocket.sh"
SCRIPT_DESC="WebSocket Testing"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover and test WebSocket endpoints. Parses JavaScript files"
    echo "  for ws:// and wss:// URLs, probes common WS paths, tests auth"
    echo "  bypass, CSWSH (Cross-Site WebSocket Hijacking), and message"
    echo "  injection using websocat when available."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "5" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──────────────────────────────────────────────
HAS_WEBSOCAT=false
check_tool websocat 2>/dev/null && HAS_WEBSOCAT=true

if ! check_tool curl 2>/dev/null; then
    err "curl is required"
    exit 1
fi

# ── Output file ──────────────────────────────────────────────
> "${OUT_DIR}/ap_websocket_findings.txt"

# ── Build target list ────────────────────────────────────────
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("$d")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("$DOMAIN")
fi

# ── Counters ─────────────────────────────────────────────────
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

record_finding() {
    local severity="$1" url="$2" test_name="$3" detail="$4"
    echo "[${severity}] ${test_name} | ${url} | ${detail}" >> "${OUT_DIR}/ap_websocket_findings.txt"
    case "$severity" in
        HIGH|CRITICAL) ((HIGH_COUNT++)) || true; warn "[${severity}] ${test_name}: ${url}" ;;
        MEDIUM)        ((MEDIUM_COUNT++)) || true; log "[MEDIUM] ${test_name}: ${url}" ;;
        *)             ((LOW_COUNT++)) || true ;;
    esac
}

# ── Common WebSocket paths ───────────────────────────────────
WS_PATHS=(
    "/ws"
    "/websocket"
    "/socket"
    "/socket.io"
    "/sockjs"
    "/cable"
    "/hub"
    "/signalr"
    "/signalr/negotiate"
    "/realtime"
    "/live"
    "/stream"
    "/events"
    "/feed"
    "/ws/v1"
    "/ws/v2"
    "/api/ws"
    "/api/websocket"
    "/api/stream"
    "/graphql"
    "/subscriptions"
    "/stomp"
    "/mqtt"
    "/wss"
    "/chat"
    "/notifications"
)

# ══════════════════════════════════════════════════════════════
# Stage 1: Discover WS URLs from JavaScript files
# ══════════════════════════════════════════════════════════════
info "Stage 1: Discovering WebSocket URLs from JavaScript files..."

WS_URLS_FILE=$(mktemp)
trap 'rm -f "$WS_URLS_FILE"' EXIT

# Check for JS files from earlier phases
js_sources=()
for f in "${OUT_DIR}"/ac_content_findings.txt "${OUT_DIR}"/katana_*.txt "${OUT_DIR}"/js_files.txt; do
    [ -s "$f" ] && js_sources+=("$f")
done

# Also check URLS_FILE for JS file references
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    js_sources+=("$URLS_FILE")
fi

# Extract JS URLs from available sources
JS_URLS=$(mktemp)
for src in "${js_sources[@]+"${js_sources[@]}"}"; do
    grep -oP 'https?://[^\s]+\.js(\?[^\s]*)?' "$src" 2>/dev/null >> "$JS_URLS" || true
done

# Also fetch and scan inline scripts from target homepages
for host in "${targets[@]}"; do
    info "  Scanning https://${host}/ for inline WebSocket references..."

    page_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        "https://${host}/" 2>/dev/null || echo "")

    if [ -n "$page_body" ]; then
        # Extract ws:// and wss:// URLs from page
        echo "$page_body" | grep -oP '(wss?://[^\s"'\''<>]+)' 2>/dev/null | sort -u >> "$WS_URLS_FILE"

        # Extract JS file URLs from page
        echo "$page_body" | grep -oP 'src=["\x27](https?://[^"\x27]+\.js[^"\x27]*)["\x27]' 2>/dev/null | \
            sed "s/^src=[\"']//" | sed "s/[\"']$//" >> "$JS_URLS"
        echo "$page_body" | grep -oP 'src=["\x27](/[^"\x27]+\.js[^"\x27]*)["\x27]' 2>/dev/null | \
            sed "s/^src=[\"']//" | sed "s/[\"']$//" | \
            while IFS= read -r path; do echo "https://${host}${path}"; done >> "$JS_URLS"
    fi
done

# Scan discovered JS files for WebSocket URLs
sort -u -o "$JS_URLS" "$JS_URLS"
js_count=$(count_lines "$JS_URLS")
info "  Scanning ${js_count} JavaScript file(s) for WebSocket references..."

scanned=0
while IFS= read -r js_url; do
    [ -z "$js_url" ] && continue
    ((scanned++)) || true
    [ "$scanned" -gt 50 ] && break  # Cap JS file scanning

    js_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        "$js_url" 2>/dev/null || echo "")

    if [ -n "$js_body" ]; then
        # Extract ws:// and wss:// URLs
        echo "$js_body" | grep -oP '(wss?://[^\s"'\''<>\)]+)' 2>/dev/null >> "$WS_URLS_FILE"

        # Extract WebSocket path patterns (e.g., new WebSocket('/ws'), connect('/socket'))
        echo "$js_body" | python3 -c "
import sys, re
js = sys.stdin.read()
# Match WebSocket constructor calls
patterns = re.findall(r'new\s+WebSocket\s*\(\s*[\"'\'']((?:wss?://)?[^\"'\'']+)[\"'\'']', js)
# Match common WS library connect calls
patterns += re.findall(r'\.connect\s*\(\s*[\"'\'']((?:wss?://)?/[^\"'\'']+)[\"'\'']', js)
patterns += re.findall(r'socket\.io\s*\(\s*[\"'\'']((?:wss?://)?[^\"'\'']+)[\"'\'']', js)
patterns += re.findall(r'ws_url\s*[:=]\s*[\"'\'']((?:wss?://)?[^\"'\'']+)[\"'\'']', js, re.I)
patterns += re.findall(r'websocket_url\s*[:=]\s*[\"'\'']((?:wss?://)?[^\"'\'']+)[\"'\'']', js, re.I)
for p in set(patterns):
    print(p)
" 2>/dev/null >> "$WS_URLS_FILE" || true
    fi
done < "$JS_URLS"
rm -f "$JS_URLS"

sort -u -o "$WS_URLS_FILE" "$WS_URLS_FILE"
ws_from_js=$(count_lines "$WS_URLS_FILE")
log "  Found ${ws_from_js} WebSocket URL(s) from JavaScript analysis"

# ══════════════════════════════════════════════════════════════
# Stage 2: Probe common WebSocket paths
# ══════════════════════════════════════════════════════════════
info "Stage 2: Probing common WebSocket paths..."

DISCOVERED_WS="${OUT_DIR}/ap_websocket_endpoints.txt"
> "$DISCOVERED_WS"

# Add JS-discovered WS URLs
if [ -s "$WS_URLS_FILE" ]; then
    while IFS= read -r ws_url; do
        [ -z "$ws_url" ] && continue
        echo "$ws_url" >> "$DISCOVERED_WS"
        record_finding "LOW" "$ws_url" "WS URL in JavaScript" \
            "WebSocket URL found in JavaScript source"
    done < "$WS_URLS_FILE"
fi

for host in "${targets[@]}"; do
    info "  Probing: ${host}"

    for wspath in "${WS_PATHS[@]}"; do
        probe_url="https://${host}${wspath}"

        # WebSocket upgrade probe via HTTP
        ws_resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGVzdGtleQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -D- -o /dev/null "$probe_url" 2>/dev/null || echo "")

        ws_status=$(echo "$ws_resp" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")

        # HTTP 101 = WebSocket upgrade successful
        if [ "$ws_status" = "101" ]; then
            echo "wss://${host}${wspath}" >> "$DISCOVERED_WS"
            record_finding "MEDIUM" "wss://${host}${wspath}" "WebSocket Endpoint" \
                "WebSocket upgrade accepted (HTTP 101 Switching Protocols)"
            log "    WebSocket confirmed: wss://${host}${wspath}"
            continue
        fi

        # HTTP 200/400 on common WS paths might indicate a WS endpoint
        if [[ "$ws_status" =~ ^(200|400|426)$ ]]; then
            # 426 = Upgrade Required — definitely a WS endpoint
            if [ "$ws_status" = "426" ]; then
                echo "wss://${host}${wspath}" >> "$DISCOVERED_WS"
                record_finding "LOW" "wss://${host}${wspath}" "WebSocket Endpoint (426)" \
                    "Upgrade Required response indicates WebSocket endpoint"
            elif [ "$ws_status" = "400" ]; then
                # Check if error mentions WebSocket
                if echo "$ws_resp" | grep -qi "websocket\|upgrade\|handshake"; then
                    echo "wss://${host}${wspath}" >> "$DISCOVERED_WS"
                    record_finding "LOW" "wss://${host}${wspath}" "WebSocket Endpoint (Bad Handshake)" \
                        "400 response mentions WebSocket — endpoint exists but handshake failed"
                fi
            fi
        fi

        # Also check socket.io specific endpoint
        if [ "$wspath" = "/socket.io" ]; then
            sio_resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                "https://${host}/socket.io/?EIO=4&transport=polling" 2>/dev/null || echo "")
            if echo "$sio_resp" | grep -qE '^\d+:\d+\{|"sid"'; then
                echo "wss://${host}/socket.io/" >> "$DISCOVERED_WS"
                record_finding "MEDIUM" "wss://${host}/socket.io/" "Socket.IO Endpoint" \
                    "Socket.IO endpoint responds to polling transport"
            fi
        fi
    done
done

sort -u -o "$DISCOVERED_WS" "$DISCOVERED_WS"
ws_count=$(count_lines "$DISCOVERED_WS")
info "Total WebSocket endpoints discovered: ${ws_count}"

if [ "$ws_count" -eq 0 ]; then
    warn "No WebSocket endpoints discovered"
    log "WebSocket testing complete: 0 endpoints found"
    log "  ${OUT_DIR}/ap_websocket_findings.txt"
    exit 0
fi

# ══════════════════════════════════════════════════════════════
# Stage 3: Auth bypass testing
# ══════════════════════════════════════════════════════════════
info "Stage 3: Testing WebSocket auth bypass..."

while IFS= read -r ws_url; do
    [ -z "$ws_url" ] && continue

    # Convert to wss:// if needed
    test_url="$ws_url"
    if [[ ! "$test_url" =~ ^wss?:// ]]; then
        test_url="wss://${test_url}"
    fi

    # Extract the HTTP URL for header-based probing
    http_url=$(echo "$test_url" | sed 's|^ws://|http://|;s|^wss://|https://|')

    info "  Auth bypass: ${test_url}"

    # Test 1: Connect without any cookies or auth headers
    noauth_resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGVzdGtleQ==" \
        -H "Sec-WebSocket-Version: 13" \
        -D- -o /dev/null "$http_url" 2>/dev/null || echo "")

    noauth_status=$(echo "$noauth_resp" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")

    if [ "$noauth_status" = "101" ]; then
        record_finding "HIGH" "$test_url" "WS Auth Bypass" \
            "WebSocket upgrade accepted without any authentication cookies/tokens"
    fi

    # Test 2: Connect with arbitrary auth token
    fake_token_resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGVzdGtleQ==" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Authorization: Bearer faketoken123" \
        -D- -o /dev/null "$http_url" 2>/dev/null || echo "")

    fake_status=$(echo "$fake_token_resp" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")

    if [ "$fake_status" = "101" ]; then
        record_finding "HIGH" "$test_url" "WS Fake Token Accepted" \
            "WebSocket upgrade accepted with arbitrary Bearer token"
    fi

done < "$DISCOVERED_WS"

# ══════════════════════════════════════════════════════════════
# Stage 4: CSWSH (Cross-Site WebSocket Hijacking)
# ══════════════════════════════════════════════════════════════
info "Stage 4: Testing CSWSH (Cross-Site WebSocket Hijacking)..."

while IFS= read -r ws_url; do
    [ -z "$ws_url" ] && continue

    http_url=$(echo "$ws_url" | sed 's|^ws://|http://|;s|^wss://|https://|')

    info "  CSWSH: ${ws_url}"

    # Test with evil.com Origin
    evil_origins=("https://evil.com" "https://attacker.com" "null")

    for origin in "${evil_origins[@]}"; do
        origin_resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGVzdGtleQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -H "Origin: ${origin}" \
            -D- -o /dev/null "$http_url" 2>/dev/null || echo "")

        origin_status=$(echo "$origin_resp" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")

        if [ "$origin_status" = "101" ]; then
            # Check ACAO header
            acao=$(echo "$origin_resp" | grep -i '^access-control-allow-origin:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')

            if [ -n "$acao" ] && [ "$acao" != "null" ]; then
                record_finding "HIGH" "$ws_url" "CSWSH" \
                    "WebSocket accepts Origin '${origin}' (HTTP 101, ACAO: ${acao}) — Cross-Site WebSocket Hijacking"
            else
                record_finding "HIGH" "$ws_url" "CSWSH (No Origin Check)" \
                    "WebSocket accepts arbitrary Origin '${origin}' (HTTP 101) — no CORS validation"
            fi
            break  # One evil origin finding is enough
        fi
    done
done < "$DISCOVERED_WS"

# ══════════════════════════════════════════════════════════════
# Stage 5: Message injection with websocat
# ══════════════════════════════════════════════════════════════
if $HAS_WEBSOCAT; then
    info "Stage 5: Testing message injection with websocat..."

    while IFS= read -r ws_url; do
        [ -z "$ws_url" ] && continue

        test_url="$ws_url"
        # Ensure wss:// prefix
        if [[ ! "$test_url" =~ ^wss?:// ]]; then
            test_url="wss://${test_url}"
        fi

        info "  Injecting: ${test_url}"

        # Test 1: Send a ping and check for response
        ping_resp=$(echo '{"type":"ping"}' | timeout 10 websocat -1 --insecure "$test_url" 2>/dev/null || echo "TIMEOUT")

        if [ "$ping_resp" != "TIMEOUT" ] && [ -n "$ping_resp" ]; then
            record_finding "MEDIUM" "$test_url" "WS Message Accepted" \
                "WebSocket accepts messages without auth. Response: $(echo "$ping_resp" | head -c 200)"
        fi

        # Test 2: Send GraphQL subscription (common WS use)
        gql_sub_resp=$(echo '{"type":"connection_init","payload":{}}' | timeout 10 websocat -1 --insecure "$test_url" 2>/dev/null || echo "TIMEOUT")

        if echo "$gql_sub_resp" | grep -qi "connection_ack\|ka\|data"; then
            record_finding "MEDIUM" "$test_url" "WS GraphQL Subscription" \
                "GraphQL subscription connection accepted. Response: $(echo "$gql_sub_resp" | head -c 200)"
        fi

        # Test 3: Common WebSocket injection payloads
        injection_payloads=(
            '{"action":"subscribe","channel":"admin"}'
            '{"type":"subscribe","topic":"#"}'
            '{"event":"join","room":"admin"}'
            '{"command":"subscribe","identifier":"{\"channel\":\"AdminChannel\"}"}'
        )

        for payload in "${injection_payloads[@]}"; do
            inject_resp=$(echo "$payload" | timeout 10 websocat -1 --insecure "$test_url" 2>/dev/null || echo "TIMEOUT")

            if [ "$inject_resp" != "TIMEOUT" ] && [ -n "$inject_resp" ]; then
                if ! echo "$inject_resp" | grep -qiE '(error|unauthorized|forbidden|denied|invalid)'; then
                    record_finding "MEDIUM" "$test_url" "WS Injection" \
                        "Payload accepted: $(echo "$payload" | head -c 100). Response: $(echo "$inject_resp" | head -c 200)"
                fi
            fi
        done

    done < "$DISCOVERED_WS"
else
    info "Stage 5: websocat not available — skipping message injection"
    info "  Install: sudo pacman -S websocat"
fi

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
total_findings=$(count_lines "${OUT_DIR}/ap_websocket_findings.txt")

echo ""
log "WebSocket testing complete:"
log "  Endpoints discovered: ${ws_count}"
log "  HIGH/CRITICAL:        ${HIGH_COUNT}"
log "  MEDIUM:               ${MEDIUM_COUNT}"
log "  LOW/INFO:             ${LOW_COUNT}"
log "  Total findings:       ${total_findings}"
log "Results:"
log "  ${OUT_DIR}/ap_websocket_findings.txt"
[ -s "$DISCOVERED_WS" ] && log "  ${DISCOVERED_WS}"

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo ""
    warn "HIGH/CRITICAL findings:"
    grep -E '^\[(HIGH|CRITICAL)\]' "${OUT_DIR}/ap_websocket_findings.txt" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
