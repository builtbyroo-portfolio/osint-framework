#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_method_tamper.sh — HTTP Method Tampering                  ║
# ║  Test endpoints for dangerous method acceptance (PUT/DELETE/  ║
# ║  TRACE/etc), OPTIONS Allow header exposure, and XST via TRACE ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_method_tamper.sh"
SCRIPT_DESC="HTTP Method Tampering"
MAX_ENDPOINTS=50

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test endpoints for HTTP method tampering vulnerabilities."
    echo "  Reads ac_interesting_endpoints.txt and probes each endpoint"
    echo "  with non-standard HTTP methods to detect misconfigurations."
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

phase_header "9" "$SCRIPT_DESC"

# ── Locate endpoint list ──────────────────────────────────────
ENDPOINTS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    ENDPOINTS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_interesting_endpoints.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ac_interesting_endpoints.txt"
else
    err "No endpoints found. Provide --urls or ensure ac_interesting_endpoints.txt exists in OUT_DIR."
    exit 1
fi

if [ ! -s "$ENDPOINTS_FILE" ]; then
    warn "Endpoints file is empty: ${ENDPOINTS_FILE}"
    exit 0
fi

total_endpoints=$(count_lines "$ENDPOINTS_FILE")
info "Loaded ${total_endpoints} endpoints from ${ENDPOINTS_FILE}"

if [ "$total_endpoints" -gt "$MAX_ENDPOINTS" ]; then
    warn "Capping to ${MAX_ENDPOINTS} endpoints (from ${total_endpoints})"
fi

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ac_method_findings.txt"
> "$FINDINGS_FILE"

# ── Sensitive endpoint pattern ────────────────────────────────
SENSITIVE_PATTERN='(admin|config|user|account|settings|api)'

# ── Methods to test ───────────────────────────────────────────
METHODS=(POST PUT DELETE PATCH TRACE HEAD CONNECT)

# ── Process endpoints ─────────────────────────────────────────
processed=0
high_count=0
medium_count=0
info_count=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((processed++)) || true
    [ "$processed" -gt "$MAX_ENDPOINTS" ] && break

    info "[${processed}/${total_endpoints:+$(( total_endpoints > MAX_ENDPOINTS ? MAX_ENDPOINTS : total_endpoints ))}] Testing: ${url}"

    # ── Step 1: GET baseline ──────────────────────────────────
    baseline=$(curl -sk "${HUNT_UA_CURL[@]}" -o /dev/null \
        -w "%{http_code}:%{size_download}" --max-time 8 "$url" 2>/dev/null || echo "000:0")
    baseline_status="${baseline%%:*}"
    baseline_size="${baseline##*:}"

    # Skip if target is unreachable
    if [ "$baseline_status" = "000" ]; then
        warn "  Unreachable (GET timeout/error), skipping"
        continue
    fi

    # ── Step 2: OPTIONS — check Allow header ──────────────────
    options_headers=$(curl -sk "${HUNT_UA_CURL[@]}" -X OPTIONS \
        -D- -o /dev/null --max-time 8 "$url" 2>/dev/null || echo "")
    allow_header=$(echo "$options_headers" | grep -i '^allow:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    options_status=$(echo "$options_headers" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")

    if [ -n "$allow_header" ]; then
        # Check for dangerous methods in Allow header
        dangerous_in_allow=""
        for dm in PUT DELETE PATCH; do
            if echo "$allow_header" | grep -qiw "$dm"; then
                dangerous_in_allow="${dangerous_in_allow:+${dangerous_in_allow}, }${dm}"
            fi
        done

        if [ -n "$dangerous_in_allow" ]; then
            ((medium_count++)) || true
            log "  [MEDIUM] OPTIONS exposes: ${dangerous_in_allow}"
            echo "[MEDIUM] ${url} OPTIONS=${options_status} exposes ${dangerous_in_allow} (baseline GET=${baseline}) [Allow: ${allow_header}]" >> "$FINDINGS_FILE"
        fi
    fi

    # ── Step 3: Test each method ──────────────────────────────
    for method in "${METHODS[@]}"; do
        result=$(curl -sk "${HUNT_UA_CURL[@]}" -X "$method" \
            -o /dev/null -w "%{http_code}:%{size_download}" --max-time 8 "$url" 2>/dev/null || echo "000:0")
        method_status="${result%%:*}"
        method_size="${result##*:}"

        # ── Step 4: Special TRACE check for XST ──────────────
        if [ "$method" = "TRACE" ] && [ "$method_status" = "200" ]; then
            trace_body=$(curl -sk "${HUNT_UA_CURL[@]}" -X TRACE \
                -H "X-Method-Test: xst-check" --max-time 8 "$url" 2>/dev/null || echo "")
            if echo "$trace_body" | grep -qi "X-Method-Test"; then
                ((high_count++)) || true
                log "  ${RED}[HIGH]${NC} TRACE echoes headers (XST vulnerability)"
                echo "[HIGH] ${url} TRACE=${result} echoes request headers — XST (baseline GET=${baseline})" >> "$FINDINGS_FILE"
                continue
            fi
        fi

        # Skip if same as baseline (no difference = no finding)
        if [ "$method_status" = "$baseline_status" ] && [ "$method_size" = "$baseline_size" ]; then
            continue
        fi

        # ── Classify findings ─────────────────────────────────
        is_sensitive=false
        if echo "$url" | grep -qiP "$SENSITIVE_PATTERN"; then
            is_sensitive=true
        fi

        allow_note=""
        [ -n "$allow_header" ] && allow_note=" [Allow: ${allow_header}]"

        case "$method" in
            PUT|DELETE)
                if [[ "$method_status" =~ ^(200|201)$ ]]; then
                    if $is_sensitive; then
                        ((high_count++)) || true
                        log "  ${RED}[HIGH]${NC} ${method}=${result} on sensitive endpoint"
                        echo "[HIGH] ${url} ${method}=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                    else
                        ((medium_count++)) || true
                        log "  ${YELLOW}[MEDIUM]${NC} ${method}=${result} accepted"
                        echo "[MEDIUM] ${url} ${method}=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                    fi
                elif [ "$method_status" != "$baseline_status" ]; then
                    ((info_count++)) || true
                    echo "[INFO] ${url} ${method}=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                fi
                ;;
            POST)
                if [ "$method_status" != "$baseline_status" ]; then
                    ((medium_count++)) || true
                    log "  ${YELLOW}[MEDIUM]${NC} POST=${result} differs from GET (potential state-changing)"
                    echo "[MEDIUM] ${url} POST=${result} differs from GET=${baseline} (potential state-changing)${allow_note}" >> "$FINDINGS_FILE"
                fi
                ;;
            PATCH)
                if [[ "$method_status" =~ ^(200|201)$ ]]; then
                    if $is_sensitive; then
                        ((high_count++)) || true
                        log "  ${RED}[HIGH]${NC} PATCH=${result} on sensitive endpoint"
                        echo "[HIGH] ${url} PATCH=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                    else
                        ((medium_count++)) || true
                        log "  ${YELLOW}[MEDIUM]${NC} PATCH=${result} accepted"
                        echo "[MEDIUM] ${url} PATCH=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                    fi
                fi
                ;;
            TRACE)
                # Non-200 TRACE differences are INFO at most
                if [ "$method_status" != "$baseline_status" ]; then
                    ((info_count++)) || true
                    echo "[INFO] ${url} TRACE=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                fi
                ;;
            HEAD|CONNECT)
                if [ "$method_status" != "$baseline_status" ]; then
                    ((info_count++)) || true
                    echo "[INFO] ${url} ${method}=${result} (baseline GET=${baseline})${allow_note}" >> "$FINDINGS_FILE"
                fi
                ;;
        esac
    done

done < "$ENDPOINTS_FILE"

# ── Summary ───────────────────────────────────────────────────
total_findings=$(count_lines "$FINDINGS_FILE")
log "Method tampering complete: ${processed} endpoints tested"
log "  HIGH:   ${high_count}"
log "  MEDIUM: ${medium_count}"
log "  INFO:   ${info_count}"
log "  Total:  ${total_findings} findings → ${FINDINGS_FILE}"

if [ "$high_count" -gt 0 ]; then
    log ""
    log "HIGH severity findings:"
    grep '^\[HIGH\]' "$FINDINGS_FILE" | while IFS= read -r line; do
        log "  ${line}"
    done
fi
