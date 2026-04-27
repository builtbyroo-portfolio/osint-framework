#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_rate_bypass.sh — Rate Limit Bypass Testing               ║
# ║  Detection · X-Forwarded-For rotation · header tricks ·      ║
# ║  case variation · method switching · path mangling ·         ║
# ║  Unicode normalization · API version switching               ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_rate_bypass.sh"
SCRIPT_DESC="Rate Limit Bypass Testing"
MAX_ENDPOINTS=30

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Detect rate limits on API endpoints and test bypass techniques"
    echo "  including IP header rotation, path mangling, method switching,"
    echo "  and case variation."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with API URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "7" "$SCRIPT_DESC"

# ── Locate endpoints ─────────────────────────────────────────
ENDPOINTS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    ENDPOINTS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_api_findings.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ac_api_findings.txt"
elif [ -f "${OUT_DIR}/ap_discovered_endpoints.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ap_discovered_endpoints.txt"
fi

# Build URL list
URL_LIST=$(mktemp)
trap 'rm -f "$URL_LIST"' EXIT

if [ -n "$ENDPOINTS_FILE" ] && [ -f "$ENDPOINTS_FILE" ]; then
    grep -oP 'https?://[^\s]+' "$ENDPOINTS_FILE" 2>/dev/null | sort -u >> "$URL_LIST"
fi

# Add common rate-limited paths from domain
if [ -n "${DOMAIN:-}" ]; then
    rate_limit_paths=("/api/login" "/api/auth" "/api/signin" "/api/register"
        "/api/signup" "/api/forgot-password" "/api/reset-password"
        "/api/otp" "/api/verify" "/api/send-code" "/api/v1/login"
        "/api/v1/auth" "/api/v2/login" "/login" "/auth" "/signin")
    for rp in "${rate_limit_paths[@]}"; do
        echo "https://${DOMAIN}${rp}" >> "$URL_LIST"
    done
fi

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -z "$d" ] && continue
        for rp in "/api/login" "/api/auth" "/login" "/auth"; do
            echo "https://${d}${rp}" >> "$URL_LIST"
        done
    done < "$DOMAINS_FILE"
fi

sort -u -o "$URL_LIST" "$URL_LIST"
total_urls=$(count_lines "$URL_LIST")

if [ "$total_urls" -eq 0 ]; then
    err "No URLs to test. Provide --urls, --domain, or run ac_api_discovery.sh first."
    exit 1
fi

info "Loaded ${total_urls} URL(s) for rate limit testing"
if [ "$total_urls" -gt "$MAX_ENDPOINTS" ]; then
    warn "Capping to ${MAX_ENDPOINTS} endpoints (from ${total_urls})"
fi

# ── Output file ──────────────────────────────────────────────
> "${OUT_DIR}/ap_rate_bypass_findings.txt"

# ── Counters ─────────────────────────────────────────────────
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
processed=0

record_finding() {
    local severity="$1" url="$2" test_name="$3" detail="$4"
    echo "[${severity}] ${test_name} | ${url} | ${detail}" >> "${OUT_DIR}/ap_rate_bypass_findings.txt"
    case "$severity" in
        HIGH|CRITICAL) ((HIGH_COUNT++)) || true; warn "[${severity}] ${test_name}: ${url}" ;;
        MEDIUM)        ((MEDIUM_COUNT++)) || true; log "[MEDIUM] ${test_name}: ${url}" ;;
        *)             ((LOW_COUNT++)) || true ;;
    esac
}

# ── Helper: generate random IP ───────────────────────────────
random_ip() {
    echo "$((RANDOM % 223 + 1)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))"
}

# ── Helper: send N requests and check for rate limiting ──────
# Returns: "limited" if rate limited, "open" if not
detect_rate_limit() {
    local url="$1"
    local count="${2:-20}"
    local method="${3:-GET}"
    local extra_headers="${4:-}"

    local rate_limited=false
    local success_count=0
    local block_count=0

    for ((i=1; i<=count; i++)); do
        local resp_code
        if [ "$method" = "POST" ]; then
            resp_code=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                ${extra_headers} \
                -d '{"username":"test","password":"test"}' \
                -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        else
            resp_code=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                ${extra_headers} \
                -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        fi

        if [[ "$resp_code" =~ ^(429|503|403)$ ]]; then
            ((block_count++)) || true
        elif [[ "$resp_code" =~ ^(200|201|301|302|400|401|404|405)$ ]]; then
            ((success_count++)) || true
        fi
    done

    if [ "$block_count" -gt 0 ]; then
        echo "limited:${block_count}/${count}"
    else
        echo "open:${success_count}/${count}"
    fi
}

# ══════════════════════════════════════════════════════════════
# Process each URL
# ══════════════════════════════════════════════════════════════
while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((processed++)) || true
    [ "$processed" -gt "$MAX_ENDPOINTS" ] && break

    # First check if endpoint is alive
    alive_check=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
        -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [ "$alive_check" = "000" ] || [ "$alive_check" = "404" ]; then
        continue
    fi

    info "[${processed}/${total_urls}] Testing: ${url} (baseline: HTTP ${alive_check})"

    # ══════════════════════════════════════════════════════════
    # Step 1: Detect if rate limiting exists
    # ══════════════════════════════════════════════════════════
    info "  [1/8] Detecting rate limits..."

    # Determine method (POST for auth endpoints, GET for others)
    method="GET"
    if echo "$url" | grep -qiP '(login|auth|signin|register|signup|forgot|reset|otp|verify|send)'; then
        method="POST"
    fi

    baseline_result=$(detect_rate_limit "$url" 15 "$method")
    baseline_type="${baseline_result%%:*}"
    baseline_detail="${baseline_result##*:}"

    if [ "$baseline_type" = "open" ]; then
        record_finding "MEDIUM" "$url" "No Rate Limit" \
            "No rate limiting detected after 15 rapid ${method} requests (${baseline_detail} succeeded)"

        # If no rate limit, skip bypass testing — already an issue
        continue
    fi

    info "    Rate limit detected (${baseline_detail} blocked)"
    record_finding "LOW" "$url" "Rate Limit Active" \
        "Rate limiting active: ${baseline_detail} requests blocked in 15-request burst"

    # ══════════════════════════════════════════════════════════
    # Step 2: X-Forwarded-For rotation
    # ══════════════════════════════════════════════════════════
    info "  [2/8] X-Forwarded-For rotation..."

    xff_success=0
    xff_blocked=0
    for ((i=1; i<=15; i++)); do
        fake_ip=$(random_ip)
        if [ "$method" = "POST" ]; then
            resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -H "X-Forwarded-For: ${fake_ip}" \
                -d '{"username":"test","password":"test"}' \
                -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        else
            resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                -H "X-Forwarded-For: ${fake_ip}" \
                -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        fi

        if [[ "$resp" =~ ^(429|503)$ ]]; then
            ((xff_blocked++)) || true
        elif [[ "$resp" =~ ^(200|201|301|302|400|401|404|405)$ ]]; then
            ((xff_success++)) || true
        fi
    done

    if [ "$xff_success" -gt 10 ] && [ "$xff_blocked" -eq 0 ]; then
        record_finding "HIGH" "$url" "Rate Limit Bypass (X-Forwarded-For)" \
            "X-Forwarded-For rotation bypasses rate limit: ${xff_success}/15 requests succeeded"
    elif [ "$xff_success" -gt 5 ]; then
        record_finding "MEDIUM" "$url" "Partial Rate Limit Bypass (X-Forwarded-For)" \
            "X-Forwarded-For rotation partially bypasses rate limit: ${xff_success}/15 succeeded"
    fi

    # ══════════════════════════════════════════════════════════
    # Step 3: Other IP headers
    # ══════════════════════════════════════════════════════════
    info "  [3/8] Alternative IP headers..."

    ip_headers=("X-Real-IP" "X-Originating-IP" "True-Client-IP" "X-Client-IP"
        "CF-Connecting-IP" "X-Forwarded" "Forwarded-For" "X-Remote-IP"
        "X-Remote-Addr" "X-Custom-IP-Authorization")

    for hdr in "${ip_headers[@]}"; do
        hdr_success=0
        for ((i=1; i<=10; i++)); do
            fake_ip=$(random_ip)
            if [ "$method" = "POST" ]; then
                resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                    -X POST -H "Content-Type: application/json" \
                    -H "${hdr}: ${fake_ip}" \
                    -d '{"username":"test","password":"test"}' \
                    -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
            else
                resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                    -H "${hdr}: ${fake_ip}" \
                    -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
            fi

            [[ "$resp" =~ ^(200|201|301|302|400|401|404|405)$ ]] && ((hdr_success++)) || true
        done

        if [ "$hdr_success" -ge 8 ]; then
            record_finding "HIGH" "$url" "Rate Limit Bypass (${hdr})" \
                "Header '${hdr}' bypasses rate limit: ${hdr_success}/10 requests succeeded"
            break  # One bypass header is enough for the finding
        fi
    done

    # ══════════════════════════════════════════════════════════
    # Step 4: Endpoint case variation
    # ══════════════════════════════════════════════════════════
    info "  [4/8] Case variation..."

    # Generate case variations of the URL path
    url_path=$(echo "$url" | grep -oP 'https?://[^/]+\K.*')
    url_base=$(echo "$url" | grep -oP 'https?://[^/]+')

    if [ -n "$url_path" ]; then
        # Generate a few case variations
        case_variations=()
        # Uppercase first letter of each path segment
        upper_first=$(echo "$url_path" | sed 's|\(/[a-z]\)|\U\1|g')
        [ "$upper_first" != "$url_path" ] && case_variations+=("${url_base}${upper_first}")

        # All uppercase
        all_upper=$(echo "$url_path" | tr '[:lower:]' '[:upper:]')
        [ "$all_upper" != "$url_path" ] && case_variations+=("${url_base}${all_upper}")

        # Mixed case
        mixed=$(echo "$url_path" | sed 's/./\U&/3;s/./\U&/5;s/./\U&/7')
        [ "$mixed" != "$url_path" ] && case_variations+=("${url_base}${mixed}")

        for var_url in "${case_variations[@]+"${case_variations[@]}"}"; do
            [ -z "$var_url" ] && continue

            var_success=0
            for ((i=1; i<=10; i++)); do
                if [ "$method" = "POST" ]; then
                    resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                        -X POST -H "Content-Type: application/json" \
                        -d '{"username":"test","password":"test"}' \
                        -o /dev/null -w "%{http_code}" "$var_url" 2>/dev/null || echo "000")
                else
                    resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                        -o /dev/null -w "%{http_code}" "$var_url" 2>/dev/null || echo "000")
                fi

                [[ "$resp" =~ ^(200|201|301|302|400|401)$ ]] && ((var_success++)) || true
            done

            if [ "$var_success" -ge 8 ]; then
                record_finding "MEDIUM" "$var_url" "Rate Limit Bypass (Case Variation)" \
                    "Case-varied URL bypasses rate limit: ${var_success}/10 succeeded (original: ${url_path})"
                break
            fi
        done
    fi

    # ══════════════════════════════════════════════════════════
    # Step 5: HTTP method switching
    # ══════════════════════════════════════════════════════════
    info "  [5/8] Method switching..."

    alt_methods=()
    if [ "$method" = "POST" ]; then
        alt_methods=("GET" "PUT" "PATCH")
    else
        alt_methods=("POST" "PUT" "PATCH")
    fi

    for alt in "${alt_methods[@]}"; do
        alt_success=0
        for ((i=1; i<=10; i++)); do
            if [ "$alt" = "GET" ]; then
                resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                    -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
            else
                resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                    -X "$alt" -H "Content-Type: application/json" \
                    -d '{"username":"test","password":"test"}' \
                    -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
            fi

            [[ "$resp" =~ ^(200|201|301|302|400|401)$ ]] && ((alt_success++)) || true
        done

        if [ "$alt_success" -ge 8 ]; then
            record_finding "MEDIUM" "$url" "Rate Limit Bypass (Method: ${alt})" \
                "Switching to ${alt} bypasses rate limit: ${alt_success}/10 succeeded (original: ${method})"
        fi
    done

    # ══════════════════════════════════════════════════════════
    # Step 6: Path parameter injection
    # ══════════════════════════════════════════════════════════
    info "  [6/8] Path parameter mangling..."

    path_mangles=(
        "${url}/.."
        "${url}/."
        "${url}/"
        "${url}/%20"
        "${url}?foo=bar"
        "${url}#"
        "${url};.css"
        "${url};.js"
        "${url}%00"
        "${url}%0d%0a"
    )

    for mangled in "${path_mangles[@]}"; do
        mangle_success=0
        for ((i=1; i<=10; i++)); do
            if [ "$method" = "POST" ]; then
                resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                    -X POST -H "Content-Type: application/json" \
                    -d '{"username":"test","password":"test"}' \
                    -o /dev/null -w "%{http_code}" "$mangled" 2>/dev/null || echo "000")
            else
                resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                    -o /dev/null -w "%{http_code}" "$mangled" 2>/dev/null || echo "000")
            fi

            [[ "$resp" =~ ^(200|201|301|302|400|401)$ ]] && ((mangle_success++)) || true
        done

        if [ "$mangle_success" -ge 8 ]; then
            # Determine which suffix was added
            suffix="${mangled#${url}}"
            record_finding "MEDIUM" "$mangled" "Rate Limit Bypass (Path: ${suffix})" \
                "Path suffix '${suffix}' bypasses rate limit: ${mangle_success}/10 succeeded"
            break  # One path bypass is enough
        fi
    done

    # ══════════════════════════════════════════════════════════
    # Step 7: Unicode normalization bypass
    # ══════════════════════════════════════════════════════════
    info "  [7/8] Unicode normalization..."

    # Replace ASCII chars with Unicode equivalents
    if echo "$url" | grep -qP '/[a-z]'; then
        # Replace 'a' with Unicode fullwidth 'a' (\uff41)
        unicode_url=$(echo "$url" | sed 's/login/l%C0%AFgin/;s/auth/%C0%A1uth/')
        if [ "$unicode_url" != "$url" ]; then
            uni_success=0
            for ((i=1; i<=10; i++)); do
                if [ "$method" = "POST" ]; then
                    resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                        -X POST -H "Content-Type: application/json" \
                        -d '{"username":"test","password":"test"}' \
                        -o /dev/null -w "%{http_code}" "$unicode_url" 2>/dev/null || echo "000")
                else
                    resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                        -o /dev/null -w "%{http_code}" "$unicode_url" 2>/dev/null || echo "000")
                fi

                [[ "$resp" =~ ^(200|201|301|302|400|401)$ ]] && ((uni_success++)) || true
            done

            if [ "$uni_success" -ge 8 ]; then
                record_finding "MEDIUM" "$unicode_url" "Rate Limit Bypass (Unicode)" \
                    "Unicode-normalized URL bypasses rate limit: ${uni_success}/10 succeeded"
            fi
        fi
    fi

    # ══════════════════════════════════════════════════════════
    # Step 8: API version switching
    # ══════════════════════════════════════════════════════════
    info "  [8/8] API version switching..."

    if echo "$url" | grep -qP '/v\d+/'; then
        current_ver=$(echo "$url" | grep -oP '/v(\d+)/' | grep -oP '\d+')
        if [ -n "$current_ver" ]; then
            for alt_ver in 1 2 3 4; do
                [ "$alt_ver" -eq "$current_ver" ] && continue
                ver_url=$(echo "$url" | sed "s|/v${current_ver}/|/v${alt_ver}/|")

                ver_success=0
                for ((i=1; i<=10; i++)); do
                    if [ "$method" = "POST" ]; then
                        resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                            -X POST -H "Content-Type: application/json" \
                            -d '{"username":"test","password":"test"}' \
                            -o /dev/null -w "%{http_code}" "$ver_url" 2>/dev/null || echo "000")
                    else
                        resp=$(curl -sk --connect-timeout 8 --max-time 10 "${HUNT_UA_CURL[@]}" \
                            -o /dev/null -w "%{http_code}" "$ver_url" 2>/dev/null || echo "000")
                    fi

                    [[ "$resp" =~ ^(200|201|301|302|400|401)$ ]] && ((ver_success++)) || true
                done

                if [ "$ver_success" -ge 8 ]; then
                    record_finding "MEDIUM" "$ver_url" "Rate Limit Bypass (API Version)" \
                        "API v${alt_ver} not rate limited: ${ver_success}/10 succeeded (v${current_ver} is limited)"
                fi
            done
        fi
    fi

done < "$URL_LIST"

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
total_findings=$(count_lines "${OUT_DIR}/ap_rate_bypass_findings.txt")

echo ""
log "Rate limit bypass testing complete: ${processed} endpoint(s) tested"
log "  HIGH/CRITICAL: ${HIGH_COUNT}"
log "  MEDIUM:        ${MEDIUM_COUNT}"
log "  LOW/INFO:      ${LOW_COUNT}"
log "  Total:         ${total_findings} findings → ${OUT_DIR}/ap_rate_bypass_findings.txt"

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo ""
    warn "HIGH findings — rate limits bypassed:"
    grep '^\[HIGH\]' "${OUT_DIR}/ap_rate_bypass_findings.txt" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
