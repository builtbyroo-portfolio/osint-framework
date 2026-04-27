#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_cdn_bypass.sh — CDN/WAF Origin Bypass                    ║
# ║  DNS history · CT logs · origin hostname patterns · IPv6     ║
# ║  fallback · mail/ftp subdomain origin discovery              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_cdn_bypass.sh"
SCRIPT_DESC="CDN/WAF Origin Bypass"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover origin IP addresses behind CDN/WAF via DNS history,"
    echo "  certificate transparency logs, origin hostname patterns,"
    echo "  IPv6 fallback, and mail/ftp subdomain enumeration."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "8" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

# ── Build domain list ─────────────────────────────────────────
DOMAIN_LIST="${OUT_DIR}/_ct_cdn_domains.txt"
> "$DOMAIN_LIST"

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$DOMAIN_LIST"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$DOMAIN_LIST"
fi
sort -u -o "$DOMAIN_LIST" "$DOMAIN_LIST"

domain_count=$(count_lines "$DOMAIN_LIST")
info "Analyzing ${domain_count} domain(s) for CDN/WAF bypass"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_cdn_bypass_findings.txt"
> "$FINDINGS_FILE"

# ── Known CDN IP ranges (partial, for comparison) ─────────────
# These are used to determine if an IP is a CDN IP vs origin IP
is_cdn_ip() {
    local ip="$1"
    # Cloudflare ranges (partial)
    if echo "$ip" | grep -qP '^(104\.1[6-9]\.|104\.2[0-7]\.|172\.6[4-9]\.|172\.7[0-1]\.|173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.)'; then
        return 0
    fi
    # CloudFront ranges (partial)
    if echo "$ip" | grep -qP '^(13\.32\.|13\.33\.|13\.35\.|54\.182\.|54\.192\.|54\.230\.|54\.239\.|52\.84\.|52\.85\.|52\.222\.|99\.84\.|99\.86\.|143\.204\.|205\.251\.)'; then
        return 0
    fi
    # Fastly ranges (partial)
    if echo "$ip" | grep -qP '^(151\.101\.|199\.27\.|23\.235\.|43\.249\.7[2-9]\.|103\.244\.5[0-1]\.)'; then
        return 0
    fi
    # Akamai ranges (partial, very large)
    if echo "$ip" | grep -qP '^(23\.([0-9]|[1-6][0-9]|7[0-9]|8[0-9]|9[0-9])\.|2\.16\.|2\.17\.|2\.18\.|2\.19\.|2\.20\.|2\.21\.|2\.22\.|2\.23\.|95\.100\.|96\.(6|7|16|17)\.)'; then
        return 0
    fi
    return 1
}

# ── Helper: test if IP serves the domain's content ───────────
test_origin_ip() {
    local ip="$1"
    local domain="$2"
    local source="$3"

    # Skip CDN IPs
    if is_cdn_ip "$ip"; then
        return
    fi

    # Test HTTPS with SNI
    resp_https=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
        --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        --resolve "${domain}:443:${ip}" \
        "https://${domain}/" 2>/dev/null || echo "000:0")

    # Test HTTP
    resp_http=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
        --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        --resolve "${domain}:80:${ip}" \
        "http://${domain}/" 2>/dev/null || echo "000:0")

    https_status="${resp_https%%:*}"
    https_size="${resp_https##*:}"
    http_status="${resp_http%%:*}"
    http_size="${resp_http##*:}"

    if [[ "$https_status" =~ ^(200|301|302|403)$ ]] && [ "${https_size:-0}" -gt 0 ]; then
        echo "[HIGH] ORIGIN IP FOUND: ${ip} | Domain: ${domain} | HTTPS: ${https_status}/${https_size}b | Source: ${source}" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} Origin IP: ${ip} (${domain}) via ${source} [HTTPS ${https_status}]"
    elif [[ "$http_status" =~ ^(200|301|302|403)$ ]] && [ "${http_size:-0}" -gt 0 ]; then
        echo "[HIGH] ORIGIN IP FOUND: ${ip} | Domain: ${domain} | HTTP: ${http_status}/${http_size}b | Source: ${source}" >> "$FINDINGS_FILE"
        warn "  ${RED}[HIGH]${NC} Origin IP: ${ip} (${domain}) via ${source} [HTTP ${http_status}]"
    fi
}

# ── Main analysis loop ───────────────────────────────────────
tested=0

while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    ((tested++)) || true

    info "[${tested}/${domain_count}] Analyzing: ${domain}"

    # Get current A records (CDN IPs)
    current_ips=$(dig +short A "$domain" 2>/dev/null | grep -P '^\d+\.\d+\.\d+\.\d+$' | sort -u)
    if [ -n "$current_ips" ]; then
        echo "[INFO] ${domain} Current A records:" >> "$FINDINGS_FILE"
        echo "$current_ips" | while IFS= read -r ip; do
            cdn_tag=""
            is_cdn_ip "$ip" && cdn_tag=" [CDN]"
            echo "[INFO]   ${ip}${cdn_tag}" >> "$FINDINGS_FILE"
        done
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 1: DNS History via crt.sh (Certificate Transparency)
    # ═══════════════════════════════════════════════════════════
    info "  Querying certificate transparency logs (crt.sh)..."

    ct_domains=$(curl -sk --connect-timeout 8 --max-time 30 \
        "${HUNT_UA_CURL[@]}" \
        "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
        python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name:
                names.add(name)
    for n in sorted(names):
        print(n)
except: pass
" 2>/dev/null || echo "")

    if [ -n "$ct_domains" ]; then
        ct_count=$(echo "$ct_domains" | wc -l)
        log "  CT log subdomains: ${ct_count}"
        echo "$ct_domains" > "${OUT_DIR}/_ct_crt_domains_${domain}.txt"

        # Resolve CT subdomains and check for non-CDN IPs
        echo "$ct_domains" | head -50 | while IFS= read -r sub; do
            [ -z "$sub" ] && continue
            sub_ip=$(dig +short A "$sub" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")
            if [ -n "$sub_ip" ] && ! is_cdn_ip "$sub_ip"; then
                # Check if this IP is different from CDN IPs
                if ! echo "$current_ips" | grep -qF "$sub_ip"; then
                    echo "[MEDIUM] CT NON-CDN IP: ${sub} -> ${sub_ip} | May be origin" >> "$FINDINGS_FILE"
                    log "  ${YELLOW}[MEDIUM]${NC} CT subdomain ${sub} resolves to non-CDN IP: ${sub_ip}"
                    test_origin_ip "$sub_ip" "$domain" "crt.sh:${sub}"
                fi
            fi
        done
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 2: Origin hostname patterns
    # ═══════════════════════════════════════════════════════════
    info "  Testing origin hostname patterns..."

    # Extract base domain (remove first subdomain if present)
    base_domain="$domain"

    ORIGIN_PREFIXES=(
        "origin" "direct" "real" "backend" "server"
        "origin-www" "direct-connect" "web"
        "raw" "node" "app" "api-origin"
        "lb" "loadbalancer" "proxy" "edge"
        "staging" "stage" "dev" "test" "qa"
        "internal" "corp" "intranet"
        "old" "legacy" "backup" "bak"
    )

    ORIGIN_SUFFIXES=(
        "mail" "ftp" "cpanel" "webmail" "smtp"
        "pop" "imap" "mx" "autodiscover"
        "vpn" "remote" "ssh" "rdp"
    )

    for prefix in "${ORIGIN_PREFIXES[@]}"; do
        test_host="${prefix}.${base_domain}"
        test_ip=$(dig +short A "$test_host" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")

        if [ -n "$test_ip" ]; then
            if ! is_cdn_ip "$test_ip" && ! echo "$current_ips" | grep -qF "$test_ip"; then
                echo "[MEDIUM] ORIGIN HOSTNAME: ${test_host} -> ${test_ip}" >> "$FINDINGS_FILE"
                log "  ${YELLOW}[MEDIUM]${NC} ${test_host} -> ${test_ip} (non-CDN)"
                test_origin_ip "$test_ip" "$domain" "hostname:${test_host}"
            fi
        fi
    done

    for suffix in "${ORIGIN_SUFFIXES[@]}"; do
        test_host="${suffix}.${base_domain}"
        test_ip=$(dig +short A "$test_host" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")

        if [ -n "$test_ip" ]; then
            if ! is_cdn_ip "$test_ip" && ! echo "$current_ips" | grep -qF "$test_ip"; then
                echo "[MEDIUM] SERVICE SUBDOMAIN: ${test_host} -> ${test_ip}" >> "$FINDINGS_FILE"
                log "  ${YELLOW}[MEDIUM]${NC} ${test_host} -> ${test_ip} (non-CDN)"
                test_origin_ip "$test_ip" "$domain" "service:${test_host}"
            fi
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 3: MX record origin discovery
    # ═══════════════════════════════════════════════════════════
    info "  Checking MX records for origin IPs..."

    mx_records=$(dig +short MX "$domain" 2>/dev/null | awk '{print $2}' | sed 's/\.$//')
    if [ -n "$mx_records" ]; then
        echo "$mx_records" | while IFS= read -r mx; do
            [ -z "$mx" ] && continue
            mx_ip=$(dig +short A "$mx" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")
            if [ -n "$mx_ip" ] && ! is_cdn_ip "$mx_ip"; then
                if ! echo "$current_ips" | grep -qF "$mx_ip"; then
                    echo "[MEDIUM] MX ORIGIN: ${mx} -> ${mx_ip}" >> "$FINDINGS_FILE"
                    log "  ${YELLOW}[MEDIUM]${NC} MX ${mx} -> ${mx_ip} (non-CDN)"
                    test_origin_ip "$mx_ip" "$domain" "MX:${mx}"
                fi
            fi
        done
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 4: SPF record origin IPs
    # ═══════════════════════════════════════════════════════════
    info "  Checking SPF record for origin IPs..."

    spf_record=$(dig +short TXT "$domain" 2>/dev/null | grep -i 'v=spf1' | tr -d '"')
    if [ -n "$spf_record" ]; then
        # Extract ip4 mechanisms
        spf_ips=$(echo "$spf_record" | grep -oP 'ip4:\K[0-9./]+' | sed 's|/.*||')
        if [ -n "$spf_ips" ]; then
            echo "$spf_ips" | while IFS= read -r spf_ip; do
                [ -z "$spf_ip" ] && continue
                if ! is_cdn_ip "$spf_ip" && ! echo "$current_ips" | grep -qF "$spf_ip"; then
                    echo "[MEDIUM] SPF ORIGIN IP: ${spf_ip} | From SPF: ${spf_record}" >> "$FINDINGS_FILE"
                    log "  ${YELLOW}[MEDIUM]${NC} SPF ip4: ${spf_ip} (non-CDN)"
                    test_origin_ip "$spf_ip" "$domain" "SPF"
                fi
            done
        fi

        # Extract include/a/mx mechanisms and resolve
        spf_includes=$(echo "$spf_record" | grep -oP 'include:\K[^ ]+')
        if [ -n "$spf_includes" ]; then
            echo "$spf_includes" | head -5 | while IFS= read -r inc; do
                inc_ip=$(dig +short A "$inc" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")
                if [ -n "$inc_ip" ] && ! is_cdn_ip "$inc_ip"; then
                    echo "[INFO] SPF include: ${inc} -> ${inc_ip}" >> "$FINDINGS_FILE"
                fi
            done
        fi
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 5: IPv6 fallback (AAAA records)
    # ═══════════════════════════════════════════════════════════
    info "  Checking IPv6 (AAAA) records..."

    aaaa_records=$(dig +short AAAA "$domain" 2>/dev/null | grep -P '^[0-9a-f:]' | sort -u)
    if [ -n "$aaaa_records" ]; then
        echo "$aaaa_records" | while IFS= read -r ipv6; do
            [ -z "$ipv6" ] && continue
            echo "[INFO] ${domain} AAAA: ${ipv6}" >> "$FINDINGS_FILE"

            # Test if IPv6 serves content directly (may bypass CDN)
            resp_v6=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
                --connect-timeout 8 --max-time 15 \
                "${HUNT_UA_CURL[@]}" \
                -6 --resolve "${domain}:443:[${ipv6}]" \
                "https://${domain}/" 2>/dev/null || echo "000:0")

            v6_status="${resp_v6%%:*}"
            v6_size="${resp_v6##*:}"

            if [[ "$v6_status" =~ ^(200|301|302)$ ]] && [ "${v6_size:-0}" -gt 0 ]; then
                # Check if response differs from CDN response (no CDN headers)
                v6_headers=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
                    "${HUNT_UA_CURL[@]}" \
                    -6 --resolve "${domain}:443:[${ipv6}]" \
                    "https://${domain}/" 2>/dev/null || echo "")

                if ! echo "$v6_headers" | grep -qiP '(cf-ray|x-amz-cf|x-cache.*cloudfront|x-akamai|x-served-by.*cache-)'; then
                    echo "[HIGH] IPV6 CDN BYPASS: ${domain} [${ipv6}] | Status: ${v6_status} | No CDN headers" >> "$FINDINGS_FILE"
                    warn "  ${RED}[HIGH]${NC} IPv6 may bypass CDN: ${domain} [${ipv6}]"
                fi
            fi
        done
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 6: Without www (may resolve differently)
    # ═══════════════════════════════════════════════════════════
    if echo "$domain" | grep -q '^www\.'; then
        bare_domain="${domain#www.}"
    else
        bare_domain="www.${domain}"
    fi

    info "  Comparing ${domain} vs ${bare_domain}..."
    alt_ip=$(dig +short A "$bare_domain" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")
    if [ -n "$alt_ip" ] && ! echo "$current_ips" | grep -qF "$alt_ip"; then
        if ! is_cdn_ip "$alt_ip"; then
            echo "[MEDIUM] ALT DOMAIN ORIGIN: ${bare_domain} -> ${alt_ip} (different from ${domain})" >> "$FINDINGS_FILE"
            log "  ${YELLOW}[MEDIUM]${NC} ${bare_domain} resolves to non-CDN: ${alt_ip}"
            test_origin_ip "$alt_ip" "$domain" "alt_domain:${bare_domain}"
        fi
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 7: Common cloud provider patterns
    # ═══════════════════════════════════════════════════════════
    info "  Testing cloud provider origin patterns..."

    # Try direct IP via common cloud metadata-style subdomains
    CLOUD_SUBS=(
        "ec2" "aws" "s3" "gce" "gcp" "azure"
        "app" "webapp" "web-origin" "api-backend"
        "us-east" "us-west" "eu-west" "ap-southeast"
        "prod" "production" "prd"
    )

    for csub in "${CLOUD_SUBS[@]}"; do
        test_host="${csub}.${base_domain}"
        test_ip=$(dig +short A "$test_host" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")

        if [ -n "$test_ip" ] && ! is_cdn_ip "$test_ip" && ! echo "$current_ips" | grep -qF "$test_ip"; then
            echo "[MEDIUM] CLOUD SUBDOMAIN: ${test_host} -> ${test_ip}" >> "$FINDINGS_FILE"
            log "  ${YELLOW}[MEDIUM]${NC} Cloud pattern ${test_host} -> ${test_ip}"
            test_origin_ip "$test_ip" "$domain" "cloud:${test_host}"
        fi
    done

    # ═══════════════════════════════════════════════════════════
    # Test 8: SecurityTrails API (if SECURITYTRAILS_API_KEY set)
    # ═══════════════════════════════════════════════════════════
    if [ -n "${SECURITYTRAILS_API_KEY:-}" ]; then
        info "  Querying SecurityTrails DNS history..."

        st_resp=$(curl -sk --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" \
            -H "APIKEY: ${SECURITYTRAILS_API_KEY}" \
            "https://api.securitytrails.com/v1/history/${domain}/dns/a" 2>/dev/null || echo "")

        if [ -n "$st_resp" ]; then
            hist_ips=$(echo "$st_resp" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    ips = set()
    for record in data.get('records', []):
        for val in record.get('values', []):
            ip = val.get('ip', '')
            if ip:
                ips.add(ip)
    for ip in sorted(ips):
        print(ip)
except: pass
" 2>/dev/null || echo "")

            if [ -n "$hist_ips" ]; then
                echo "$hist_ips" | while IFS= read -r hist_ip; do
                    [ -z "$hist_ip" ] && continue
                    if ! is_cdn_ip "$hist_ip" && ! echo "$current_ips" | grep -qF "$hist_ip"; then
                        echo "[MEDIUM] DNS HISTORY: ${domain} -> ${hist_ip} (historical A record)" >> "$FINDINGS_FILE"
                        log "  ${YELLOW}[MEDIUM]${NC} Historical IP: ${hist_ip}"
                        test_origin_ip "$hist_ip" "$domain" "SecurityTrails"
                    fi
                done
            fi
        fi
    else
        info "  SecurityTrails: SECURITYTRAILS_API_KEY not set, skipping"
    fi

    # ═══════════════════════════════════════════════════════════
    # Test 9: Check TXT records for origin hints
    # ═══════════════════════════════════════════════════════════
    info "  Checking TXT records for origin hints..."

    txt_records=$(dig +short TXT "$domain" 2>/dev/null | tr -d '"')
    if [ -n "$txt_records" ]; then
        # Look for IPs in TXT records
        txt_ips=$(echo "$txt_records" | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if [ -n "$txt_ips" ]; then
            echo "$txt_ips" | while IFS= read -r txt_ip; do
                if ! is_cdn_ip "$txt_ip" && ! echo "$current_ips" | grep -qF "$txt_ip"; then
                    echo "[INFO] TXT RECORD IP: ${domain} TXT contains ${txt_ip}" >> "$FINDINGS_FILE"
                    test_origin_ip "$txt_ip" "$domain" "TXT_record"
                fi
            done
        fi

        # Look for hostname hints
        echo "$txt_records" | grep -oP '[\w.-]+\.[\w.-]+\.(com|net|org|io|cloud)' | head -5 | while IFS= read -r txt_host; do
            txt_host_ip=$(dig +short A "$txt_host" 2>/dev/null | head -1 | grep -P '^\d+\.\d+\.\d+\.\d+$' || echo "")
            if [ -n "$txt_host_ip" ] && ! is_cdn_ip "$txt_host_ip"; then
                echo "[INFO] TXT HOSTNAME: ${txt_host} -> ${txt_host_ip}" >> "$FINDINGS_FILE"
            fi
        done
    fi

done < "$DOMAIN_LIST"

# ── Cleanup ───────────────────────────────────────────────────
rm -f "$DOMAIN_LIST" "${OUT_DIR}/_ct_crt_domains_"*.txt

# ── Summary ───────────────────────────────────────────────────
if [ -s "$FINDINGS_FILE" ]; then
    sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"
fi
finding_count=$(count_lines "$FINDINGS_FILE")
high_count=$(grep -c '^\[HIGH\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)
info_count=$(grep -c '^\[INFO\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)

log "CDN/WAF bypass: ${finding_count} total findings"
log "  HIGH (confirmed origin IP):   ${high_count}"
log "  MEDIUM (potential origin):     ${medium_count}"
log "  INFO (DNS/record data):        ${info_count}"
log "Tested ${tested} domains"
if [ "$high_count" -gt 0 ]; then
    warn "Origin IPs discovered — direct access bypasses CDN/WAF protections"
    warn "Verify by comparing responses with and without CDN to confirm bypass"
fi
log "Results: ${FINDINGS_FILE}"
