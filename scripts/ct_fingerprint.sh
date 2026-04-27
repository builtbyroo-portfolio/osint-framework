#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_fingerprint.sh — CDN & Cache Fingerprinting              ║
# ║  Detect CDN provider, cache behavior, Vary headers, Age      ║
# ║  progression → ct_cdn_profile.txt + ct_cache_behavior.txt    ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_fingerprint.sh"
SCRIPT_DESC="CDN & Cache Fingerprinting"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Fingerprint CDN provider, cache layers, and caching behavior."
    echo "  Identifies Cloudflare, Akamai, Fastly, Varnish, CloudFront,"
    echo "  Imperva/Incapsula, Sucuri, and others from response headers."
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

phase_header "1" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

# ── Build domain list ─────────────────────────────────────────
DOMAIN_LIST="${OUT_DIR}/_ct_fp_domains.txt"
> "$DOMAIN_LIST"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$DOMAIN_LIST"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$DOMAIN_LIST"
fi
sort -u -o "$DOMAIN_LIST" "$DOMAIN_LIST"

domain_count=$(count_lines "$DOMAIN_LIST")
info "Fingerprinting ${domain_count} domain(s)"

# ── Output files ──────────────────────────────────────────────
CDN_PROFILE="${OUT_DIR}/ct_cdn_profile.txt"
CACHE_BEHAVIOR="${OUT_DIR}/ct_cache_behavior.txt"
FINDINGS_FILE="${OUT_DIR}/ct_fingerprint_findings.txt"
> "$CDN_PROFILE"
> "$CACHE_BEHAVIOR"
> "$FINDINGS_FILE"

# ── Common cacheable test paths ───────────────────────────────
CACHE_PATHS=("/" "/robots.txt" "/favicon.ico" "/about" "/index.html" "/sitemap.xml")

# ── CDN detection from headers ────────────────────────────────
detect_cdn() {
    local headers="$1"
    local cdn="unknown"

    # Cloudflare
    if echo "$headers" | grep -qi 'cf-cache-status\|cf-ray\|server:[[:space:]]*cloudflare'; then
        cdn="cloudflare"
    # Akamai
    elif echo "$headers" | grep -qi 'x-akamai-\|akamai\|x-cache.*akamai'; then
        cdn="akamai"
    # Fastly
    elif echo "$headers" | grep -qi 'x-served-by.*cache-\|x-cache.*fastly\|fastly-debug\|via.*varnish.*fastly\|x-fastly'; then
        cdn="fastly"
    # CloudFront
    elif echo "$headers" | grep -qi 'x-amz-cf-\|x-cache.*cloudfront\|via.*cloudfront\|x-amz-cf-pop\|x-amz-cf-id'; then
        cdn="cloudfront"
    # Imperva / Incapsula
    elif echo "$headers" | grep -qi 'x-iinfo\|incap_ses\|visid_incap\|x-cdn.*imperva\|x-cdn.*incapsula'; then
        cdn="imperva"
    # Sucuri
    elif echo "$headers" | grep -qi 'x-sucuri-\|server:[[:space:]]*sucuri\|x-sucuri-id'; then
        cdn="sucuri"
    # Varnish (generic, not Fastly)
    elif echo "$headers" | grep -qi 'via.*varnish\|x-varnish\|x-cache.*varnish'; then
        cdn="varnish"
    # Azure CDN
    elif echo "$headers" | grep -qi 'x-msedge-ref\|x-azure-ref\|x-ec-debug'; then
        cdn="azure_cdn"
    # Google Cloud CDN
    elif echo "$headers" | grep -qi 'via.*google\|x-goog-\|server:[[:space:]]*gws'; then
        cdn="google_cdn"
    # KeyCDN
    elif echo "$headers" | grep -qi 'server:[[:space:]]*keycdn\|x-edge-\|x-shield'; then
        cdn="keycdn"
    # StackPath / MaxCDN
    elif echo "$headers" | grep -qi 'x-hw:\|server:[[:space:]]*netdna\|x-cdn.*stackpath'; then
        cdn="stackpath"
    # Edgecast / Verizon
    elif echo "$headers" | grep -qi 'server:[[:space:]]*ecs\|x-ec-debug\|x-cache.*ecs'; then
        cdn="edgecast"
    fi

    echo "$cdn"
}

# ── Extract cache status from headers ─────────────────────────
extract_cache_status() {
    local headers="$1"
    local status="none"

    # Cloudflare cache status
    local cf_status
    cf_status=$(echo "$headers" | grep -i '^cf-cache-status:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -n "$cf_status" ]; then
        echo "CF:${cf_status}"
        return
    fi

    # Standard X-Cache header
    local xcache
    xcache=$(echo "$headers" | grep -i '^x-cache:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -n "$xcache" ]; then
        echo "X-Cache:${xcache}"
        return
    fi

    # X-Cache-Hits (Varnish/Fastly)
    local xcache_hits
    xcache_hits=$(echo "$headers" | grep -i '^x-cache-hits:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -n "$xcache_hits" ]; then
        echo "X-Cache-Hits:${xcache_hits}"
        return
    fi

    # Cache-Status (RFC 9211)
    local cache_status
    cache_status=$(echo "$headers" | grep -i '^cache-status:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -n "$cache_status" ]; then
        echo "Cache-Status:${cache_status}"
        return
    fi

    echo "$status"
}

# ── Main fingerprinting loop ─────────────────────────────────
while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    info "Analyzing: ${domain}"

    cdn="" cache_info="" vary_header="" age_header="" server_header=""
    cc_header="" pragma_header="" etag_header="" last_modified=""

    # ── Fetch full response headers from main page ──
    headers=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "https://${domain}/" 2>/dev/null || \
        curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "http://${domain}/" 2>/dev/null || echo "")

    if [ -z "$headers" ]; then
        warn "  No response from ${domain}"
        continue
    fi

    # ── CDN Detection ──
    cdn=$(detect_cdn "$headers")
    log "  CDN: ${cdn}"

    # ── Extract key cache headers ──
    server_header=$(echo "$headers" | grep -i '^server:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    vary_header=$(echo "$headers" | grep -i '^vary:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    age_header=$(echo "$headers" | grep -i '^age:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    cc_header=$(echo "$headers" | grep -i '^cache-control:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    pragma_header=$(echo "$headers" | grep -i '^pragma:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    etag_header=$(echo "$headers" | grep -i '^etag:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    last_modified=$(echo "$headers" | grep -i '^last-modified:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    cache_info=$(extract_cache_status "$headers")

    # ── Via header (reveals proxy chain) ──
    via_header=$(echo "$headers" | grep -i '^via:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')

    # ── X-Served-By (Fastly POP identification) ──
    served_by=$(echo "$headers" | grep -i '^x-served-by:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')

    # ── Build CDN profile ──
    {
        echo "══════ ${domain} ══════"
        echo "CDN: ${cdn}"
        echo "Server: ${server_header:-n/a}"
        echo "Cache-Status: ${cache_info}"
        echo "Cache-Control: ${cc_header:-n/a}"
        echo "Vary: ${vary_header:-n/a}"
        echo "Age: ${age_header:-n/a}"
        echo "ETag: ${etag_header:-n/a}"
        echo "Last-Modified: ${last_modified:-n/a}"
        echo "Pragma: ${pragma_header:-n/a}"
        echo "Via: ${via_header:-n/a}"
        echo "X-Served-By: ${served_by:-n/a}"
        echo ""
    } >> "$CDN_PROFILE"

    # ── Vary header analysis (cache key composition) ──
    if [ -n "$vary_header" ]; then
        log "  Vary: ${vary_header}"
        # Check for dangerous Vary configurations
        if echo "$vary_header" | grep -qi 'user-agent'; then
            echo "[INFO] ${domain} Vary includes User-Agent — cache splits by UA (larger attack surface)" >> "$FINDINGS_FILE"
        fi
        if echo "$vary_header" | grep -qi 'cookie'; then
            echo "[INFO] ${domain} Vary includes Cookie — cache keys on cookies" >> "$FINDINGS_FILE"
        fi
        if [ "$vary_header" = "*" ]; then
            echo "[INFO] ${domain} Vary: * — caching should be disabled" >> "$FINDINGS_FILE"
        fi
        # Check for headers NOT in Vary (potential unkeyed headers)
        if ! echo "$vary_header" | grep -qi 'accept-encoding\|accept'; then
            echo "[NOTE] ${domain} Vary does NOT include Accept-Encoding — potential cache key gap" >> "$FINDINGS_FILE"
        fi
    else
        echo "[NOTE] ${domain} No Vary header — all requests may share same cache entry" >> "$FINDINGS_FILE"
    fi

    # ── Test cacheability per path ──
    info "  Testing cache behavior across paths..."
    for path in "${CACHE_PATHS[@]}"; do
        url="https://${domain}${path}"
        cacheable="unknown"
        path_cache_status=""

        # First request (prime)
        resp1=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "")
        [ -z "$resp1" ] && continue

        http_status=$(echo "$resp1" | head -1 | grep -oP '\d{3}' | head -1)
        [ -z "$http_status" ] && continue
        [ "$http_status" = "000" ] && continue

        path_cache_status=$(extract_cache_status "$resp1")
        path_cc=$(echo "$resp1" | grep -i '^cache-control:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        path_age=$(echo "$resp1" | grep -i '^age:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')

        # Determine cacheability
        if echo "$path_cache_status" | grep -qiP '(HIT|STALE|REVALIDATED)'; then
            cacheable="CACHED"
        elif echo "$path_cache_status" | grep -qiP '(MISS|EXPIRED)'; then
            cacheable="CACHEABLE"
        elif echo "$path_cache_status" | grep -qiP '(BYPASS|DYNAMIC)'; then
            cacheable="NOT_CACHED"
        elif echo "$path_cc" | grep -qiP '(no-cache|no-store|private)'; then
            cacheable="NOT_CACHED"
        elif echo "$path_cc" | grep -qiP '(public|max-age|s-maxage)'; then
            cacheable="CACHEABLE"
        fi

        echo "${domain}${path} | HTTP:${http_status} | Cache:${path_cache_status} | CC:${path_cc:-n/a} | Age:${path_age:-n/a} | ${cacheable}" >> "$CACHE_BEHAVIOR"
    done

    # ── Age header progression (detect active caching) ──
    info "  Testing Age header progression..."
    age_test_url="https://${domain}/robots.txt"
    age_values=()
    for i in 1 2 3; do
        resp=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$age_test_url" 2>/dev/null || echo "")
        age_val=$(echo "$resp" | grep -i '^age:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        if [ -n "$age_val" ]; then
            age_values+=("$age_val")
        fi
        [ "$i" -lt 3 ] && sleep 1
    done

    if [ "${#age_values[@]}" -ge 2 ]; then
        age_str="${age_values[*]}"
        echo "${domain} Age progression (/robots.txt): ${age_str}" >> "$CACHE_BEHAVIOR"
        # If age is incrementing, the response is actively cached
        if [ "${#age_values[@]}" -ge 2 ] && [ "${age_values[0]}" -lt "${age_values[1]}" ] 2>/dev/null; then
            echo "[INFO] ${domain} Active caching detected — Age header incrementing (${age_str})" >> "$FINDINGS_FILE"
        fi
    fi

    # ── Test with Cache-Control request headers ──
    info "  Testing server respect for client cache directives..."
    for directive in "no-cache" "no-store" "max-age=0"; do
        resp=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" -H "Cache-Control: ${directive}" \
            "https://${domain}/" 2>/dev/null || echo "")
        [ -z "$resp" ] && continue

        resp_cc=$(echo "$resp" | grep -i '^cache-control:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        resp_cache=$(extract_cache_status "$resp")

        echo "${domain} Client CC:${directive} -> Server CC:${resp_cc:-n/a} Cache:${resp_cache}" >> "$CACHE_BEHAVIOR"

        # If server still returns HIT despite no-cache, cache ignores client directives
        if echo "$resp_cache" | grep -qiP '(HIT)' && [ "$directive" = "no-cache" ]; then
            echo "[MEDIUM] ${domain} Cache ignores client Cache-Control: no-cache — still returns HIT" >> "$FINDINGS_FILE"
        fi
    done

    # ── Pragma: no-cache test ──
    resp=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" -H "Pragma: no-cache" \
        "https://${domain}/" 2>/dev/null || echo "")
    if [ -n "$resp" ]; then
        resp_cache=$(extract_cache_status "$resp")
        if echo "$resp_cache" | grep -qiP '(HIT)'; then
            echo "[INFO] ${domain} Cache ignores Pragma: no-cache header" >> "$FINDINGS_FILE"
        fi
    fi

    # ── Cache-Status (RFC 9211) presence ──
    rfc_cs=$(echo "$headers" | grep -i '^cache-status:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -n "$rfc_cs" ]; then
        echo "[INFO] ${domain} Uses RFC 9211 Cache-Status header: ${rfc_cs}" >> "$FINDINGS_FILE"
    fi

    # ── CDN-specific fingerprinting findings ──
    case "$cdn" in
        cloudflare)
            cf_ray=$(echo "$headers" | grep -i '^cf-ray:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
            [ -n "$cf_ray" ] && echo "[INFO] ${domain} Cloudflare POP: ${cf_ray}" >> "$FINDINGS_FILE"
            ;;
        fastly)
            [ -n "$served_by" ] && echo "[INFO] ${domain} Fastly POP chain: ${served_by}" >> "$FINDINGS_FILE"
            ;;
        akamai)
            akamai_ref=$(echo "$headers" | grep -i '^x-akamai-\|^x-true-cache-key:' | head -3 | tr '\r\n' ' ')
            [ -n "$akamai_ref" ] && echo "[INFO] ${domain} Akamai headers: ${akamai_ref}" >> "$FINDINGS_FILE"
            ;;
        cloudfront)
            amz_id=$(echo "$headers" | grep -i '^x-amz-cf-id:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
            [ -n "$amz_id" ] && echo "[INFO] ${domain} CloudFront request ID: ${amz_id}" >> "$FINDINGS_FILE"
            ;;
    esac

done < "$DOMAIN_LIST"

# ── Cleanup ───────────────────────────────────────────────────
rm -f "$DOMAIN_LIST"

# ── Summary ───────────────────────────────────────────────────
profile_count=$(count_lines "$CDN_PROFILE")
behavior_count=$(count_lines "$CACHE_BEHAVIOR")
finding_count=$(count_lines "$FINDINGS_FILE")

log "CDN profiles: ${profile_count} lines"
log "Cache behavior tests: ${behavior_count} lines"
log "Fingerprint findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    info "Notable findings:"
    grep '^\[MEDIUM\]' "$FINDINGS_FILE" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
log "CDN profile: ${CDN_PROFILE}"
log "Cache behavior: ${CACHE_BEHAVIOR}"
log "Findings: ${FINDINGS_FILE}"
