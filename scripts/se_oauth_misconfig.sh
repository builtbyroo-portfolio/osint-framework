#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_oauth_misconfig.sh — OAuth/SSO Misconfiguration          ║
# ║  redirect_uri bypass, state, PKCE, implicit flow (Phase 8)  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_oauth_misconfig.sh"
SCRIPT_DESC="OAuth/SSO Misconfiguration"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test OAuth endpoints for misconfigurations:"
    echo "  - redirect_uri validation bypass"
    echo "  - Missing state parameter (CSRF in OAuth)"
    echo "  - Missing PKCE on public clients"
    echo "  - Implicit flow (response_type=token)"
    echo "  - OpenID configuration exposure"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with OAuth URLs (from Phase 1)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "8" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

urls_input="${URLS_FILE:-${OUT_DIR}/oauth_urls.txt}"
findings_file="${OUT_DIR}/oauth_findings.txt"
detail_file="${OUT_DIR}/oauth_detail.txt"
> "$findings_file"
> "$detail_file"

target_domain="${DOMAIN:-}"

# ── Build domain list for well-known checks ──
domains_list="${OUT_DIR}/se_oauth_domains.txt"
> "$domains_list"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$domains_list"
fi
if [ -n "$target_domain" ]; then
    echo "$target_domain" >> "$domains_list"
fi
sort -u -o "$domains_list" "$domains_list"

# ── Check 1: OpenID Configuration Exposure ──
info "Checking for OpenID/OAuth configuration endpoints..."
while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    for scheme in "https" "http"; do
        for path in ".well-known/openid-configuration" ".well-known/oauth-authorization-server" "oauth/.well-known/openid-configuration"; do
            config_url="${scheme}://${domain}/${path}"
            response=$(curl -sk --max-time 8 "${HUNT_UA_CURL[@]}" "$config_url" 2>/dev/null || true)
            [ -z "$response" ] && continue

            if echo "$response" | grep -qP '"(authorization_endpoint|issuer|token_endpoint)"'; then
                echo "OPENID_CONFIG: ${config_url}" >> "$detail_file"
                echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for k in ['issuer','authorization_endpoint','token_endpoint','userinfo_endpoint','jwks_uri','scopes_supported','response_types_supported','grant_types_supported']:
        if k in d:
            print(f'  {k}: {d[k]}')
except: pass
" >> "$detail_file" 2>/dev/null || true

                # Extract authorization endpoint for further testing
                auth_endpoint=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('authorization_endpoint',''))" 2>/dev/null || true)
                if [ -n "$auth_endpoint" ]; then
                    echo "$auth_endpoint" >> "$urls_input" 2>/dev/null || true
                fi

                # Check if implicit flow is supported
                if echo "$response" | grep -qP '"token"'; then
                    echo "[P3:OAUTH:IMPLICIT_FLOW_SUPPORTED] ${config_url} | response_types_supported includes 'token'" >> "$findings_file"
                fi

                log "OpenID config found: ${config_url}"
                break 2  # One scheme is enough
            fi
        done
    done
done < "$domains_list"

# ── Load OAuth params from Phase 1 ──
oauth_params="${OUT_DIR}/oauth_params.txt"
client_ids=()
redirect_uris=()
if [ -f "$oauth_params" ]; then
    while IFS= read -r line; do
        if [[ "$line" =~ ^CLIENT_ID:\ (.+)\ \(from ]]; then
            client_ids+=("${BASH_REMATCH[1]}")
        fi
        if [[ "$line" =~ ^REDIRECT_URI:\ (.+)\ \(from ]]; then
            redirect_uris+=("${BASH_REMATCH[1]}")
        fi
    done < "$oauth_params"
fi

# ── Check 2: redirect_uri Validation ──
if [ -s "$urls_input" ]; then
    info "Testing redirect_uri validation on OAuth endpoints..."

    while IFS= read -r url; do
        [ -z "$url" ] && continue

        # Skip non-OAuth URLs
        echo "$url" | grep -qiP '(oauth|authorize|auth/callback|sso|connect)' || continue

        echo "── Testing: ${url} ──" >> "$detail_file"

        # Build test URLs with manipulated redirect_uri
        base_redir=""
        if [ ${#redirect_uris[@]} -gt 0 ]; then
            base_redir="${redirect_uris[0]}"
        fi

        # redirect_uri bypass payloads
        bypass_payloads=(
            "https://evil.com"
            "https://evil.com@${target_domain}"
            "https://${target_domain}.evil.com"
            "https://evil.com/${target_domain}"
            "https://${target_domain}%40evil.com"
            "https://${target_domain}/../evil.com"
        )

        for payload in "${bypass_payloads[@]}"; do
            # If URL already has redirect_uri, replace it
            if echo "$url" | grep -qi 'redirect_uri='; then
                test_url=$(echo "$url" | sed -E "s|redirect_uri=[^&]*|redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null || echo "$payload")|")
            else
                separator="?"
                echo "$url" | grep -q '?' && separator="&"
                test_url="${url}${separator}redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null || echo "$payload")"
            fi

            response=$(curl -sk -D- -o /dev/null --max-time 10 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || true)
            [ -z "$response" ] && continue

            http_code=$(echo "$response" | head -1 | grep -oP '\d{3}' | head -1)
            location=$(echo "$response" | grep -i '^Location:' | head -1 | tr -d '\r' | awk '{print $2}')

            # Check if redirect accepted the malicious URI
            if [ -n "$location" ] && echo "$location" | grep -qi "evil.com"; then
                echo "[P2:OAUTH:REDIRECT_URI_BYPASS] ${test_url} -> ${location} | payload: ${payload}" >> "$findings_file"
                echo "REDIRECT_URI_BYPASS: ${payload} -> ${location}" >> "$detail_file"
                break  # One bypass per endpoint is enough
            fi

            # Check if server returned 200 (accepted the redirect_uri without redirect)
            if [ "$http_code" = "200" ]; then
                body=$(curl -sk --max-time 8 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || true)
                if echo "$body" | grep -qi "evil.com"; then
                    echo "[P3:OAUTH:REDIRECT_URI_REFLECTED] ${test_url} | redirect_uri reflected in page" >> "$findings_file"
                    break
                fi
            fi
        done

        # ── Check 3: Missing state parameter ──
        # If the OAuth URL lacks a state parameter, CSRF in OAuth is possible
        if ! echo "$url" | grep -qi 'state='; then
            # Verify by making request and checking if state is required
            response=$(curl -sk -D- --max-time 10 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || true)
            http_code=$(echo "$response" | head -1 | grep -oP '\d{3}' | head -1)

            # If it proceeds without state parameter (not error/redirect to error)
            if [[ "$http_code" =~ ^(200|301|302)$ ]] && ! echo "$response" | grep -qi "state.*required\|missing.*state"; then
                echo "[P3:OAUTH:NO_STATE] ${url} | OAuth flow accepts requests without state parameter (CSRF)" >> "$findings_file"
            fi
        fi

        # ── Check 4: Implicit flow (response_type=token) ──
        if echo "$url" | grep -qi 'authorize'; then
            separator="?"
            echo "$url" | grep -q '?' && separator="&"
            implicit_url="${url}${separator}response_type=token"
            response=$(curl -sk -D- -o /dev/null --max-time 10 "${HUNT_UA_CURL[@]}" "$implicit_url" 2>/dev/null || true)
            http_code=$(echo "$response" | head -1 | grep -oP '\d{3}' | head -1)

            if [[ "$http_code" =~ ^(200|302)$ ]] && ! echo "$response" | grep -qi "unsupported_response_type\|invalid.*response_type"; then
                echo "[P3:OAUTH:IMPLICIT_FLOW] ${implicit_url} | Implicit flow (response_type=token) accepted — token in URL fragment" >> "$findings_file"
            fi
        fi

    done < <(sort -u "$urls_input" | head -20)
fi

# ── Check 5: PKCE enforcement ──
info "Checking PKCE enforcement..."
if [ -s "$urls_input" ]; then
    while IFS= read -r url; do
        echo "$url" | grep -qiP '(oauth|authorize)' || continue

        # Try auth request without code_challenge
        separator="?"
        echo "$url" | grep -q '?' && separator="&"
        no_pkce_url="${url}${separator}response_type=code"

        response=$(curl -sk -D- --max-time 10 "${HUNT_UA_CURL[@]}" "$no_pkce_url" 2>/dev/null || true)
        if ! echo "$response" | grep -qi "code_challenge.*required\|pkce.*required"; then
            http_code=$(echo "$response" | head -1 | grep -oP '\d{3}' | head -1)
            if [[ "$http_code" =~ ^(200|302)$ ]]; then
                echo "PKCE_NOT_REQUIRED: ${url}" >> "$detail_file"
                # Only flag as finding for public clients (no client_secret)
            fi
        fi
        break  # One check per hunt
    done < <(sort -u "$urls_input")
fi

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
log "OAuth/SSO findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "OAuth misconfigurations found:"
    cat "$findings_file"
fi
log "Detailed analysis: ${detail_file}"
