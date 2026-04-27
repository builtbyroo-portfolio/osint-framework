#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_surface_map.sh — SE Surface Mapping                      ║
# ║  Login/form/OAuth endpoint discovery (Phase 1)               ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_surface_map.sh"
SCRIPT_DESC="SE Surface Mapping"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover login, registration, password reset, OAuth, and"
    echo "  other SE-relevant endpoints. Produces surface_urls.txt,"
    echo "  sensitive_urls.txt, and oauth_urls.txt for downstream phases."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Primary target domain"
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

# ── Build domain list ──
domains_list="${OUT_DIR}/se_domains_clean.txt"
> "$domains_list"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$domains_list"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$domains_list"
fi
sort -u -o "$domains_list" "$domains_list"

domain_count=$(count_lines "$domains_list")
log "Target domains: ${domain_count}"

# ── Output files ──
surface_file="${OUT_DIR}/surface_urls.txt"
sensitive_file="${OUT_DIR}/sensitive_urls.txt"
oauth_file="${OUT_DIR}/oauth_urls.txt"
whatweb_file="${OUT_DIR}/whatweb_results.txt"
> "$surface_file"
> "$sensitive_file"
> "$oauth_file"
> "$whatweb_file"

# ── Common SE-relevant paths ──
# Login / auth / registration / password reset / invite / OAuth / SSO
SE_PATHS=(
    "login" "signin" "sign-in" "sign_in" "auth" "authenticate"
    "register" "signup" "sign-up" "sign_up" "join" "create-account"
    "forgot-password" "forgot_password" "reset-password" "reset_password"
    "password/reset" "account/recover" "account/recovery"
    "logout" "signout" "sign-out"
    "oauth" "oauth/authorize" "oauth2/authorize" "oauth/callback"
    "auth/callback" "login/callback" "connect/authorize"
    "sso" "sso/login" "saml/login" "saml2/login" "cas/login"
    ".well-known/openid-configuration" ".well-known/oauth-authorization-server"
    "api/auth" "api/login" "api/register" "api/oauth"
    "account" "account/settings" "account/security" "profile"
    "settings" "settings/security" "settings/password"
    "admin" "admin/login" "administrator"
    "invite" "invitation" "onboarding"
    "verify" "verify-email" "confirm" "activate"
    "2fa" "mfa" "two-factor" "totp"
    "unsubscribe" "preferences" "consent"
)

# ── Probe endpoints per domain ──
info "Probing ~${#SE_PATHS[@]} SE-relevant paths per domain..."

while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    info "Scanning: ${domain}"

    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"

        # Check if base URL is live first
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        for path in "${SE_PATHS[@]}"; do
            test_url="${base_url}/${path}"
            response=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "000|0|")
            status=$(echo "$response" | cut -d'|' -f1)
            size=$(echo "$response" | cut -d'|' -f2)
            redirect=$(echo "$response" | cut -d'|' -f3)

            # Alive endpoints (200, 301, 302, 401, 403)
            if [[ "$status" =~ ^(200|301|302|303|307|401|403)$ ]]; then
                echo "$test_url" >> "$surface_file"

                # Classify as sensitive (forms that change state)
                case "$path" in
                    login|signin|sign-in|sign_in|register|signup|sign-up|sign_up|forgot-password|forgot_password|reset-password|reset_password|password/reset|account/recover|account/recovery|account/settings|account/security|settings|settings/security|settings/password|2fa|mfa|two-factor|admin|admin/login|unsubscribe|consent)
                        echo "$test_url" >> "$sensitive_file"
                        ;;
                esac

                # Classify as OAuth/SSO
                case "$path" in
                    oauth|oauth/authorize|oauth2/authorize|oauth/callback|auth/callback|login/callback|connect/authorize|sso|sso/login|saml/login|saml2/login|cas/login|.well-known/openid-configuration|.well-known/oauth-authorization-server|api/oauth)
                        echo "$test_url" >> "$oauth_file"
                        ;;
                esac

                # If redirect points to OAuth provider, capture that too
                if [ -n "$redirect" ] && echo "$redirect" | grep -qiP '(oauth|authorize|openid|saml|sso)'; then
                    echo "$redirect" >> "$oauth_file"
                fi
            fi
        done

        # Only probe one working scheme per domain
        [ "$base_status" != "000" ] && break
    done
done < "$domains_list"

# ── Extract OAuth parameters from discovered pages ──
info "Extracting OAuth parameters from login/auth pages..."
if [ -s "$oauth_file" ]; then
    oauth_params_file="${OUT_DIR}/oauth_params.txt"
    > "$oauth_params_file"
    while IFS= read -r url; do
        page_content=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || true)
        [ -z "$page_content" ] && continue

        # Extract client_id, redirect_uri, scope from page content
        echo "$page_content" | grep -oP 'client_id[=:]["'"'"']?\K[^"'"'"'&\s]+' | while read -r cid; do
            echo "CLIENT_ID: ${cid} (from ${url})" >> "$oauth_params_file"
        done
        echo "$page_content" | grep -oP 'redirect_uri[=:]["'"'"']?\K[^"'"'"'&\s]+' | while read -r ruri; do
            echo "REDIRECT_URI: ${ruri} (from ${url})" >> "$oauth_params_file"
        done
        echo "$page_content" | grep -oP 'scope[=:]["'"'"']?\K[^"'"'"'&\s]+' | while read -r scope; do
            echo "SCOPE: ${scope} (from ${url})" >> "$oauth_params_file"
        done
    done < <(head -20 "$oauth_file")
    param_count=$(count_lines "$oauth_params_file")
    if [ "$param_count" -gt 0 ]; then
        log "Extracted ${param_count} OAuth parameters"
    fi
fi

# ── WhatWeb fingerprinting on sensitive URLs ──
if check_tool "whatweb" 2>/dev/null; then
    info "Running WhatWeb fingerprinting on sensitive endpoints..."
    if [ -s "$sensitive_file" ]; then
        head -20 "$sensitive_file" | while IFS= read -r url; do
            whatweb --no-errors -q --color=never "$url" 2>/dev/null >> "$whatweb_file" || true
        done
    fi
    log "WhatWeb results: ${whatweb_file}"
fi

# ── Katana crawl for additional auth-related URLs ──
if check_tool "katana" 2>/dev/null && [ -s "$surface_file" ]; then
    info "Running Katana crawler on surface URLs (depth 2)..."
    katana_out="${OUT_DIR}/katana_se_urls.txt"
    head -10 "$surface_file" | katana -silent -depth 2 -jc -kf all \
        -f qurl "${HUNT_UA_ARGS[@]}" 2>/dev/null | sort -u > "$katana_out" || true

    if [ -s "$katana_out" ]; then
        # Extract auth-related URLs from crawl
        grep -iP '(login|auth|oauth|sso|register|signup|reset|password|account|session|token|callback|redirect|consent|approve|grant)' \
            "$katana_out" >> "$surface_file" || true
        grep -iP '(oauth|authorize|callback|redirect_uri|client_id|response_type|state=|code=|token=)' \
            "$katana_out" >> "$oauth_file" || true
        log "Katana added $(count_lines "$katana_out") crawled URLs"
    fi
fi

# ── httpx probing for live status + tech detection ──
if check_tool "httpx-pd" 2>/dev/null && [ -s "$surface_file" ]; then
    info "Running httpx-pd tech detection on surface URLs..."
    httpx_out="${OUT_DIR}/surface_httpx.txt"
    cat "$surface_file" | sort -u | httpx-pd -silent -status-code -content-length -tech-detect \
        -threads "$THREADS" "${HUNT_UA_ARGS[@]}" 2>/dev/null > "$httpx_out" || true
    log "httpx results: ${httpx_out}"
fi

# ── Dedup all output files ──
for f in "$surface_file" "$sensitive_file" "$oauth_file"; do
    if [ -s "$f" ]; then
        sort -u -o "$f" "$f"
    fi
done

# ── Summary ──
log "Surface URLs: $(count_lines "$surface_file")"
log "Sensitive URLs: $(count_lines "$sensitive_file")"
log "OAuth/SSO URLs: $(count_lines "$oauth_file")"
if [ -s "$whatweb_file" ]; then
    log "WhatWeb results: $(count_lines "$whatweb_file") entries"
fi
log "Surface mapping complete — downstream phases can now consume these files"
