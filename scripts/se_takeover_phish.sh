#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_takeover_phish.sh — Subdomain Takeover (Phishing Angle)  ║
# ║  Dangling CNAMEs on auth/login/sso/mail subdomains (Phase 9) ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_takeover_phish.sh"
SCRIPT_DESC="Subdomain Takeover (Phishing Surface)"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Check auth-related subdomains for dangling CNAMEs that could"
    echo "  be claimed for phishing. Prioritizes login, auth, sso, mail,"
    echo "  and support subdomains."
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

phase_header "9" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

# ── Build domain list ──
domains_list="${OUT_DIR}/se_takeover_domains.txt"
> "$domains_list"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$domains_list"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$domains_list"
fi
sort -u -o "$domains_list" "$domains_list"

findings_file="${OUT_DIR}/takeover_findings.txt"
> "$findings_file"

# ── Priority subdomain prefixes (phishing-relevant) ──
AUTH_PREFIXES=(
    "login" "auth" "sso" "oauth" "id" "identity" "accounts" "account"
    "signin" "signup" "register" "connect" "cas" "adfs" "saml"
)
MAIL_PREFIXES=(
    "mail" "email" "smtp" "imap" "pop" "webmail" "mx" "postfix"
    "exchange" "outlook" "mta"
)
SUPPORT_PREFIXES=(
    "support" "help" "helpdesk" "desk" "tickets" "service"
    "portal" "community" "forum" "feedback"
)
OTHER_PREFIXES=(
    "www" "app" "api" "cdn" "static" "assets" "docs" "dev"
    "staging" "stage" "stg" "qa" "test" "beta" "sandbox"
    "shop" "store" "pay" "payment" "billing" "checkout"
)

# ── Service fingerprints (reused from takeover_exploiter.sh) ──
declare -a FINGERPRINTS=(
    "amazonaws.com|NoSuchBucket|AWS S3|CLAIMABLE"
    "s3.amazonaws.com|NoSuchBucket|AWS S3|CLAIMABLE"
    "herokuapp.com|No such app|Heroku|CLAIMABLE"
    "herokudns.com|No such app|Heroku|CLAIMABLE"
    "github.io|There isn't a GitHub Pages site here|GitHub Pages|CLAIMABLE"
    "azurewebsites.net|404 Web Site not found|Azure|CLAIMABLE"
    "cloudapp.net|404 Web Site not found|Azure|CLAIMABLE"
    "azureedge.net|404 Not Found|Azure CDN|CLAIMABLE"
    "trafficmanager.net|404 Not Found|Azure TM|CLAIMABLE"
    "blob.core.windows.net|BlobNotFound|Azure Blob|CLAIMABLE"
    "shopify.com|Sorry, this shop is currently unavailable|Shopify|CLAIMABLE"
    "myshopify.com|Sorry, this shop is currently unavailable|Shopify|CLAIMABLE"
    "netlify.app|Not Found - Request ID|Netlify|CLAIMABLE"
    "netlify.com|Not Found - Request ID|Netlify|CLAIMABLE"
    "ghost.io|The thing you were looking for is no longer here|Ghost|CLAIMABLE"
    "pantheon.io|The gods are wise|Pantheon|CLAIMABLE"
    "tumblr.com|There's nothing here|Tumblr|CLAIMABLE"
    "wordpress.com|Do you want to register|WordPress.com|CLAIMABLE"
    "webflow.io|The page you are looking for doesn't exist|Webflow|CLAIMABLE"
    "surge.sh|project not found|Surge.sh|CLAIMABLE"
    "bitbucket.io|Repository not found|Bitbucket|CLAIMABLE"
    "zendesk.com|Help Center Closed|Zendesk|LIKELY_CLAIMABLE"
    "freshdesk.com|May not be configured|Freshdesk|LIKELY_CLAIMABLE"
    "statuspage.io|You are being redirected|StatusPage|LIKELY_CLAIMABLE"
    "cname.vercel-dns.com|DEPLOYMENT_NOT_FOUND|Vercel|CLAIMABLE"
    "vercel.app|DEPLOYMENT_NOT_FOUND|Vercel|CLAIMABLE"
    "unbounce.com|The requested URL was not found|Unbounce|CLAIMABLE"
    "uservoice.com|This UserVoice subdomain is currently available|UserVoice|CLAIMABLE"
    "helpjuice.com|We could not find what you're looking for|HelpJuice|CLAIMABLE"
    "helpscoutdocs.com|No settings were found for this company|HelpScout|CLAIMABLE"
)

# ── Generate target subdomains ──
target_subs="${OUT_DIR}/se_takeover_targets.txt"
> "$target_subs"

while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    for prefix in "${AUTH_PREFIXES[@]}" "${MAIL_PREFIXES[@]}" "${SUPPORT_PREFIXES[@]}" "${OTHER_PREFIXES[@]}"; do
        echo "${prefix}.${domain}" >> "$target_subs"
    done
done < "$domains_list"

# ── Add subdomains from subfinder if available ──
if check_tool "subfinder" 2>/dev/null; then
    info "Running subfinder for additional subdomain discovery..."
    subfinder_out="${OUT_DIR}/subfinder_se.txt"
    cat "$domains_list" | subfinder -silent -all 2>/dev/null > "$subfinder_out" || true
    if [ -s "$subfinder_out" ]; then
        # Filter to auth/mail/support-relevant subdomains
        grep -iP '^(login|auth|sso|oauth|id|identity|account|signin|signup|mail|email|webmail|support|help|portal|pay|checkout)\.' \
            "$subfinder_out" >> "$target_subs" || true
        log "subfinder added $(count_lines "$subfinder_out") subdomains"
    fi
fi

sort -u -o "$target_subs" "$target_subs"
total=$(count_lines "$target_subs")
log "Testing ${total} subdomains for takeover"

checked=0
dangling=0

while IFS= read -r subdomain; do
    [ -z "$subdomain" ] && continue
    ((checked++)) || true

    # ── DNS Resolution ──
    cname=$(dig +short CNAME "$subdomain" 2>/dev/null | head -1 | sed 's/\.$//')
    [ -z "$cname" ] && continue

    # Check if CNAME target resolves
    a_record=$(dig +short A "$cname" 2>/dev/null | head -1)

    # ── NXDOMAIN check ──
    is_dangling=false
    if [ -z "$a_record" ]; then
        # CNAME exists but target doesn't resolve — dangling
        nxdomain_check=$(dig "$cname" 2>/dev/null | grep -c "NXDOMAIN" || true)
        if [ "$nxdomain_check" -gt 0 ]; then
            is_dangling=true
        fi
    fi

    # ── Service fingerprint check ──
    service_match=""
    confidence=""
    for fp in "${FINGERPRINTS[@]}"; do
        IFS='|' read -r cname_pattern http_pattern service_name conf <<< "$fp"
        if echo "$cname" | grep -qi "$cname_pattern"; then
            # Match found — check HTTP fingerprint
            body=$(curl -sk --max-time 8 "${HUNT_UA_CURL[@]}" "https://${subdomain}" 2>/dev/null || \
                   curl -sk --max-time 8 "${HUNT_UA_CURL[@]}" "http://${subdomain}" 2>/dev/null || true)

            if [ -n "$body" ] && echo "$body" | grep -qi "$http_pattern"; then
                service_match="$service_name"
                confidence="$conf"
                is_dangling=true
                break
            elif $is_dangling; then
                service_match="$service_name"
                confidence="LIKELY_CLAIMABLE"
                break
            fi
        fi
    done

    if $is_dangling; then
        ((dangling++)) || true

        # ── Impact classification based on subdomain type ──
        impact="MEDIUM"
        prefix=$(echo "$subdomain" | cut -d. -f1)
        if echo "$prefix" | grep -qiP '^(login|auth|sso|oauth|id|identity|account|signin|cas|adfs|saml)$'; then
            impact="CRITICAL"
        elif echo "$prefix" | grep -qiP '^(mail|email|webmail|smtp|exchange|outlook)$'; then
            impact="HIGH"
        elif echo "$prefix" | grep -qiP '^(support|help|helpdesk|portal|pay|payment|billing|checkout)$'; then
            impact="HIGH"
        fi

        severity="P3"
        [ "$impact" = "CRITICAL" ] && severity="P1"
        [ "$impact" = "HIGH" ] && severity="P2"

        service_info=""
        if [ -n "$service_match" ]; then
            service_info=" | service:${service_match} confidence:${confidence}"
        fi

        echo "[${severity}:TAKEOVER:${confidence:-DANGLING}] ${subdomain} -> ${cname}${service_info} | impact:${impact}" >> "$findings_file"
    fi

    [ $((checked % 50)) -eq 0 ] && info "Checked ${checked}/${total} subdomains (${dangling} dangling)..."
done < "$target_subs"

# ── Nuclei takeover templates ──
if check_tool "nuclei" 2>/dev/null && [ -s "$target_subs" ]; then
    info "Running nuclei takeover templates..."
    nuclei_to="${OUT_DIR}/nuclei_se_takeover.txt"
    nuclei -l "$target_subs" -tags takeover -silent \
        "${HUNT_UA_ARGS[@]}" 2>/dev/null > "$nuclei_to" || true
    if [ -s "$nuclei_to" ]; then
        while IFS= read -r line; do
            echo "[P2:TAKEOVER:NUCLEI] ${line}" >> "$findings_file"
        done < "$nuclei_to"
        log "Nuclei takeover findings: $(count_lines "$nuclei_to")"
    fi
fi

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
log "Checked: ${checked} subdomains"
log "Dangling CNAMEs: ${dangling}"
log "Takeover findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "Subdomain takeover opportunities:"
    cat "$findings_file"
fi
