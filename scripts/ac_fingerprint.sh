#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_fingerprint.sh — Technology Fingerprinting               ║
# ║  WhatWeb + header analysis → tech_profile.txt + wordlists   ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_fingerprint.sh"
SCRIPT_DESC="Technology Fingerprinting"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Fingerprint target technologies to drive CMS-specific wordlist selection."
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

# Build domain list
DOMAIN_LIST="${OUT_DIR}/_ac_fp_domains.txt"
> "$DOMAIN_LIST"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" >> "$DOMAIN_LIST"
elif [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" >> "$DOMAIN_LIST"
fi

> "${OUT_DIR}/tech_profile.txt"
> "${OUT_DIR}/ac_cms_wordlists.txt"
mkdir -p "${OUT_DIR}/fingerprint"

CMS_DIR="${SECLISTS}/Discovery/Web-Content/CMS"
TRICKEST_DIR="${SECLISTS}/Discovery/Web-Content/CMS/trickest-cms-wordlist"

# ── WhatWeb scan ──
if check_tool whatweb 2>/dev/null; then
    info "Running WhatWeb fingerprinting..."
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        local_out="${OUT_DIR}/fingerprint/${domain}_whatweb.json"

        whatweb -q --log-json="$local_out" "https://${domain}" 2>/dev/null || \
        whatweb -q --log-json="$local_out" "http://${domain}" 2>/dev/null || true

        if [ -s "$local_out" ]; then
            # Extract tech identifiers from WhatWeb JSON
            techs=$(python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    if isinstance(data, list): data = data[0] if data else {}
    plugins = data.get('plugins', {})
    techs = []
    for name, info in plugins.items():
        n = name.lower()
        if n in ('ip','country','httpserver','html','title','uncommonheaders','cookies','x-powered-by','meta-generator','script','frame','email','passwordfield'): continue
        ver = ''
        if isinstance(info, dict) and info.get('version'):
            v = info['version']
            ver = v[0] if isinstance(v,list) else str(v)
        techs.append(f'{name}={ver}' if ver else name)
    print(' '.join(techs))
except: pass
" "$local_out" 2>/dev/null || echo "")
            [ -n "$techs" ] && log "  ${domain}: ${techs}"
        fi
    done < "$DOMAIN_LIST"
else
    warn "whatweb not installed — using header-only fingerprinting"
fi

# ── Header-based fingerprinting ──
info "Analyzing response headers..."
while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    cms="" framework="" server="" language="" extras=""

    # Fetch headers
    headers=$(curl -sk -D- -o /dev/null --max-time 10 "${HUNT_UA_CURL[@]}" "https://${domain}/" 2>/dev/null || \
              curl -sk -D- -o /dev/null --max-time 10 "${HUNT_UA_CURL[@]}" "http://${domain}/" 2>/dev/null || echo "")
    [ -z "$headers" ] && continue

    # Extract body for generator meta tags
    body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "https://${domain}/" 2>/dev/null | head -200 || echo "")

    # Server header
    srv=$(echo "$headers" | grep -i '^server:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    [ -n "$srv" ] && server="$srv"

    # X-Powered-By
    xpb=$(echo "$headers" | grep -i '^x-powered-by:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -n "$xpb" ]; then
        case "${xpb,,}" in
            *php*)     language="php" ;;
            *asp.net*) language="aspnet" ;;
            *express*) framework="express" ;;
            *next*)    framework="nextjs" ;;
            *)         extras="$xpb" ;;
        esac
    fi

    # Cookie-based detection
    cookies=$(echo "$headers" | grep -i '^set-cookie:' | tr -d '\r')
    case "${cookies,,}" in
        *phpsessid*)       language="${language:-php}" ;;
        *jsessionid*)      language="${language:-java}" ;;
        *asp.net_sessionid*|*aspxauth*) language="${language:-aspnet}" ;;
        *csrftoken*django*|*sessionid*) framework="${framework:-django}" ;;
        *laravel_session*) framework="${framework:-laravel}" ;;
        *wp-settings*|*wordpress_logged_in*) cms="wordpress" ;;
    esac

    # X-Generator / meta generator
    xgen=$(echo "$headers" | grep -i '^x-generator:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    if [ -z "$xgen" ] && [ -n "$body" ]; then
        xgen=$(echo "$body" | grep -oP '<meta[^>]+name=["\x27]generator["\x27][^>]+content=["\x27]\K[^"\x27]+' | head -1 || echo "")
    fi
    case "${xgen,,}" in
        *wordpress*)   cms="wordpress" ;;
        *drupal*)      cms="drupal" ;;
        *joomla*)      cms="joomla" ;;
        *sharepoint*)  cms="sharepoint" ;;
        *magento*)     cms="magento" ;;
        *hugo*)        cms="hugo" ;;
        *ghost*)       cms="ghost" ;;
    esac

    # Body-based CMS detection
    if [ -z "$cms" ] && [ -n "$body" ]; then
        case "$body" in
            *wp-content/*|*wp-includes/*) cms="wordpress" ;;
            *Drupal.settings*|*/sites/default/*) cms="drupal" ;;
            *Joomla*|*/media/jui/*) cms="joomla" ;;
            */_next/*|*__NEXT_DATA__*) framework="${framework:-nextjs}" ;;
            */_nuxt/*) framework="${framework:-nuxtjs}" ;;
            *csrfmiddlewaretoken*) framework="${framework:-django}" ;;
            *laravel*|*Laravel*) framework="${framework:-laravel}" ;;
            *coldfusion*|*CFTOKEN*) framework="${framework:-coldfusion}" ;;
        esac
    fi

    # Server-based framework detection
    case "${server,,}" in
        *tomcat*|*catalina*) framework="${framework:-tomcat}" ;;
        *nginx*)  ;;  # too generic
        *apache*) ;;  # too generic
        *iis*)    language="${language:-aspnet}" ;;
        *openresty*) ;;
    esac

    # Special endpoint probes
    # Spring Boot Actuator
    act_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${HUNT_UA_CURL[@]}" "https://${domain}/actuator/health" 2>/dev/null || echo "000")
    [[ "$act_status" =~ ^(200|401)$ ]] && framework="${framework:-springboot}"

    # Adobe AEM
    aem_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${HUNT_UA_CURL[@]}" "https://${domain}/crx/de" 2>/dev/null || echo "000")
    [[ "$aem_status" =~ ^(200|401|302)$ ]] && cms="${cms:-aem}"

    # Build profile line
    profile="${domain}"
    [ -n "$cms" ] && profile+=" CMS=${cms}"
    [ -n "$framework" ] && profile+=" FRAMEWORK=${framework}"
    [ -n "$server" ] && profile+=" SERVER=${server}"
    [ -n "$language" ] && profile+=" LANG=${language}"
    [ -n "$extras" ] && profile+=" EXTRA=${extras}"

    echo "$profile" >> "${OUT_DIR}/tech_profile.txt"
    log "  ${profile}"

    # ── Map technologies to SecLists wordlists ──
    case "$cms" in
        wordpress)
            for wl in "wordpress.fuzz.txt" "wp-plugins.fuzz.txt" "wp-themes.fuzz.txt"; do
                [ -f "${CMS_DIR}/${wl}" ] && echo "${CMS_DIR}/${wl}" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            done
            [ -f "${TRICKEST_DIR}/wordpress.txt" ] && echo "${TRICKEST_DIR}/wordpress.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        drupal)
            for wl in "Drupal.txt" "drupal-themes.fuzz.txt"; do
                [ -f "${CMS_DIR}/${wl}" ] && echo "${CMS_DIR}/${wl}" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            done
            [ -f "${TRICKEST_DIR}/drupal.txt" ] && echo "${TRICKEST_DIR}/drupal.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        joomla)
            for wl in "joomla-plugins.fuzz.txt" "joomla-themes.fuzz.txt"; do
                [ -f "${CMS_DIR}/${wl}" ] && echo "${CMS_DIR}/${wl}" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            done
            [ -f "${TRICKEST_DIR}/joomla.txt" ] && echo "${TRICKEST_DIR}/joomla.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        sharepoint)
            for wl in "Sharepoint.txt" "Sharepoint-Ennumeration.txt"; do
                [ -f "${CMS_DIR}/${wl}" ] && echo "${CMS_DIR}/${wl}" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            done
            ;;
        magento)
            [ -f "${CMS_DIR}/sitemap-magento.txt" ] && echo "${CMS_DIR}/sitemap-magento.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            [ -f "${TRICKEST_DIR}/magento.txt" ] && echo "${TRICKEST_DIR}/magento.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        aem)
            [ -f "${CMS_DIR}/Adobe-AEM_2021.txt" ] && echo "${CMS_DIR}/Adobe-AEM_2021.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        ghost)
            [ -f "${TRICKEST_DIR}/ghost.txt" ] && echo "${TRICKEST_DIR}/ghost.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
    esac

    case "$framework" in
        django)
            [ -f "${CMS_DIR}/Django.txt" ] && echo "${CMS_DIR}/Django.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            [ -f "${TRICKEST_DIR}/django-cms.txt" ] && echo "${TRICKEST_DIR}/django-cms.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        laravel)
            [ -f "${TRICKEST_DIR}/laravel.txt" ] && echo "${TRICKEST_DIR}/laravel.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        tomcat)
            [ -f "${TRICKEST_DIR}/tomcat.txt" ] && echo "${TRICKEST_DIR}/tomcat.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        coldfusion)
            [ -f "${CMS_DIR}/ColdFusion.fuzz.txt" ] && echo "${CMS_DIR}/ColdFusion.fuzz.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        springboot)
            # Spring Boot doesn't have a dedicated CMS wordlist but Actuator endpoints are covered in Phase 3
            :
            ;;
    esac

    case "$language" in
        php)
            [ -f "${CMS_DIR}/php-nuke.fuzz.txt" ] && echo "${CMS_DIR}/php-nuke.fuzz.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
        aspnet)
            # SAP is ASP-adjacent
            [ -f "${CMS_DIR}/SAP.fuzz.txt" ] && echo "${CMS_DIR}/SAP.fuzz.txt" >> "${OUT_DIR}/ac_cms_wordlists.txt"
            ;;
    esac

done < "$DOMAIN_LIST"

# Deduplicate wordlists
if [ -f "${OUT_DIR}/ac_cms_wordlists.txt" ]; then
    sort -u -o "${OUT_DIR}/ac_cms_wordlists.txt" "${OUT_DIR}/ac_cms_wordlists.txt"
fi

tech_count=$(count_lines "${OUT_DIR}/tech_profile.txt")
wl_count=$(count_lines "${OUT_DIR}/ac_cms_wordlists.txt" 2>/dev/null || echo 0)
log "Fingerprinted ${tech_count} domains"
log "Selected ${wl_count} CMS-specific wordlists for Phase 2"
log "Tech profiles: ${OUT_DIR}/tech_profile.txt"
log "CMS wordlists: ${OUT_DIR}/ac_cms_wordlists.txt"

# Cleanup
rm -f "${OUT_DIR}/_ac_fp_domains.txt"
