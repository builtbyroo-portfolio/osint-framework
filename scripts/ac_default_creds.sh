#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_default_creds.sh — Default Credential Testing            ║
# ║  Service-specific creds · HTTP Basic Auth · Form brute        ║
# ║  Reads ac_login_panels.txt + tech_profile.txt from earlier    ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_default_creds.sh"
SCRIPT_DESC="Default Credential Testing"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test default and common credentials against discovered login panels"
    echo "  and known service endpoints. Uses tech_profile.txt from Phase 1 for"
    echo "  service detection and ac_login_panels.txt from Phase 2 for targets."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with URLs (login panels)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "7" "$SCRIPT_DESC"

# ── Output files ──
> "${OUT_DIR}/ac_cred_findings.txt"
> "${OUT_DIR}/ac_detected_services.txt"

# ── Resolve login panels input ──
PANELS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    PANELS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_login_panels.txt" ]; then
    PANELS_FILE="${OUT_DIR}/ac_login_panels.txt"
fi

TECH_FILE="${OUT_DIR}/tech_profile.txt"

if [ -z "$PANELS_FILE" ] && [ ! -f "$TECH_FILE" ] && [ -z "${DOMAIN:-}" ]; then
    err "No login panels, tech profile, or domain provided"
    err "  Run Phase 1 (ac_fingerprint.sh) and Phase 2 (ac_content_discovery.sh) first,"
    err "  or provide --domain or --urls"
    script_usage
    exit 1
fi

panel_count=0
[ -n "$PANELS_FILE" ] && [ -s "$PANELS_FILE" ] && panel_count=$(count_lines "$PANELS_FILE")
info "Login panels to test: ${panel_count}"
[ -f "$TECH_FILE" ] && info "Tech profile: ${TECH_FILE}" || info "No tech profile found (Phase 1 output)"

# ── SecLists paths ──
TOMCAT_CREDS="${SECLISTS}/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt"
DEFAULT_CREDS_CSV="${SECLISTS}/Passwords/Default-Credentials/default-passwords.csv"

# ── Counters ──
CRIT_COUNT=0
HIGH_COUNT=0

# ── Helper: record finding ──
record_finding() {
    local severity="$1"
    local service="$2"
    local url="$3"
    local detail="$4"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${severity}] [${timestamp}] ${service} | ${url} | ${detail}" >> "${OUT_DIR}/ac_cred_findings.txt"
    if [ "$severity" = "CRITICAL" ]; then
        err "CRITICAL: ${service} — ${url}"
        err "  ${detail}"
        ((CRIT_COUNT++)) || true
    else
        warn "${severity}: ${service} — ${url}"
        warn "  ${detail}"
        ((HIGH_COUNT++)) || true
    fi
}

# ── Helper: record detected service ──
record_service() {
    local service="$1"
    local url="$2"
    local detail="${3:-}"
    echo "${service} | ${url} | ${detail}" >> "${OUT_DIR}/ac_detected_services.txt"
}

# ── Build base URLs from domain or tech profile ──
BASE_URLS=()
if [ -n "${DOMAIN:-}" ]; then
    BASE_URLS+=("https://${DOMAIN}")
fi
if [ -f "$TECH_FILE" ]; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        tech_domain=$(echo "$line" | awk '{print $1}')
        [ -z "$tech_domain" ] && continue
        base="https://${tech_domain}"
        # Avoid duplicates
        local_dup=false
        for existing in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
            [ "$existing" = "$base" ] && local_dup=true && break
        done
        $local_dup || BASE_URLS+=("$base")
    done < "$TECH_FILE"
fi

# ══════════════════════════════════════════════════════════════
# 1. TOMCAT /manager/html — Default Credentials
# ══════════════════════════════════════════════════════════════
info "Testing Tomcat Manager default credentials..."

test_tomcat() {
    local base_url="$1"
    local manager_url="${base_url}/manager/html"

    # First check if Tomcat Manager is present
    local status
    status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
        "${HUNT_UA_CURL[@]}" "$manager_url" 2>/dev/null || echo "000")

    if [ "$status" != "401" ] && [ "$status" != "200" ] && [ "$status" != "403" ]; then
        return
    fi

    record_service "Tomcat Manager" "$manager_url" "HTTP ${status}"
    log "  Tomcat Manager detected: ${manager_url} (${status})"

    if [ ! -f "$TOMCAT_CREDS" ]; then
        warn "  Tomcat credential list not found: ${TOMCAT_CREDS}"
        return
    fi

    local tested=0 found=0
    while IFS=: read -r user pass; do
        [ -z "$user" ] && continue
        ((tested++)) || true

        local resp_code resp_body
        resp_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            -u "${user}:${pass}" -w "\n%{http_code}" "$manager_url" 2>/dev/null || echo "000")
        resp_code=$(echo "$resp_body" | tail -1)
        resp_body=$(echo "$resp_body" | sed '$d')

        if [ "$resp_code" = "200" ]; then
            # Verify it's actually a successful login (body contains manager content)
            if echo "$resp_body" | grep -qiE '(deploy|undeploy|server.info|applications|manager)'; then
                record_finding "CRITICAL" "Tomcat Manager" "$manager_url" \
                    "Default credentials work: ${user}:${pass} (HTTP 200, manager content confirmed)"
                ((found++)) || true
                break
            fi
        fi
    done < "$TOMCAT_CREDS"
    info "  Tomcat: tested ${tested} credential pairs, found ${found}"
}

for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    test_tomcat "$base"
done

# Also check tech profile for tomcat-specific domains
if [ -f "$TECH_FILE" ]; then
    while IFS= read -r line; do
        echo "$line" | grep -qiE 'FRAMEWORK=tomcat|SERVER=.*[Tt]omcat' || continue
        tech_domain=$(echo "$line" | awk '{print $1}')
        test_tomcat "https://${tech_domain}"
    done < "$TECH_FILE"
fi

# ══════════════════════════════════════════════════════════════
# 2. JENKINS — Default Credentials
# ══════════════════════════════════════════════════════════════
info "Testing Jenkins default credentials..."

JENKINS_CREDS=("admin:admin" "admin:password" "admin:jenkins")

test_jenkins() {
    local url="$1"

    # Normalize to base URL
    local jenkins_base
    jenkins_base=$(echo "$url" | sed 's|/login.*||;s|/$||')

    # Check if Jenkins is responding
    local resp_body resp_code
    resp_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -w "\n%{http_code}" "${jenkins_base}/" 2>/dev/null || echo "000")
    resp_code=$(echo "$resp_body" | tail -1)
    resp_body=$(echo "$resp_body" | sed '$d')

    # Confirm Jenkins presence
    if ! echo "$resp_body" | grep -qiE '(jenkins|hudson)'; then
        if [[ "$url" != *jenkins* ]] && [[ "$url" != *Jenkins* ]]; then
            return
        fi
    fi

    record_service "Jenkins" "$jenkins_base" "Detected"
    log "  Jenkins detected: ${jenkins_base}"

    # Get the login page to extract crumb (CSRF token)
    local login_page crumb_header
    login_page=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -c /tmp/_ac_jenkins_cookies "$jenkins_base/login" 2>/dev/null || echo "")

    # Try to get Jenkins crumb
    crumb_header=""
    local crumb_json
    crumb_json=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -b /tmp/_ac_jenkins_cookies \
        "${jenkins_base}/crumbIssuer/api/json" 2>/dev/null || echo "")
    if echo "$crumb_json" | grep -q "crumbRequestField"; then
        local crumb_field crumb_value
        crumb_field=$(echo "$crumb_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('crumbRequestField',''))" 2>/dev/null || echo "")
        crumb_value=$(echo "$crumb_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('crumb',''))" 2>/dev/null || echo "")
        [ -n "$crumb_field" ] && [ -n "$crumb_value" ] && crumb_header="-H ${crumb_field}: ${crumb_value}"
    fi

    for cred in "${JENKINS_CREDS[@]}"; do
        local user pass
        user="${cred%%:*}"
        pass="${cred#*:}"

        local login_resp login_code
        login_resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            -b /tmp/_ac_jenkins_cookies \
            -d "j_username=${user}&j_password=${pass}&from=%2F&Submit=Sign+in" \
            ${crumb_header} \
            -w "\n%{http_code}" \
            -L "${jenkins_base}/j_spring_security_check" 2>/dev/null || echo "000")
        login_code=$(echo "$login_resp" | tail -1)
        login_resp=$(echo "$login_resp" | sed '$d')

        # Successful login: redirects to dashboard, contains "logout" or "log out"
        if echo "$login_resp" | grep -qiE '(logout|log\s*out|/logout|dashboard|manage jenkins)'; then
            record_finding "CRITICAL" "Jenkins" "$jenkins_base" \
                "Default credentials work: ${user}:${pass} (dashboard content confirmed)"
            break
        fi
    done

    rm -f /tmp/_ac_jenkins_cookies
}

# Check panels file for Jenkins URLs
if [ -n "$PANELS_FILE" ] && [ -s "$PANELS_FILE" ]; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        if echo "$url" | grep -qiE '(jenkins|/j_spring_security_check)'; then
            test_jenkins "$url"
        fi
    done < "$PANELS_FILE"
fi

# Check base URLs for Jenkins at /jenkins path
for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    jenkins_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
        "${HUNT_UA_CURL[@]}" "${base}/jenkins/" 2>/dev/null || echo "000")
    if [[ "$jenkins_status" =~ ^(200|301|302|403)$ ]]; then
        test_jenkins "${base}/jenkins"
    fi
done

# ══════════════════════════════════════════════════════════════
# 3. GRAFANA — admin:admin
# ══════════════════════════════════════════════════════════════
info "Testing Grafana default credentials..."

test_grafana() {
    local base_url="$1"
    local login_url="${base_url}/login"
    local api_url="${base_url}/api/login"

    # Check if Grafana is present
    local login_body login_code
    login_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -w "\n%{http_code}" "$login_url" 2>/dev/null || echo "000")
    login_code=$(echo "$login_body" | tail -1)
    login_body=$(echo "$login_body" | sed '$d')

    if ! echo "$login_body" | grep -qiE '(grafana|"appTitle"|grafana-app)'; then
        return
    fi

    record_service "Grafana" "$base_url" "Login page detected"
    log "  Grafana detected: ${base_url}"

    # Test admin:admin via API
    local resp
    resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/json" \
        -d '{"user":"admin","password":"admin"}' \
        -w "\n%{http_code}" "$api_url" 2>/dev/null || echo "000")
    local resp_code
    resp_code=$(echo "$resp" | tail -1)
    resp=$(echo "$resp" | sed '$d')

    if [ "$resp_code" = "200" ]; then
        # Check for successful login indicators
        if echo "$resp" | grep -qiE '(redirectUrl|"message":"Logged in")'; then
            record_finding "CRITICAL" "Grafana" "$base_url" \
                "Default credentials work: admin:admin (API login returned 200, session granted)"
            return
        fi
    fi

    # Also check if password change is forced (still a successful auth)
    if echo "$resp" | grep -qiE 'change.?password'; then
        record_finding "CRITICAL" "Grafana" "$base_url" \
            "Default credentials work: admin:admin (password change required — first login, never changed)"
    fi
}

for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    test_grafana "$base"
    test_grafana "${base}/grafana"
done

# Check panels for Grafana URLs
if [ -n "$PANELS_FILE" ] && [ -s "$PANELS_FILE" ]; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        if echo "$url" | grep -qiE 'grafana'; then
            grafana_base=$(echo "$url" | sed 's|/login.*||;s|/$||')
            test_grafana "$grafana_base"
        fi
    done < "$PANELS_FILE"
fi

# ══════════════════════════════════════════════════════════════
# 4. PHPMYADMIN — root:(empty), root:root, root:password
# ══════════════════════════════════════════════════════════════
info "Testing phpMyAdmin default credentials..."

PMA_CREDS=("root:" "root:root" "root:password")

test_phpmyadmin() {
    local base_url="$1"

    # Check if phpMyAdmin is present
    local pma_body pma_code
    pma_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -w "\n%{http_code}" "$base_url" 2>/dev/null || echo "000")
    pma_code=$(echo "$pma_body" | tail -1)
    pma_body=$(echo "$pma_body" | sed '$d')

    if ! echo "$pma_body" | grep -qiE '(phpmyadmin|pma_username|phpMyAdmin)'; then
        return
    fi

    record_service "phpMyAdmin" "$base_url" "Detected (HTTP ${pma_code})"
    log "  phpMyAdmin detected: ${base_url}"

    # Extract the login form token if present
    local token
    token=$(echo "$pma_body" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=\"token\"\s+value=\"([^\"]+)\"', html)
if m: print(m.group(1))
else:
    m = re.search(r'token=([a-f0-9]+)', html)
    if m: print(m.group(1))
" 2>/dev/null || echo "")

    # Extract the server field value
    local server_field
    server_field=$(echo "$pma_body" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=\"server\"\s+value=\"([^\"]+)\"', html)
if m: print(m.group(1))
else: print('1')
" 2>/dev/null || echo "1")

    for cred in "${PMA_CREDS[@]}"; do
        local user pass
        user="${cred%%:*}"
        pass="${cred#*:}"

        local post_data="pma_username=${user}&pma_password=${pass}&server=${server_field}"
        [ -n "$token" ] && post_data+="&token=${token}"

        local resp resp_code
        resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            -X POST -d "$post_data" \
            -D- -w "\n%{http_code}" \
            -L "$base_url" 2>/dev/null || echo "000")
        resp_code=$(echo "$resp" | tail -1)
        resp=$(echo "$resp" | sed '$d')

        # Success indicators: redirect to index.php with session, body contains server info
        if echo "$resp" | grep -qiE '(server_databases|phpmyadmin-page-content|db_structure|phpMyAdmin\s+[0-9])'; then
            record_finding "CRITICAL" "phpMyAdmin" "$base_url" \
                "Default credentials work: ${user}:${pass} (database panel accessible)"
            break
        fi

        # Check for session cookie being set (Set-Cookie with phpMyAdmin or pma)
        if echo "$resp" | grep -qiE 'Set-Cookie:.*phpMyAdmin|Set-Cookie:.*pma_'; then
            if ! echo "$resp" | grep -qiE '(denied|error|failed|incorrect)'; then
                record_finding "CRITICAL" "phpMyAdmin" "$base_url" \
                    "Default credentials work: ${user}:${pass} (session cookie granted)"
                break
            fi
        fi
    done
}

# Check common phpMyAdmin paths
PMA_PATHS=("/phpmyadmin" "/phpMyAdmin" "/pma" "/mysql" "/dbadmin" "/myadmin" "/phpmyadmin/index.php")
for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    for pma_path in "${PMA_PATHS[@]}"; do
        pma_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
            "${HUNT_UA_CURL[@]}" "${base}${pma_path}" 2>/dev/null || echo "000")
        if [[ "$pma_status" =~ ^(200|301|302)$ ]]; then
            test_phpmyadmin "${base}${pma_path}"
        fi
    done
done

# Check panels for phpMyAdmin URLs
if [ -n "$PANELS_FILE" ] && [ -s "$PANELS_FILE" ]; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        if echo "$url" | grep -qiE '(phpmyadmin|pma|dbadmin|myadmin)'; then
            test_phpmyadmin "$url"
        fi
    done < "$PANELS_FILE"
fi

# ══════════════════════════════════════════════════════════════
# 5. KIBANA — Unauthenticated /api/status
# ══════════════════════════════════════════════════════════════
info "Testing Kibana unauthenticated access..."

test_kibana() {
    local base_url="$1"
    local api_url="${base_url}/api/status"

    local resp resp_code
    resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -w "\n%{http_code}" "$api_url" 2>/dev/null || echo "000")
    resp_code=$(echo "$resp" | tail -1)
    resp=$(echo "$resp" | sed '$d')

    if [ "$resp_code" != "200" ]; then
        return
    fi

    # Check if it returns Kibana status JSON
    if echo "$resp" | grep -qiE '("name":.*"status"|"version".*"number"|kbn-name|kibana)'; then
        record_service "Kibana" "$base_url" "API status accessible (HTTP 200)"
        log "  Kibana detected: ${base_url}"

        # Extract version info
        local version
        version=$(echo "$resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    v = d.get('version', {})
    if isinstance(v, dict):
        print(v.get('number', 'unknown'))
    else:
        print(str(v))
except: print('unknown')
" 2>/dev/null || echo "unknown")

        record_finding "HIGH" "Kibana" "$api_url" \
            "Unauthenticated access to Kibana API status (version: ${version}) — no auth required"

        # Also check if Kibana dashboards are accessible
        local dash_code
        dash_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
            "${HUNT_UA_CURL[@]}" "${base_url}/app/kibana" 2>/dev/null || echo "000")
        if [ "$dash_code" = "200" ]; then
            record_finding "CRITICAL" "Kibana" "${base_url}/app/kibana" \
                "Kibana dashboard accessible without authentication (version: ${version})"
        fi
    fi
}

for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    test_kibana "$base"
    test_kibana "${base}/kibana"
done

# ══════════════════════════════════════════════════════════════
# 6. SPRING BOOT ACTUATOR — Sensitive endpoints without auth
# ══════════════════════════════════════════════════════════════
info "Testing Spring Boot Actuator sensitive endpoints..."

ACTUATOR_ENDPOINTS=("/actuator/env" "/actuator/configprops" "/actuator/beans" "/actuator/mappings" "/actuator/heapdump" "/actuator/threaddump")

test_actuator() {
    local base_url="$1"
    local found_sensitive=false

    for endpoint in "${ACTUATOR_ENDPOINTS[@]}"; do
        local resp resp_code
        resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            -w "\n%{http_code}" "${base_url}${endpoint}" 2>/dev/null || echo "000")
        resp_code=$(echo "$resp" | tail -1)
        resp=$(echo "$resp" | sed '$d')

        if [ "$resp_code" = "200" ]; then
            # Verify it's actual actuator data (not a generic 200 page)
            local body_len=${#resp}
            if [ "$body_len" -gt 50 ]; then
                if echo "$resp" | grep -qiE '(\{.*"property"|"beans"|"contexts"|"dispatcherServlets"|"activeProfiles")'; then
                    record_service "Spring Boot Actuator" "${base_url}${endpoint}" "Accessible (HTTP 200)"
                    found_sensitive=true

                    local severity="HIGH"
                    local detail="Actuator endpoint accessible without auth: ${endpoint}"

                    # /actuator/env and /actuator/heapdump are critical
                    if [ "$endpoint" = "/actuator/env" ] || [ "$endpoint" = "/actuator/heapdump" ]; then
                        severity="CRITICAL"
                        detail="Sensitive actuator endpoint accessible — may expose secrets: ${endpoint}"
                    fi

                    record_finding "$severity" "Spring Boot Actuator" "${base_url}${endpoint}" "$detail"
                fi
            fi
        fi
    done

    $found_sensitive && log "  Spring Boot Actuator sensitive endpoints found on ${base_url}"
}

for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    test_actuator "$base"
done

# Also check tech profile for springboot
if [ -f "$TECH_FILE" ]; then
    while IFS= read -r line; do
        echo "$line" | grep -qiE 'FRAMEWORK=springboot' || continue
        tech_domain=$(echo "$line" | awk '{print $1}')
        test_actuator "https://${tech_domain}"
    done < "$TECH_FILE"
fi

# ══════════════════════════════════════════════════════════════
# 7. HTTP BASIC AUTH — 401 + WWW-Authenticate: Basic
# ══════════════════════════════════════════════════════════════
info "Testing HTTP Basic Auth with default credentials..."

# Top 20 common user:pass pairs for Basic Auth
BASIC_CREDS=(
    "admin:admin" "admin:password" "admin:123456" "admin:admin123"
    "root:root" "root:password" "root:toor" "root:123456"
    "user:user" "user:password" "test:test" "guest:guest"
    "administrator:administrator" "administrator:password"
    "operator:operator" "manager:manager" "demo:demo"
    "support:support" "monitor:monitor" "tomcat:tomcat"
)

test_basic_auth() {
    local url="$1"

    # Check if the URL returns 401 with Basic auth challenge
    local headers
    headers=$(curl -sk -D- -o /dev/null --max-time 10 \
        "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "")

    local status
    status=$(echo "$headers" | head -1 | grep -oP '\d{3}' | head -1 || echo "000")

    if [ "$status" != "401" ]; then
        return
    fi

    if ! echo "$headers" | grep -qiE 'WWW-Authenticate:.*Basic'; then
        return
    fi

    local realm
    realm=$(echo "$headers" | grep -oiP 'realm="[^"]*"' | head -1 || echo "")
    record_service "HTTP Basic Auth" "$url" "401 challenge ${realm}"
    log "  Basic Auth detected: ${url} ${realm}"

    for cred in "${BASIC_CREDS[@]}"; do
        local user pass
        user="${cred%%:*}"
        pass="${cred#*:}"

        local resp_code
        resp_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
            "${HUNT_UA_CURL[@]}" -u "${user}:${pass}" "$url" 2>/dev/null || echo "000")

        if [ "$resp_code" = "200" ] || [ "$resp_code" = "301" ] || [ "$resp_code" = "302" ]; then
            # Verify it's not returning 200 for everything (WAF/custom error)
            local bad_code
            bad_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
                "${HUNT_UA_CURL[@]}" -u "invaliduser_$$:invalidpass_$$" "$url" 2>/dev/null || echo "000")

            if [ "$bad_code" != "$resp_code" ]; then
                record_finding "CRITICAL" "HTTP Basic Auth" "$url" \
                    "Default credentials work: ${user}:${pass} (HTTP ${resp_code} vs ${bad_code} for invalid creds)"
                return
            fi
        fi
    done
}

# Test all panels for Basic Auth
if [ -n "$PANELS_FILE" ] && [ -s "$PANELS_FILE" ]; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        test_basic_auth "$url"
    done < "$PANELS_FILE"
fi

# Test base URLs for Basic Auth
for base in "${BASE_URLS[@]+"${BASE_URLS[@]}"}"; do
    test_basic_auth "$base"
done

# ══════════════════════════════════════════════════════════════
# 8. FORM-BASED LOGIN — Generic credential testing
# ══════════════════════════════════════════════════════════════
info "Testing form-based logins with common credentials..."

FORM_CREDS=(
    "admin:admin" "admin:password" "admin:Password1" "admin:123456"
    "root:root" "root:toor" "test:test" "guest:guest"
    "user:user" "demo:demo"
)

test_form_login() {
    local url="$1"

    # Fetch the login page
    local page_body page_code
    page_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -c /tmp/_ac_form_cookies_$$ \
        -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
    page_code=$(echo "$page_body" | tail -1)
    page_body=$(echo "$page_body" | sed '$d')

    if [ "$page_code" = "000" ]; then
        return
    fi

    # Extract form details with python3
    local form_info
    form_info=$(echo "$page_body" | python3 -c "
import sys, re
from html.parser import HTMLParser

html = sys.stdin.read()

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_form = False
        self.form_action = ''
        self.form_method = 'POST'
        self.username_field = ''
        self.password_field = ''
        self.hidden_fields = {}
        self.found = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self.in_form = True
            self.form_action = attrs_dict.get('action', '')
            self.form_method = attrs_dict.get('method', 'POST').upper()
        elif tag == 'input' and self.in_form:
            input_type = attrs_dict.get('type', 'text').lower()
            input_name = attrs_dict.get('name', '')
            if not input_name:
                return
            if input_type == 'password':
                self.password_field = input_name
                self.found = True
            elif input_type in ('text', 'email') and not self.username_field:
                self.username_field = input_name
            elif input_type == 'hidden':
                self.hidden_fields[input_name] = attrs_dict.get('value', '')

    def handle_endtag(self, tag):
        if tag == 'form':
            self.in_form = False

parser = FormParser()
try:
    parser.feed(html)
except:
    pass

if parser.found and parser.password_field:
    # Output: action|method|username_field|password_field|hidden1=val1&hidden2=val2
    hidden_str = '&'.join(f'{k}={v}' for k, v in parser.hidden_fields.items())
    print(f'{parser.form_action}|{parser.form_method}|{parser.username_field}|{parser.password_field}|{hidden_str}')
" 2>/dev/null || echo "")

    if [ -z "$form_info" ]; then
        return
    fi

    local form_action form_method user_field pass_field hidden_fields
    IFS='|' read -r form_action form_method user_field pass_field hidden_fields <<< "$form_info"

    if [ -z "$pass_field" ]; then
        return
    fi

    # If no username field found, try common names
    if [ -z "$user_field" ]; then
        for fname in username user login email name; do
            if echo "$page_body" | grep -qiE "name=['\"]${fname}['\"]"; then
                user_field="$fname"
                break
            fi
        done
    fi

    [ -z "$user_field" ] && return

    log "  Login form detected: ${url}"
    log "    Action: ${form_action}, Method: ${form_method}"
    log "    Fields: user=${user_field}, pass=${pass_field}"

    # Resolve form action URL
    local post_url
    if [ -z "$form_action" ] || [ "$form_action" = "#" ]; then
        post_url="$url"
    elif [[ "$form_action" == http* ]]; then
        post_url="$form_action"
    elif [[ "$form_action" == /* ]]; then
        # Absolute path — combine with base
        local base_origin
        base_origin=$(echo "$url" | grep -oP 'https?://[^/]+')
        post_url="${base_origin}${form_action}"
    else
        # Relative path
        local base_dir
        base_dir=$(echo "$url" | sed 's|/[^/]*$|/|')
        post_url="${base_dir}${form_action}"
    fi

    # Get baseline failed login response for comparison
    local baseline_body baseline_code baseline_size
    local post_data="${user_field}=invaliduser_$$_baseline&${pass_field}=invalidpass_$$_baseline"
    [ -n "$hidden_fields" ] && post_data+="&${hidden_fields}"

    baseline_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        -b /tmp/_ac_form_cookies_$$ \
        -X POST -d "$post_data" \
        -L -w "\n%{http_code}" "$post_url" 2>/dev/null || echo "000")
    baseline_code=$(echo "$baseline_body" | tail -1)
    baseline_body=$(echo "$baseline_body" | sed '$d')
    baseline_size=${#baseline_body}

    for cred in "${FORM_CREDS[@]}"; do
        local user pass
        user="${cred%%:*}"
        pass="${cred#*:}"

        local post_data="${user_field}=${user}&${pass_field}=${pass}"
        [ -n "$hidden_fields" ] && post_data+="&${hidden_fields}"

        local resp_body resp_code
        resp_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            -b /tmp/_ac_form_cookies_$$ \
            -X POST -d "$post_data" \
            -D /tmp/_ac_form_headers_$$ \
            -L -w "\n%{http_code}" "$post_url" 2>/dev/null || echo "000")
        resp_code=$(echo "$resp_body" | tail -1)
        resp_body=$(echo "$resp_body" | sed '$d')
        local resp_size=${#resp_body}

        local success=false
        local reason=""

        # Check 1: Response contains dashboard/welcome/logout indicators
        if echo "$resp_body" | grep -qiE '(dashboard|welcome|logout|log\s*out|my.?account|profile|sign.?out)'; then
            if ! echo "$baseline_body" | grep -qiE '(dashboard|welcome|logout|log\s*out|my.?account|profile|sign.?out)'; then
                success=true
                reason="Response contains authenticated indicators (dashboard/welcome/logout)"
            fi
        fi

        # Check 2: Session cookie set
        if [ -f /tmp/_ac_form_headers_$$ ]; then
            if grep -qiE 'Set-Cookie:.*(session|sess|sid|token|auth|jwt)' /tmp/_ac_form_headers_$$; then
                if ! echo "$resp_body" | grep -qiE '(invalid|incorrect|wrong|failed|error|denied)'; then
                    success=true
                    reason="${reason:+${reason}; }Session token set in cookie"
                fi
            fi
        fi

        # Check 3: Significant body size difference (>30% change from baseline)
        if [ "$baseline_size" -gt 100 ] && [ "$resp_size" -gt 100 ]; then
            local size_diff=$(( resp_size - baseline_size ))
            [ "$size_diff" -lt 0 ] && size_diff=$(( -size_diff ))
            local threshold=$(( baseline_size * 30 / 100 ))
            if [ "$size_diff" -gt "$threshold" ]; then
                # Only count as success if no error keywords
                if ! echo "$resp_body" | grep -qiE '(invalid|incorrect|wrong|failed|error|denied|bad.?password)'; then
                    success=true
                    reason="${reason:+${reason}; }Body size differs significantly (${baseline_size} vs ${resp_size})"
                fi
            fi
        fi

        if $success; then
            record_finding "CRITICAL" "Form Login" "$url" \
                "Default credentials work: ${user}:${pass} — ${reason}"
            break
        fi
    done

    rm -f /tmp/_ac_form_cookies_$$ /tmp/_ac_form_headers_$$
}

# Test all login panels
if [ -n "$PANELS_FILE" ] && [ -s "$PANELS_FILE" ]; then
    tested_forms=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        # Skip URLs we already tested with service-specific handlers
        echo "$url" | grep -qiE '(tomcat|jenkins|grafana|phpmyadmin|kibana|actuator)' && continue

        test_form_login "$url"
        ((tested_forms++)) || true
    done < "$PANELS_FILE"
    info "Tested ${tested_forms} form-based login panels"
fi

# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════

# Dedup output files
sort -u -o "${OUT_DIR}/ac_cred_findings.txt" "${OUT_DIR}/ac_cred_findings.txt" 2>/dev/null || true
sort -u -o "${OUT_DIR}/ac_detected_services.txt" "${OUT_DIR}/ac_detected_services.txt" 2>/dev/null || true

findings_count=$(count_lines "${OUT_DIR}/ac_cred_findings.txt")
services_count=$(count_lines "${OUT_DIR}/ac_detected_services.txt")

echo ""
log "Phase 7 complete: Default Credential Testing"
log "  Detected services: ${services_count}"
log "  Credential findings: ${findings_count}"
[ "$CRIT_COUNT" -gt 0 ] && err "  CRITICAL findings: ${CRIT_COUNT}"
[ "$HIGH_COUNT" -gt 0 ] && warn "  HIGH findings: ${HIGH_COUNT}"
log "  Services:  ${OUT_DIR}/ac_detected_services.txt"
log "  Findings:  ${OUT_DIR}/ac_cred_findings.txt"

if [ "$findings_count" -eq 0 ]; then
    log "  No default credentials found — target appears hardened"
fi
