#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_misconfig_probe.sh — Known Misconfiguration Endpoint    ║
# ║  Probes 80+ technology-specific endpoints for info leaks,   ║
# ║  unauthenticated admin panels, debug endpoints, and CVEs.   ║
# ║  Standalone or integrated into access.sh pipeline.          ║
# ╚══════════════════════════════════════════════════════════════╝

set -uo pipefail

SCRIPT_NAME="ac_misconfig_probe"
SCRIPT_DESC="Known misconfiguration endpoint probing"

# Source shared library
HUNT_DIR="${HUNT_DIR:-$(dirname "$(readlink -f "$0")")/..}"
source "${HUNT_DIR}/lib.sh"

parse_common_args "$@"

# ── Output files ─────────────────────────────────────────────
FINDINGS="${OUT_DIR}/ac_misconfig_findings.txt"
DETAILS="${OUT_DIR}/ac_misconfig_details.txt"
> "$FINDINGS"
> "$DETAILS"

# ── Build target list ────────────────────────────────────────
TARGETS_FILE=$(mktemp)
trap 'rm -f "$TARGETS_FILE"' EXIT

if [ -n "${DOMAINS_FILE:-}" ] && [ -s "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/^\*\.//')
        [ -z "$d" ] && continue
        echo "https://${d}" >> "$TARGETS_FILE"
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    echo "https://${DOMAIN}" >> "$TARGETS_FILE"
fi

# Also pull from httpx live hosts if available
for f in "${OUT_DIR}"/*_live_subdomains.txt "${OUT_DIR}"/*_reachable_hosts.txt "${OUT_DIR}"/ac_fingerprint_hosts.txt; do
    [ -s "$f" ] || continue
    grep -oP 'https?://[^\s\[\]]+' "$f" 2>/dev/null | sed 's/\/$//;s/\[.*$//' >> "$TARGETS_FILE"
done

sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
local_count=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
info "Probing ${local_count} targets for known misconfigurations..."

# ── Probe function ───────────────────────────────────────────
probe() {
    local base_url="$1" path="$2" label="$3" match_type="$4" match_pattern="$5" severity="${6:-MEDIUM}"
    local url="${base_url}${path}"
    local resp
    resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" -D- "$url" 2>/dev/null)
    local status
    status=$(echo "$resp" | head -1 | grep -oP '\d{3}' | head -1)
    [ -z "$status" ] && return

    local matched=false
    case "$match_type" in
        status_200)
            [[ "$status" == "200" ]] && matched=true ;;
        status_not_404)
            [[ "$status" != "404" && "$status" != "000" ]] && matched=true ;;
        body_contains)
            if [[ "$status" == "200" ]] && echo "$resp" | grep -qi "$match_pattern"; then
                matched=true
            fi ;;
        body_json_key)
            if [[ "$status" == "200" ]] && echo "$resp" | grep -qP "\"${match_pattern}\""; then
                matched=true
            fi ;;
        status_and_body)
            if [[ "$status" == "200" ]] && echo "$resp" | grep -qi "$match_pattern"; then
                matched=true
            fi ;;
    esac

    if $matched; then
        local size
        size=$(echo "$resp" | wc -c)
        echo "[${severity}] ${label} | HTTP ${status} | ${size} bytes | ${url}" >> "$FINDINGS"
        echo "=== ${label} ===" >> "$DETAILS"
        echo "URL: ${url}" >> "$DETAILS"
        echo "Status: ${status}" >> "$DETAILS"
        echo "$resp" | head -30 >> "$DETAILS"
        echo "---" >> "$DETAILS"
        log "[${severity}] ${label}: ${url} (HTTP ${status})"
    fi
}

# ── Probe all targets ────────────────────────────────────────
while IFS= read -r base; do
    [ -z "$base" ] && continue
    base="${base%/}"

    info "Probing: ${base}"

    # ── Spring Boot Actuator ──────────────────────────────
    probe "$base" "/actuator" "Spring Actuator Index" body_contains "actuator" "HIGH"
    probe "$base" "/actuator/health" "Spring Actuator Health" body_json_key "status" "MEDIUM"
    probe "$base" "/actuator/env" "Spring Actuator Env" body_json_key "propertySources" "CRITICAL"
    probe "$base" "/actuator/configprops" "Spring Actuator ConfigProps" body_json_key "contexts" "CRITICAL"
    probe "$base" "/actuator/mappings" "Spring Actuator Mappings" body_json_key "contexts" "HIGH"
    probe "$base" "/actuator/beans" "Spring Actuator Beans" body_json_key "contexts" "HIGH"
    probe "$base" "/actuator/info" "Spring Actuator Info" status_200 "" "LOW"
    probe "$base" "/actuator/heapdump" "Spring Actuator Heapdump" status_200 "" "CRITICAL"
    probe "$base" "/actuator/threaddump" "Spring Actuator Threaddump" status_200 "" "HIGH"

    # ── ServiceNow ────────────────────────────────────────
    probe "$base" "/stats.do" "ServiceNow Stats" body_contains "servlet_path" "HIGH"
    probe "$base" "/threads.do" "ServiceNow Threads" body_contains "thread" "HIGH"
    probe "$base" "/xmlstats.do" "ServiceNow XML Stats" body_contains "xml" "HIGH"
    probe "$base" "/background_progress_worker.do" "ServiceNow BGWorker" body_contains "progress" "MEDIUM"

    # ── Metabase ──────────────────────────────────────────
    probe "$base" "/api/session/properties" "Metabase Setup Token" body_json_key "setup-token" "CRITICAL"
    probe "$base" "/api/health" "Metabase Health" body_contains "ok" "LOW"

    # ── HashiCorp Vault ───────────────────────────────────
    probe "$base" "/v1/sys/health" "Vault Health" body_json_key "sealed" "MEDIUM"
    probe "$base" "/v1/sys/seal-status" "Vault Seal Status" body_json_key "sealed" "MEDIUM"
    probe "$base" "/v1/sys/init" "Vault Init Status" body_json_key "initialized" "MEDIUM"
    probe "$base" "/v1/sys/leader" "Vault Leader" body_json_key "leader_address" "HIGH"
    probe "$base" "/v1/sys/internal/ui/mounts" "Vault Mounts" body_json_key "secret" "HIGH"

    # ── Apache Airflow ────────────────────────────────────
    probe "$base" "/api/v1/health" "Airflow Health" body_json_key "metadatabase" "MEDIUM"
    probe "$base" "/api/v1/version" "Airflow Version" body_json_key "version" "MEDIUM"
    probe "$base" "/api/v1/dags" "Airflow DAGs" body_json_key "dags" "HIGH"

    # ── Kubernetes / Container ────────────────────────────
    probe "$base" "/healthz" "Kubernetes Healthz" body_contains "ok" "LOW"
    probe "$base" "/readyz" "Kubernetes Readyz" body_contains "ok" "LOW"
    probe "$base" "/metrics" "Prometheus Metrics" body_contains "HELP" "MEDIUM"
    probe "$base" "/debug/pprof/" "Go pprof Debug" body_contains "pprof" "HIGH"
    probe "$base" "/debug/vars" "Go Expvar Debug" body_json_key "memstats" "HIGH"

    # ── GraphQL ───────────────────────────────────────────
    for gql_path in "/graphql" "/graphiql" "/graphql/console" "/v1/graphql" "/api/graphql"; do
        probe "$base" "$gql_path" "GraphQL Endpoint" body_contains "query" "MEDIUM"
    done

    # ── Swagger / OpenAPI ─────────────────────────────────
    for sw_path in "/swagger-ui.html" "/swagger-ui/" "/swagger.json" "/api-docs" "/v2/api-docs" "/v3/api-docs" "/openapi.json" "/api/docs" "/docs"; do
        probe "$base" "$sw_path" "Swagger/OpenAPI" body_contains "swagger\|openapi\|paths" "MEDIUM"
    done

    # ── WordPress ─────────────────────────────────────────
    probe "$base" "/wp-json/wp/v2/users" "WordPress User Enum" body_json_key "slug" "MEDIUM"
    probe "$base" "/wp-json/" "WordPress REST API" body_json_key "namespaces" "LOW"
    probe "$base" "/xmlrpc.php" "WordPress XMLRPC" body_contains "XML-RPC server accepts POST" "LOW"

    # ── Next.js ───────────────────────────────────────────
    probe "$base" "/_next/data" "Next.js Data Dir" status_not_404 "" "LOW"

    # ── Streamlit ─────────────────────────────────────────
    probe "$base" "/_stcore/health" "Streamlit Health" body_contains "ok" "MEDIUM"

    # ── Environment / Debug ───────────────────────────────
    probe "$base" "/server-info" "Server Info" status_200 "" "MEDIUM"
    probe "$base" "/server-status" "Apache Server Status" body_contains "Apache Server Status" "MEDIUM"
    probe "$base" "/nginx_status" "Nginx Status" body_contains "Active connections" "MEDIUM"
    probe "$base" "/.env" "Dotenv File" body_contains "DB_\|API_KEY\|SECRET\|PASSWORD\|TOKEN" "CRITICAL"
    probe "$base" "/.git/HEAD" "Git HEAD Exposed" body_contains "ref:" "CRITICAL"
    probe "$base" "/.git/config" "Git Config Exposed" body_contains "repositoryformatversion" "CRITICAL"
    probe "$base" "/phpinfo.php" "PHP Info" body_contains "phpinfo" "HIGH"
    probe "$base" "/info.php" "PHP Info Alt" body_contains "phpinfo" "HIGH"
    probe "$base" "/elmah.axd" "ELMAH Error Log" body_contains "Error Log" "HIGH"
    probe "$base" "/trace.axd" "ASP.NET Trace" body_contains "Trace" "HIGH"

    # ── Telerik ───────────────────────────────────────────
    probe "$base" "/Telerik.Web.UI.WebResource.axd?type=rau" "Telerik RAU Handler" status_not_404 "" "HIGH"
    probe "$base" "/Telerik.Web.UI.DialogHandler.aspx" "Telerik Dialog Handler" status_not_404 "" "HIGH"

    # ── CMS / Admin Panels ────────────────────────────────
    probe "$base" "/admin" "Admin Panel" status_200 "" "MEDIUM"
    probe "$base" "/admin/" "Admin Panel (slash)" status_200 "" "MEDIUM"
    probe "$base" "/administrator" "Joomla Admin" status_200 "" "MEDIUM"
    probe "$base" "/manager/html" "Tomcat Manager" body_contains "Tomcat" "HIGH"
    probe "$base" "/jenkins" "Jenkins" body_contains "Jenkins" "HIGH"
    probe "$base" "/jmx-console/" "JBoss JMX Console" body_contains "JMX" "CRITICAL"

    # ── Firebase ──────────────────────────────────────────
    probe "$base" "/__/firebase/init.json" "Firebase Config" body_json_key "projectId" "MEDIUM"

    # ── Versa Director ────────────────────────────────────
    probe "$base" "/vnms/customization/uploadCustomLogo.xhtml" "Versa Director Upload" status_not_404 "" "CRITICAL"
    probe "$base" "/versa/login" "Versa Director Login" body_contains "Versa" "HIGH"

    # ── Misc Services ─────────────────────────────────────
    probe "$base" "/status" "Status Page" status_200 "" "LOW"
    probe "$base" "/health" "Health Check" status_200 "" "LOW"
    probe "$base" "/version" "Version Endpoint" status_200 "" "LOW"
    probe "$base" "/api/health" "API Health" status_200 "" "LOW"
    probe "$base" "/api/version" "API Version" status_200 "" "LOW"
    probe "$base" "/api/v1/health" "API v1 Health" status_200 "" "LOW"
    probe "$base" "/.well-known/openid-configuration" "OIDC Discovery" body_json_key "issuer" "LOW"
    probe "$base" "/.well-known/security.txt" "Security.txt" status_200 "" "INFO"

    # ── CORS Quick Check ──────────────────────────────────
    local cors_resp
    cors_resp=$(curl -sk --connect-timeout 8 --max-time 12 "${HUNT_UA_CURL[@]}" -H "Origin: https://evil.com" -D- "$base/" 2>/dev/null)
    if echo "$cors_resp" | grep -qi "access-control-allow-origin: https://evil.com"; then
        if echo "$cors_resp" | grep -qi "access-control-allow-credentials: true"; then
            echo "[HIGH] CORS Origin Reflection + Credentials | ${base}" >> "$FINDINGS"
            log "[HIGH] CORS + Credentials: ${base}"
        else
            echo "[LOW] CORS Origin Reflection (no credentials) | ${base}" >> "$FINDINGS"
        fi
    fi

done < "$TARGETS_FILE"

# ── Summary ──────────────────────────────────────────────────
finding_count=$(wc -l < "$FINDINGS" | tr -d ' ')
if [ "$finding_count" -gt 0 ]; then
    echo ""
    log "Misconfiguration probe complete: ${finding_count} findings"
    warn "Critical/High findings:"
    grep -E '^\[(CRITICAL|HIGH)\]' "$FINDINGS" | while IFS= read -r line; do
        echo "  $line"
    done
else
    log "Misconfiguration probe complete: no findings"
fi
