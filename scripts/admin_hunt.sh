#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  admin_hunt.sh — Admin Panel Discovery                       ║
# ║  ffuf admin path fuzzing                                      ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="admin_hunt.sh"
SCRIPT_DESC="Admin Panel Discovery"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover admin panels and management interfaces."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with URLs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "ADMIN" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

> "${OUT_DIR}/admin_findings.txt"

# ── ffuf admin path fuzzing ──
if check_tool ffuf 2>/dev/null; then
    # Build target list
    targets=""
    if [ -n "${DOMAIN:-}" ]; then
        targets="https://${DOMAIN}"
    elif [ -f "${URLS_FILE:-}" ]; then
        targets=$(head -10 "$URLS_FILE")
    fi

    # Admin-specific wordlist
    admin_wordlist=""
    if [ -f "${SECLISTS}/Discovery/Web-Content/big.txt" ]; then
        admin_wordlist="${SECLISTS}/Discovery/Web-Content/big.txt"
    elif [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
        admin_wordlist="/usr/share/wordlists/dirb/common.txt"
    fi

    if [ -n "$admin_wordlist" ] && [ -n "$targets" ]; then
        info "Running ffuf admin panel fuzzing..."
        mkdir -p "${OUT_DIR}/admin_ffuf"

        # Common admin paths to check directly
        admin_paths=(
            "admin" "administrator" "admin.php" "admin.html" "admin/login"
            "wp-admin" "wp-login.php" "cpanel" "phpmyadmin" "adminer"
            "panel" "dashboard" "manage" "manager" "console"
            "_admin" "backend" "control" "cms" "webadmin"
            "siteadmin" "system" "portal" "admin-console"
        )

        echo "$targets" | while IFS= read -r base_url; do
            [ -z "$base_url" ] && continue
            host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')

            # Quick check common admin paths
            for path in "${admin_paths[@]}"; do
                status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${base_url}/${path}" 2>/dev/null || echo "000")
                if [[ "$status" =~ ^(200|301|302|401|403)$ ]]; then
                    echo "${status} ${base_url}/${path}" >> "${OUT_DIR}/admin_findings.txt"
                fi
            done

            # Full ffuf scan — use JSON output for structured results
            ffuf -u "${base_url}/FUZZ" -w "$admin_wordlist" \
                "${HUNT_UA_ARGS[@]}" \
                -mc 200,301,302,401,403 -fc 404 \
                -t "${THREADS}" -o "${OUT_DIR}/admin_ffuf/${host}.json" \
                -of json 2>/dev/null || true

            # Extract results with status codes from JSON
            if [ -s "${OUT_DIR}/admin_ffuf/${host}.json" ]; then
                python3 -c "
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    for r in d.get('results',[]):
        u=r.get('url',''); s=r.get('status',0)
        if any(k in u.lower() for k in ['admin','panel','login','dashboard','manage','console','portal','backend']):
            print(f'{s} {u}')
except: pass
" "${OUT_DIR}/admin_ffuf/${host}.json" >> "${OUT_DIR}/admin_findings.txt" 2>/dev/null || true
            fi
        done
    fi
fi

# ── Known Misconfiguration Endpoint Probing ──
# These endpoints are commonly unauthenticated and leak sensitive data
info "Probing for known misconfiguration endpoints..."
> "${OUT_DIR}/misconfig_findings.txt"

config_endpoints=(
    # HashiCorp Vault
    "/v1/sys/health" "/v1/sys/seal-status" "/v1/sys/leader"
    "/v1/sys/init" "/v1/sys/internal/ui/mounts"
    # Metabase
    "/api/session/properties" "/api/health"
    # Apache Airflow
    "/api/v1/health" "/api/v1/version" "/api/v1/config"
    # Spring Boot Actuator
    "/actuator" "/actuator/env" "/actuator/health" "/actuator/info"
    "/actuator/configprops" "/actuator/mappings" "/actuator/beans"
    "/env" "/health" "/info" "/mappings"
    # Next.js / Nuxt.js
    "/_next/data" "/__nextjs_original-stack-frame"
    # Consul / etcd
    "/v1/agent/self" "/v1/catalog/services" "/v2/keys/?recursive=true"
    # Laravel / Symfony
    "/_debugbar/open" "/_profiler" "/telescope/requests"
    # Grafana / Kibana / Prometheus
    "/api/datasources" "/api/org" "/metrics" "/graph"
    "/api/status/buildinfo"
    # Docker / Kubernetes
    "/v2/_catalog" "/version" "/healthz" "/api/v1/namespaces"
    # Misc
    "/.env" "/.git/config" "/server-status" "/server-info"
    "/phpinfo.php" "/info.php" "/debug" "/trace"
    "/swagger-ui.html" "/api-docs" "/openapi.json"
    "/graphql" "/graphiql" "/_stcore/health"
    "/admin/config" "/config.js" "/app-config.json"
)

echo "$targets" | while IFS= read -r base_url; do
    [ -z "$base_url" ] && continue
    for endpoint in "${config_endpoints[@]}"; do
        result=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
            --max-time 5 "${base_url}${endpoint}" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"
        # Only log if response is meaningful (not empty 200, not redirect to login)
        if [[ "$status" =~ ^(200|401|403|500)$ ]] && [ "${size:-0}" -gt 50 ]; then
            echo "${status} [${size}B] ${base_url}${endpoint}" >> "${OUT_DIR}/misconfig_findings.txt"
        fi
    done
done

misconfig_count=$(count_lines "${OUT_DIR}/misconfig_findings.txt")
log "Misconfiguration endpoints: ${misconfig_count}"
if [ "$misconfig_count" -gt 0 ]; then
    warn "Found ${misconfig_count} potentially exposed config endpoints!"
    echo "# --- Misconfiguration Endpoints ---" >> "${OUT_DIR}/admin_findings.txt"
    cat "${OUT_DIR}/misconfig_findings.txt" >> "${OUT_DIR}/admin_findings.txt"
fi

sort -u -o "${OUT_DIR}/admin_findings.txt" "${OUT_DIR}/admin_findings.txt"
log "Total admin findings: $(count_lines "${OUT_DIR}/admin_findings.txt")"
log "Admin results: ${OUT_DIR}/admin_findings.txt"
