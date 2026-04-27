#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_schema_harvest.sh — API Schema & Documentation Harvest   ║
# ║  Swagger/OpenAPI · Postman · API Blueprint · GraphQL IDE ·   ║
# ║  spec parsing · undocumented endpoint extraction             ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_schema_harvest.sh"
SCRIPT_DESC="API Schema & Documentation Harvesting"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover API documentation files (Swagger, OpenAPI, Postman,"
    echo "  API Blueprint, GraphQL IDEs), parse discovered specs to extract"
    echo "  undocumented endpoints, and cross-reference with earlier phases."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "8" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Output files ─────────────────────────────────────────────
> "${OUT_DIR}/ap_schema_harvest_findings.txt"
> "${OUT_DIR}/ap_discovered_endpoints.txt"
SPEC_DIR="${OUT_DIR}/api_specs"
mkdir -p "$SPEC_DIR"

# ── Build target list ────────────────────────────────────────
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("https://${d}")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("https://${DOMAIN}")
fi

if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        # Extract base URL
        base=$(echo "$u" | grep -oP 'https?://[^/]+')
        [ -n "$base" ] && targets+=("$base")
    done < "$URLS_FILE"
fi

# Deduplicate targets
TARGETS_UNIQ=$(mktemp)
trap 'rm -f "$TARGETS_UNIQ"' EXIT
printf '%s\n' "${targets[@]}" | sort -u > "$TARGETS_UNIQ"
targets=()
while IFS= read -r t; do
    [ -n "$t" ] && targets+=("$t")
done < "$TARGETS_UNIQ"
rm -f "$TARGETS_UNIQ"

# ── Counters ─────────────────────────────────────────────────
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
SPECS_FOUND=0
ENDPOINTS_EXTRACTED=0

record_finding() {
    local severity="$1" url="$2" test_name="$3" detail="$4"
    echo "[${severity}] ${test_name} | ${url} | ${detail}" >> "${OUT_DIR}/ap_schema_harvest_findings.txt"
    case "$severity" in
        HIGH|CRITICAL) ((HIGH_COUNT++)) || true; warn "[${severity}] ${test_name}: ${url}" ;;
        MEDIUM)        ((MEDIUM_COUNT++)) || true; log "[MEDIUM] ${test_name}: ${url}" ;;
        *)             ((LOW_COUNT++)) || true ;;
    esac
}

# ── Swagger/OpenAPI paths ────────────────────────────────────
SWAGGER_PATHS=(
    "/swagger.json"
    "/swagger.yaml"
    "/swagger.yml"
    "/openapi.json"
    "/openapi.yaml"
    "/openapi.yml"
    "/api-docs"
    "/api-docs.json"
    "/v1/api-docs"
    "/v2/api-docs"
    "/v3/api-docs"
    "/swagger/v1/swagger.json"
    "/swagger/v2/swagger.json"
    "/_swagger/v1/swagger.json"
    "/api/swagger.json"
    "/api/openapi.json"
    "/api/openapi.yaml"
    "/api/v1/swagger.json"
    "/api/v1/openapi.json"
    "/api/v2/swagger.json"
    "/api/v2/openapi.json"
    "/api/v3/swagger.json"
    "/swagger-resources"
    "/swagger-resources/configuration/ui"
    "/swagger-resources/configuration/security"
    "/api/docs"
    "/api/spec"
    "/spec"
    "/spec.json"
    "/spec.yaml"
    "/api.json"
    "/api.yaml"
)

# ── Swagger UI paths ─────────────────────────────────────────
SWAGGER_UI_PATHS=(
    "/swagger-ui.html"
    "/swagger-ui/"
    "/swagger-ui/index.html"
    "/swagger/"
    "/api/swagger-ui.html"
    "/api/swagger-ui/"
    "/docs"
    "/docs/"
    "/api/docs"
    "/redoc"
    "/redoc/"
    "/api-explorer"
    "/api-explorer/"
    "/api/explorer"
    "/developer"
    "/developer/docs"
    "/dev/docs"
)

# ── Postman/Collection paths ─────────────────────────────────
POSTMAN_PATHS=(
    "/postman"
    "/.postman"
    "/collection.json"
    "/postman_collection.json"
    "/api.postman_collection.json"
    "/postman/collection"
    "/.postman/collection.json"
    "/api/postman"
)

# ── API Blueprint paths ──────────────────────────────────────
BLUEPRINT_PATHS=(
    "/apiary.apib"
    "/blueprint.md"
    "/api.apib"
    "/api-blueprint.md"
    "/docs/api.md"
    "/docs/api.apib"
)

# ── GraphQL IDE paths ────────────────────────────────────────
GQL_IDE_PATHS=(
    "/graphiql"
    "/graphql/playground"
    "/playground"
    "/altair"
    "/voyager"
    "/graphql-explorer"
    "/graphql/console"
    "/graphql/ide"
)

# ══════════════════════════════════════════════════════════════
# Stage 1: Swagger/OpenAPI spec discovery
# ══════════════════════════════════════════════════════════════
info "Stage 1: Swagger/OpenAPI specification discovery..."

for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
    info "  Probing: ${host}"

    for spath in "${SWAGGER_PATHS[@]}"; do
        spec_url="${base_url}${spath}"
        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}:%{content_type}" \
            "$spec_url" 2>/dev/null || echo "000:0:")
        status=$(echo "$result" | cut -d: -f1)
        size=$(echo "$result" | cut -d: -f2)
        ctype=$(echo "$result" | cut -d: -f3-)

        if [[ "$status" =~ ^(200)$ ]] && [ "${size:-0}" -gt 100 ]; then
            # Fetch and validate the spec
            spec_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$spec_url" 2>/dev/null || echo "")

            if [ -z "$spec_body" ]; then
                continue
            fi

            # Check if it's a valid API spec
            spec_info=$(echo "$spec_body" | python3 -c "
import json, sys, yaml

try:
    content = sys.stdin.read()
    d = None
    # Try JSON first
    try:
        d = json.loads(content)
    except:
        try:
            d = yaml.safe_load(content)
        except:
            pass

    if d is None:
        sys.exit(1)

    spec_type = 'unknown'
    title = 'unknown'
    version = 'unknown'
    path_count = 0

    if 'openapi' in d:
        spec_type = f'OpenAPI {d[\"openapi\"]}'
        title = d.get('info', {}).get('title', 'unknown')
        version = d.get('info', {}).get('version', 'unknown')
        path_count = len(d.get('paths', {}))
    elif 'swagger' in d:
        spec_type = f'Swagger {d[\"swagger\"]}'
        title = d.get('info', {}).get('title', 'unknown')
        version = d.get('info', {}).get('version', 'unknown')
        path_count = len(d.get('paths', {}))
    elif isinstance(d, list) and d and 'location' in d[0]:
        spec_type = 'Swagger Resources'
        path_count = len(d)
    else:
        sys.exit(1)

    print(f'{spec_type}|{title}|{version}|{path_count}')
except:
    sys.exit(1)
" 2>/dev/null || echo "")

            if [ -n "$spec_info" ]; then
                ((SPECS_FOUND++)) || true
                spec_type=$(echo "$spec_info" | cut -d'|' -f1)
                title=$(echo "$spec_info" | cut -d'|' -f2)
                ver=$(echo "$spec_info" | cut -d'|' -f3)
                path_count=$(echo "$spec_info" | cut -d'|' -f4)

                # Save spec to file
                safe_name=$(echo "${host}_$(basename "$spath")" | sed 's|[^a-zA-Z0-9._-]|_|g')
                spec_file="${SPEC_DIR}/${safe_name}"
                echo "$spec_body" > "$spec_file"

                record_finding "HIGH" "$spec_url" "API Spec Exposed" \
                    "${spec_type} — '${title}' v${ver} — ${path_count} paths — full spec accessible"
                log "    Spec: ${spec_type} '${title}' v${ver} (${path_count} paths) -> ${spec_file}"

                # Extract endpoints from spec
                echo "$spec_body" | python3 -c "
import json, sys

try:
    content = sys.stdin.read()
    d = json.loads(content)

    paths = d.get('paths', {})
    base_path = d.get('basePath', '')
    servers = d.get('servers', [])
    server_url = servers[0].get('url', '') if servers else ''

    for path, methods in paths.items():
        full_path = f'{base_path}{path}' if base_path else (f'{server_url}{path}' if server_url else path)
        method_list = [m.upper() for m in methods.keys() if m.lower() in ('get','post','put','delete','patch','options','head')]
        if method_list:
            print(f'{','.join(method_list)} {full_path}')
        else:
            print(f'ANY {full_path}')
except:
    pass
" 2>/dev/null | while IFS= read -r ep_line; do
                    echo "${base_url}${ep_line##* }" >> "${OUT_DIR}/ap_discovered_endpoints.txt"
                    ((ENDPOINTS_EXTRACTED++)) || true
                done

                # Check for auth definitions (API keys, OAuth)
                echo "$spec_body" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    # OpenAPI 3.x
    components = d.get('components', {}).get('securitySchemes', {})
    # Swagger 2.x
    if not components:
        components = d.get('securityDefinitions', {})
    if components:
        for name, scheme in components.items():
            stype = scheme.get('type', 'unknown')
            scheme_type = scheme.get('scheme', '')
            flow = scheme.get('flows', {})
            if stype == 'apiKey':
                loc = scheme.get('in', '?')
                param = scheme.get('name', '?')
                print(f'AUTH: {name} — apiKey in {loc} ({param})')
            elif stype == 'http':
                print(f'AUTH: {name} — HTTP {scheme_type}')
            elif stype == 'oauth2':
                for flow_name in flow:
                    print(f'AUTH: {name} — OAuth2 {flow_name}')
            else:
                print(f'AUTH: {name} — {stype}')
except: pass
" 2>/dev/null | while IFS= read -r auth_line; do
                    echo "  ${auth_line}" >> "${OUT_DIR}/ap_schema_harvest_findings.txt"
                done
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 2: Swagger UI discovery
# ══════════════════════════════════════════════════════════════
info "Stage 2: Swagger UI / API documentation discovery..."

for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')

    for ui_path in "${SWAGGER_UI_PATHS[@]}"; do
        ui_url="${base_url}${ui_path}"
        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$ui_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [ "$status" = "200" ] && [ "${size:-0}" -gt 500 ]; then
            # Verify it's an actual docs page
            body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$ui_url" 2>/dev/null | head -200 || echo "")

            if echo "$body" | grep -qiE '(swagger|openapi|redoc|api.?doc|api.?explorer|rapidoc)'; then
                record_finding "MEDIUM" "$ui_url" "API Documentation UI" \
                    "Interactive API documentation accessible (HTTP ${status}, ${size}B)"
                log "    API docs UI: ${ui_url}"

                # Try to extract the spec URL from the UI page
                spec_url_from_ui=$(echo "$body" | python3 -c "
import sys, re
html = sys.stdin.read()
# Common patterns for spec URL in Swagger UI
patterns = [
    r'url\s*[:=]\s*[\"\\x27](https?://[^\"\\x27]+(?:swagger|openapi|api-docs)[^\"\\x27]*)[\"\\x27]',
    r'url\s*[:=]\s*[\"\\x27](/[^\"\\x27]+(?:swagger|openapi|api-docs)[^\"\\x27]*)[\"\\x27]',
    r'spec-url=[\"\\x27]([^\"\\x27]+)[\"\\x27]',
    r'data-url=[\"\\x27]([^\"\\x27]+)[\"\\x27]',
]
for p in patterns:
    m = re.search(p, html, re.I)
    if m:
        print(m.group(1))
        break
" 2>/dev/null || echo "")

                if [ -n "$spec_url_from_ui" ]; then
                    echo "  Spec URL extracted from UI: ${spec_url_from_ui}" >> "${OUT_DIR}/ap_schema_harvest_findings.txt"
                fi
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 3: Postman collection discovery
# ══════════════════════════════════════════════════════════════
info "Stage 3: Postman collection discovery..."

for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')

    for pm_path in "${POSTMAN_PATHS[@]}"; do
        pm_url="${base_url}${pm_path}"
        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$pm_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [ "$status" = "200" ] && [ "${size:-0}" -gt 100 ]; then
            body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$pm_url" 2>/dev/null || echo "")

            if echo "$body" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    if 'info' in d and ('item' in d or 'collection' in d):
        sys.exit(0)
    if d.get('info', {}).get('schema', '').startswith('https://schema.getpostman.com'):
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                ((SPECS_FOUND++)) || true
                safe_name=$(echo "${host}_postman" | sed 's|[^a-zA-Z0-9._-]|_|g')
                echo "$body" > "${SPEC_DIR}/${safe_name}.json"

                # Extract endpoints from Postman collection
                pm_info=$(echo "$body" | python3 -c "
import json, sys

def extract_items(items, prefix=''):
    endpoints = []
    for item in items:
        if 'item' in item:
            endpoints += extract_items(item['item'], f'{prefix}/{item.get(\"name\", \"\")}')
        elif 'request' in item:
            req = item['request']
            method = req.get('method', 'GET')
            url = req.get('url', '')
            if isinstance(url, dict):
                raw = url.get('raw', '')
                host = '.'.join(url.get('host', []))
                path = '/'.join(url.get('path', []))
                url = raw or f'{host}/{path}'
            endpoints.append(f'{method} {url}')
    return endpoints

try:
    d = json.loads(sys.stdin.read())
    name = d.get('info', {}).get('name', 'unknown')
    items = d.get('item', [])
    eps = extract_items(items)
    print(f'{name}|{len(eps)}')
    for ep in eps:
        print(ep)
except: pass
" 2>/dev/null || echo "")

                if [ -n "$pm_info" ]; then
                    pm_name=$(echo "$pm_info" | head -1 | cut -d'|' -f1)
                    pm_ep_count=$(echo "$pm_info" | head -1 | cut -d'|' -f2)

                    record_finding "HIGH" "$pm_url" "Postman Collection Exposed" \
                        "Collection '${pm_name}' with ${pm_ep_count} requests accessible"

                    # Extract endpoint URLs
                    echo "$pm_info" | tail -n +2 | while IFS= read -r ep_line; do
                        [ -z "$ep_line" ] && continue
                        ep_url=$(echo "$ep_line" | grep -oP 'https?://[^\s]+' || echo "$ep_line")
                        echo "$ep_url" >> "${OUT_DIR}/ap_discovered_endpoints.txt"
                        ((ENDPOINTS_EXTRACTED++)) || true
                    done
                fi
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 4: API Blueprint discovery
# ══════════════════════════════════════════════════════════════
info "Stage 4: API Blueprint discovery..."

for base_url in "${targets[@]}"; do
    for bp_path in "${BLUEPRINT_PATHS[@]}"; do
        bp_url="${base_url}${bp_path}"
        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$bp_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [ "$status" = "200" ] && [ "${size:-0}" -gt 100 ]; then
            body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$bp_url" 2>/dev/null | head -100 || echo "")

            # Check for API Blueprint markers
            if echo "$body" | grep -qiE '(FORMAT:|HOST:|##.*\[GET\]|##.*\[POST\]|# Group|# Data Structures)'; then
                ((SPECS_FOUND++)) || true
                record_finding "MEDIUM" "$bp_url" "API Blueprint Exposed" \
                    "API Blueprint document accessible (HTTP ${status}, ${size}B)"
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 5: GraphQL IDE discovery
# ══════════════════════════════════════════════════════════════
info "Stage 5: GraphQL IDE/Explorer discovery..."

for base_url in "${targets[@]}"; do
    for gql_path in "${GQL_IDE_PATHS[@]}"; do
        gql_url="${base_url}${gql_path}"
        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$gql_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [ "$status" = "200" ] && [ "${size:-0}" -gt 500 ]; then
            body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$gql_url" 2>/dev/null | head -200 || echo "")

            if echo "$body" | grep -qiE '(graphiql|graphql.?playground|altair|voyager|graphql.?ide|GraphQL)'; then
                record_finding "MEDIUM" "$gql_url" "GraphQL IDE Exposed" \
                    "GraphQL development IDE accessible in production (HTTP ${status}, ${size}B)"
                log "    GraphQL IDE: ${gql_url}"
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 6: Cross-reference with ac_swagger_specs.txt
# ══════════════════════════════════════════════════════════════
if [ -f "${OUT_DIR}/ac_swagger_specs.txt" ] && [ -s "${OUT_DIR}/ac_swagger_specs.txt" ]; then
    info "Stage 6: Cross-referencing with ac_swagger_specs.txt..."

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        spec_url=$(echo "$line" | grep -oP 'https?://[^\s]+')
        [ -z "$spec_url" ] && continue

        # Check if we already found this spec
        if ! grep -qF "$spec_url" "${OUT_DIR}/ap_schema_harvest_findings.txt" 2>/dev/null; then
            echo "[CROSS-REF] Previously discovered in ac_swagger_specs: ${spec_url}" >> "${OUT_DIR}/ap_schema_harvest_findings.txt"

            # Try to fetch and extract endpoints from it
            spec_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$spec_url" 2>/dev/null || echo "")

            if [ -n "$spec_body" ]; then
                echo "$spec_body" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    paths = d.get('paths', {})
    base_path = d.get('basePath', '')
    for path in paths:
        full = f'{base_path}{path}' if base_path else path
        print(full)
except: pass
" 2>/dev/null | while IFS= read -r ep; do
                    base=$(echo "$spec_url" | grep -oP 'https?://[^/]+')
                    echo "${base}${ep}" >> "${OUT_DIR}/ap_discovered_endpoints.txt"
                    ((ENDPOINTS_EXTRACTED++)) || true
                done
            fi
        fi
    done < "${OUT_DIR}/ac_swagger_specs.txt"
else
    info "Stage 6: No ac_swagger_specs.txt found — skipping cross-reference"
fi

# ══════════════════════════════════════════════════════════════
# Dedup & summary
# ══════════════════════════════════════════════════════════════
sort -u -o "${OUT_DIR}/ap_discovered_endpoints.txt" "${OUT_DIR}/ap_discovered_endpoints.txt" 2>/dev/null || true

total_findings=$(count_lines "${OUT_DIR}/ap_schema_harvest_findings.txt")
total_endpoints=$(count_lines "${OUT_DIR}/ap_discovered_endpoints.txt")

echo ""
log "API schema harvesting complete:"
log "  Specs discovered:       ${SPECS_FOUND}"
log "  Endpoints extracted:    ${total_endpoints}"
log "  HIGH/CRITICAL findings: ${HIGH_COUNT}"
log "  MEDIUM findings:        ${MEDIUM_COUNT}"
log "  LOW/INFO findings:      ${LOW_COUNT}"
log "  Total findings:         ${total_findings}"
log "Results:"
log "  ${OUT_DIR}/ap_schema_harvest_findings.txt"
log "  ${OUT_DIR}/ap_discovered_endpoints.txt"
[ "$(ls -A "$SPEC_DIR" 2>/dev/null)" ] && log "  Spec files: ${SPEC_DIR}/"

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo ""
    warn "HIGH/CRITICAL findings — exposed API documentation:"
    grep -E '^\[(HIGH|CRITICAL)\]' "${OUT_DIR}/ap_schema_harvest_findings.txt" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
