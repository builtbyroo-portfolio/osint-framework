#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_api_discovery.sh — API Endpoint Discovery                ║
# ║  REST fuzzing · GraphQL introspection · Swagger/OpenAPI ·    ║
# ║  SOAP WSDL probing                                           ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_api_discovery.sh"
SCRIPT_DESC="API Endpoint Discovery"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover API endpoints: REST, GraphQL, Swagger/OpenAPI, and SOAP."
    echo "  Uses ffuf for fuzzing and curl for targeted probes."
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

phase_header "3" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

# ── Build target list ──
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("https://${d}")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("https://${DOMAIN}")
fi

if [ ${#targets[@]} -eq 0 ]; then
    err "No targets resolved from input"
    exit 1
fi

# ── Tool checks ──
HAS_FFUF=false
check_tool ffuf 2>/dev/null && HAS_FFUF=true

if ! check_tool curl 2>/dev/null; then
    err "curl is required"
    exit 1
fi

# ── SecLists paths ──
WL_API_REST="${SECLISTS}/Discovery/Web-Content/api/api-endpoints-res.txt"
WL_API_WILD="${SECLISTS}/Discovery/Web-Content/api/api-seen-in-wild.txt"
WL_GRAPHQL="${SECLISTS}/Discovery/Web-Content/graphql.txt"

# ── Output files ──
> "${OUT_DIR}/ac_api_findings.txt"
> "${OUT_DIR}/ac_graphql_findings.txt"
> "${OUT_DIR}/ac_swagger_specs.txt"
mkdir -p "${OUT_DIR}/ffuf_api"

# ══════════════════════════════════════════════════════════════
# REST API fuzzing
# ══════════════════════════════════════════════════════════════
if $HAS_FFUF; then
    info "REST API endpoint fuzzing..."

    # Prefixes to fuzz under
    api_prefixes=("/api/FUZZ" "/api/v1/FUZZ" "/api/v2/FUZZ" "/rest/FUZZ")

    # Wordlists to use (only those that exist)
    rest_wordlists=()
    [ -f "$WL_API_REST" ] && rest_wordlists+=("$WL_API_REST")
    [ -f "$WL_API_WILD" ] && rest_wordlists+=("$WL_API_WILD")

    if [ ${#rest_wordlists[@]} -eq 0 ]; then
        warn "No REST API wordlists found in ${SECLISTS}/Discovery/Web-Content/api/"
    else
        for base_url in "${targets[@]}"; do
            host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
            info "  Target: ${host}"

            for prefix in "${api_prefixes[@]}"; do
                # Sanitize prefix for filename: /api/v1/FUZZ -> api_v1
                prefix_tag=$(echo "$prefix" | sed 's|^/||;s|/FUZZ$||;s|/|_|g')

                for wl in "${rest_wordlists[@]}"; do
                    wl_tag=$(basename "$wl" .txt)
                    out_json="${OUT_DIR}/ffuf_api/${host}_${prefix_tag}_${wl_tag}.json"

                    ffuf -u "${base_url}${prefix}" -w "$wl" \
                        "${HUNT_UA_ARGS[@]}" \
                        -mc 200,201,301,302,401,403,405,500 -fc 404 \
                        -t "${THREADS}" -o "$out_json" -of json \
                        -timeout 10 2>/dev/null || true

                    # Parse ffuf JSON results
                    if [ -s "$out_json" ]; then
                        python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    for r in data.get('results', []):
        url = r.get('url', '')
        status = r.get('status', 0)
        length = r.get('length', 0)
        words = r.get('words', 0)
        print(f'{status} [{length}B/{words}w] {url}')
except: pass
" "$out_json" >> "${OUT_DIR}/ac_api_findings.txt" 2>/dev/null || true
                    fi
                done
            done
        done
    fi
else
    warn "ffuf not installed — skipping REST API fuzzing"
fi

# ══════════════════════════════════════════════════════════════
# GraphQL discovery
# ══════════════════════════════════════════════════════════════
info "GraphQL endpoint discovery..."

INTROSPECTION_QUERY='{__schema{queryType{fields{name}}mutationType{fields{name}}}}'

for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')

    # Step 1: Discover GraphQL paths via ffuf
    graphql_paths=()
    if $HAS_FFUF && [ -f "$WL_GRAPHQL" ]; then
        out_json="${OUT_DIR}/ffuf_api/${host}_graphql_paths.json"

        ffuf -u "${base_url}/FUZZ" -w "$WL_GRAPHQL" \
            "${HUNT_UA_ARGS[@]}" \
            -mc 200,201,301,302,401,403,405,500 -fc 404 \
            -t "${THREADS}" -o "$out_json" -of json \
            -timeout 10 2>/dev/null || true

        if [ -s "$out_json" ]; then
            while IFS= read -r gql_path; do
                [ -n "$gql_path" ] && graphql_paths+=("$gql_path")
            done < <(python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    for r in data.get('results', []):
        url = r.get('url', '')
        status = r.get('status', 0)
        if url:
            print(url)
except: pass
" "$out_json" 2>/dev/null)
        fi
    fi

    # Also check common GraphQL paths manually if ffuf missed them
    common_gql_paths=("/graphql" "/graphiql" "/v1/graphql" "/api/graphql" "/query")
    for gpath in "${common_gql_paths[@]}"; do
        gql_url="${base_url}${gpath}"
        # Skip if already found by ffuf
        already_found=false
        for existing in "${graphql_paths[@]+"${graphql_paths[@]}"}"; do
            [ "$existing" = "$gql_url" ] && already_found=true && break
        done
        $already_found && continue

        status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
            "${HUNT_UA_CURL[@]}" "$gql_url" 2>/dev/null || echo "000")
        if [[ "$status" =~ ^(200|301|302|401|403|405)$ ]]; then
            graphql_paths+=("$gql_url")
        fi
    done

    if [ ${#graphql_paths[@]} -eq 0 ]; then
        info "  ${host}: no GraphQL endpoints found"
        continue
    fi

    info "  ${host}: testing ${#graphql_paths[@]} GraphQL endpoint(s) for introspection..."

    # Step 2: Test introspection on each discovered path
    for gql_url in "${graphql_paths[@]}"; do
        # GET introspection
        get_resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            "${gql_url}?query=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${INTROSPECTION_QUERY}'))" 2>/dev/null)" \
            2>/dev/null || echo "")

        get_has_schema=false
        if echo "$get_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    qt = schema.get('queryType', {})
    if qt and qt.get('fields'):
        sys.exit(0)
    sys.exit(1)
except: sys.exit(1)
" 2>/dev/null; then
            get_has_schema=true
        fi

        # POST introspection
        post_resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            -X POST -H "Content-Type: application/json" \
            -d "{\"query\":\"${INTROSPECTION_QUERY}\"}" \
            "$gql_url" 2>/dev/null || echo "")

        post_has_schema=false
        if echo "$post_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    qt = schema.get('queryType', {})
    if qt and qt.get('fields'):
        sys.exit(0)
    sys.exit(1)
except: sys.exit(1)
" 2>/dev/null; then
            post_has_schema=true
        fi

        # Record findings
        if $get_has_schema; then
            echo "INTROSPECTION_ENABLED [GET] ${gql_url}" >> "${OUT_DIR}/ac_graphql_findings.txt"
            # Extract field names
            echo "$get_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    qt = schema.get('queryType', {})
    mt = schema.get('mutationType', {})
    if qt and qt.get('fields'):
        names = [f['name'] for f in qt['fields']]
        print(f'  queryType fields: {', '.join(names)}')
    if mt and mt.get('fields'):
        names = [f['name'] for f in mt['fields']]
        print(f'  mutationType fields: {', '.join(names)}')
except: pass
" >> "${OUT_DIR}/ac_graphql_findings.txt" 2>/dev/null || true
            warn "  INTROSPECTION ENABLED (GET): ${gql_url}"
        fi

        if $post_has_schema; then
            echo "INTROSPECTION_ENABLED [POST] ${gql_url}" >> "${OUT_DIR}/ac_graphql_findings.txt"
            echo "$post_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    qt = schema.get('queryType', {})
    mt = schema.get('mutationType', {})
    if qt and qt.get('fields'):
        names = [f['name'] for f in qt['fields']]
        print(f'  queryType fields: {', '.join(names)}')
    if mt and mt.get('fields'):
        names = [f['name'] for f in mt['fields']]
        print(f'  mutationType fields: {', '.join(names)}')
except: pass
" >> "${OUT_DIR}/ac_graphql_findings.txt" 2>/dev/null || true
            warn "  INTROSPECTION ENABLED (POST): ${gql_url}"
        fi

        if ! $get_has_schema && ! $post_has_schema; then
            # Endpoint exists but introspection is disabled or returned error
            get_status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                "${HUNT_UA_CURL[@]}" "$gql_url" 2>/dev/null || echo "000")
            echo "ENDPOINT_ALIVE [${get_status}] ${gql_url}" >> "${OUT_DIR}/ac_graphql_findings.txt"
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Swagger / OpenAPI discovery
# ══════════════════════════════════════════════════════════════
info "Swagger/OpenAPI endpoint probing..."

swagger_paths=(
    "/swagger-ui.html"
    "/swagger-ui/"
    "/api-docs"
    "/openapi.json"
    "/openapi.yaml"
    "/v2/api-docs"
    "/v3/api-docs"
    "/swagger.json"
    "/swagger.yaml"
    "/swagger/v1/swagger.json"
    "/swagger-resources"
    "/_swagger/v1/swagger.json"
    "/api/swagger.json"
    "/api/openapi.json"
    "/docs"
    "/redoc"
)

for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
    info "  Probing ${host} for Swagger/OpenAPI..."

    for spath in "${swagger_paths[@]}"; do
        result=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
            --max-time 8 "${HUNT_UA_CURL[@]}" "${base_url}${spath}" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [[ "$status" =~ ^(200|301|302)$ ]] && [ "${size:-0}" -gt 50 ]; then
            echo "${status} [${size}B] ${base_url}${spath}" >> "${OUT_DIR}/ac_swagger_specs.txt"
            log "    Found: ${status} ${base_url}${spath} (${size}B)"

            # If it returned 200 and is JSON, try to extract API info
            if [ "$status" = "200" ] && [ "${size:-0}" -gt 100 ]; then
                body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "${base_url}${spath}" 2>/dev/null || echo "")
                echo "$body" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # OpenAPI 3.x
    if 'openapi' in d:
        title = d.get('info', {}).get('title', 'unknown')
        ver = d.get('openapi', '?')
        paths = list(d.get('paths', {}).keys())
        print(f'  OpenAPI {ver} — {title} — {len(paths)} paths')
        for p in paths[:20]:
            print(f'    {p}')
        if len(paths) > 20:
            print(f'    ... and {len(paths)-20} more')
    # Swagger 2.x
    elif 'swagger' in d:
        title = d.get('info', {}).get('title', 'unknown')
        ver = d.get('swagger', '?')
        paths = list(d.get('paths', {}).keys())
        print(f'  Swagger {ver} — {title} — {len(paths)} paths')
        for p in paths[:20]:
            print(f'    {p}')
        if len(paths) > 20:
            print(f'    ... and {len(paths)-20} more')
    # Swagger Resources
    elif isinstance(d, list) and d and 'location' in d[0]:
        for entry in d:
            loc = entry.get('location', '')
            print(f'  Swagger Resource: {loc}')
except: pass
" >> "${OUT_DIR}/ac_swagger_specs.txt" 2>/dev/null || true
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# SOAP / ASMX WSDL probing
# ══════════════════════════════════════════════════════════════
info "SOAP/ASMX WSDL probing..."

# Look for .asmx URLs from Phase 2 content discovery output
CONTENT_FILE="${OUT_DIR}/ac_content_findings.txt"
asmx_urls=()

if [ -f "$CONTENT_FILE" ] && [ -s "$CONTENT_FILE" ]; then
    while IFS= read -r asmx_url; do
        [ -n "$asmx_url" ] && asmx_urls+=("$asmx_url")
    done < <(grep -oP 'https?://[^\s]+\.asmx' "$CONTENT_FILE" 2>/dev/null | sort -u)
fi

# Also probe common SOAP endpoints directly
soap_paths=(
    "/service.asmx"
    "/services.asmx"
    "/webservice.asmx"
    "/api.asmx"
    "/ws/service.asmx"
    "/WebService.asmx"
)

for base_url in "${targets[@]}"; do
    for spath in "${soap_paths[@]}"; do
        soap_url="${base_url}${spath}"
        status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
            "${HUNT_UA_CURL[@]}" "$soap_url" 2>/dev/null || echo "000")
        if [[ "$status" =~ ^(200|301|302|401|403)$ ]]; then
            # Avoid duplicates
            already=false
            for existing in "${asmx_urls[@]+"${asmx_urls[@]}"}"; do
                [ "$existing" = "$soap_url" ] && already=true && break
            done
            $already || asmx_urls+=("$soap_url")
        fi
    done
done

soap_count=0
if [ ${#asmx_urls[@]} -gt 0 ]; then
    info "  Testing ${#asmx_urls[@]} ASMX endpoint(s) for WSDL..."
    for asmx_url in "${asmx_urls[@]}"; do
        wsdl_url="${asmx_url}?WSDL"
        result=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
            --max-time 10 "${HUNT_UA_CURL[@]}" "$wsdl_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [ "$status" = "200" ] && [ "${size:-0}" -gt 100 ]; then
            echo "${status} [${size}B] ${wsdl_url}" >> "${OUT_DIR}/ac_api_findings.txt"
            ((soap_count++)) || true
            log "    WSDL exposed: ${wsdl_url} (${size}B)"

            # Extract operation names from WSDL XML
            body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$wsdl_url" 2>/dev/null || echo "")
            if [ -n "$body" ]; then
                echo "$body" | python3 -c "
import sys, re
try:
    xml = sys.stdin.read()
    # Extract operation names from <wsdl:operation> or <s:element> or <operation>
    ops = re.findall(r'<(?:wsdl:)?operation\s+name=[\"\\x27]([^\"\\x27]+)', xml)
    elems = re.findall(r'<s:element\s+name=[\"\\x27]([^\"\\x27]+)', xml)
    if ops:
        print(f'  Operations ({len(ops)}): {', '.join(sorted(set(ops)))}')
    if elems:
        print(f'  Elements ({len(elems)}): {', '.join(sorted(set(elems))[:30])}')
except: pass
" >> "${OUT_DIR}/ac_api_findings.txt" 2>/dev/null || true
            fi
        fi
    done
else
    info "  No ASMX endpoints found (checked Phase 2 output + common paths)"
fi

# ══════════════════════════════════════════════════════════════
# Dedup & summary
# ══════════════════════════════════════════════════════════════
for f in ac_api_findings.txt ac_graphql_findings.txt ac_swagger_specs.txt; do
    sort -u -o "${OUT_DIR}/${f}" "${OUT_DIR}/${f}" 2>/dev/null || true
done

api_count=$(count_lines "${OUT_DIR}/ac_api_findings.txt")
graphql_count=$(count_lines "${OUT_DIR}/ac_graphql_findings.txt")
swagger_count=$(count_lines "${OUT_DIR}/ac_swagger_specs.txt")

log "API discovery complete:"
log "  REST endpoints:    ${api_count} (includes SOAP/WSDL)"
log "  GraphQL findings:  ${graphql_count}"
log "  Swagger/OpenAPI:   ${swagger_count}"
log "Results:"
log "  ${OUT_DIR}/ac_api_findings.txt"
log "  ${OUT_DIR}/ac_graphql_findings.txt"
log "  ${OUT_DIR}/ac_swagger_specs.txt"
