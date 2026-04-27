#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_graphql_recon.sh — GraphQL Endpoint Discovery &          ║
# ║  Fingerprinting · graphinder · introspection · engine ID ·   ║
# ║  graphql-cop · cross-tool input from ac_graphql_findings     ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_graphql_recon.sh"
SCRIPT_DESC="GraphQL Endpoint Discovery & Fingerprinting"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover GraphQL endpoints via path probing and graphinder,"
    echo "  test introspection, fingerprint the GraphQL engine, and read"
    echo "  cross-tool inputs from ac_graphql_findings.txt."
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

phase_header "1" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    # Try cross-tool input
    if [ ! -f "${OUT_DIR}/ac_graphql_findings.txt" ]; then
        err "Provide --domain, --domains, --urls, or ensure ac_graphql_findings.txt exists in OUT_DIR"
        script_usage
        exit 1
    fi
fi

# ── Tool checks ──────────────────────────────────────────────
HAS_GRAPHINDER=false
check_tool graphinder 2>/dev/null && HAS_GRAPHINDER=true

HAS_GQL_COP=false
if command -v graphql-cop &>/dev/null; then
    HAS_GQL_COP=true
elif [ -f "${BHEH_DIR:-/dev/null}/graphql-cop/graphql-cop.py" ]; then
    HAS_GQL_COP=true
fi

if ! check_tool curl 2>/dev/null; then
    err "curl is required"
    exit 1
fi

# ── Output files ─────────────────────────────────────────────
> "${OUT_DIR}/ap_graphql_endpoints.txt"
> "${OUT_DIR}/ap_graphql_recon_findings.txt"

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

# If URLS_FILE provided, add those as base URLs
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        targets+=("$u")
    done < "$URLS_FILE"
fi

# ── Import cross-tool inputs from ac_graphql_findings.txt ────
CROSS_ENDPOINTS=()
if [ -f "${OUT_DIR}/ac_graphql_findings.txt" ] && [ -s "${OUT_DIR}/ac_graphql_findings.txt" ]; then
    info "Reading cross-tool input: ac_graphql_findings.txt"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Extract URLs from lines like: INTROSPECTION_ENABLED [GET] https://...
        url=$(echo "$line" | grep -oP 'https?://[^\s]+' | head -1)
        if [ -n "$url" ]; then
            CROSS_ENDPOINTS+=("$url")
            echo "$url" >> "${OUT_DIR}/ap_graphql_endpoints.txt"
            echo "[CROSS-TOOL] Imported from ac_graphql_findings: ${url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
        fi
    done < "${OUT_DIR}/ac_graphql_findings.txt"
    log "Imported ${#CROSS_ENDPOINTS[@]} endpoint(s) from ac_graphql_findings.txt"
fi

# ── Common GraphQL paths to probe ────────────────────────────
GQL_PATHS=(
    "/graphql"
    "/gql"
    "/v1/graphql"
    "/v2/graphql"
    "/v3/graphql"
    "/api/graphql"
    "/api/gql"
    "/api/v1/graphql"
    "/api/v2/graphql"
    "/graphiql"
    "/playground"
    "/console"
    "/altair"
    "/voyager"
    "/v1/explore"
    "/v1/explorer"
    "/query"
    "/api/query"
    "/graphql/console"
    "/graphql/schema"
    "/graphql/v1"
    "/admin/graphql"
    "/admin/api/graphql"
    "/internal/graphql"
    "/_graphql"
    "/graph"
    "/graphql-explorer"
    "/subscriptions"
    "/graphql/playground"
    "/api/graphiql"
)

# ══════════════════════════════════════════════════════════════
# Stage 1: graphinder discovery (if available)
# ══════════════════════════════════════════════════════════════
if $HAS_GRAPHINDER; then
    info "Running graphinder for automated GraphQL endpoint discovery..."
    for base_url in "${targets[@]}"; do
        host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
        info "  graphinder scanning: ${host}"

        graphinder_out=$(mktemp)
        graphinder -d "$host" -o "$graphinder_out" 2>/dev/null || true

        if [ -s "$graphinder_out" ]; then
            while IFS= read -r ep; do
                [ -z "$ep" ] && continue
                echo "$ep" >> "${OUT_DIR}/ap_graphql_endpoints.txt"
                echo "[GRAPHINDER] Discovered: ${ep}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
                log "  graphinder found: ${ep}"
            done < "$graphinder_out"
        fi
        rm -f "$graphinder_out"
    done
else
    info "graphinder not available — using manual path probing"
fi

# ══════════════════════════════════════════════════════════════
# Stage 2: Manual path probing
# ══════════════════════════════════════════════════════════════
info "Probing common GraphQL paths..."

for base_url in "${targets[@]}"; do
    # Strip trailing paths for base URL probing
    base_origin=$(echo "$base_url" | grep -oP 'https?://[^/]+')
    [ -z "$base_origin" ] && continue
    host=$(echo "$base_origin" | sed 's|https\?://||')
    info "  Probing: ${host}"

    for gpath in "${GQL_PATHS[@]}"; do
        probe_url="${base_origin}${gpath}"

        # Skip if already discovered
        if grep -qxF "$probe_url" "${OUT_DIR}/ap_graphql_endpoints.txt" 2>/dev/null; then
            continue
        fi

        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$probe_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        # GraphQL endpoints typically respond to GET with 200, 400 (needs query), or 405 (POST only)
        if [[ "$status" =~ ^(200|400|405)$ ]] && [ "${size:-0}" -gt 0 ]; then
            # Verify it looks like a GraphQL endpoint by sending a query
            verify_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d '{"query":"{__typename}"}' \
                "$probe_url" 2>/dev/null || echo "")

            if echo "$verify_resp" | grep -qiE '("data"|"errors"|"__typename"|"Query"|"Mutation"|graphql)'; then
                echo "$probe_url" >> "${OUT_DIR}/ap_graphql_endpoints.txt"
                echo "[PROBE] Confirmed GraphQL: HTTP ${status} ${probe_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
                log "    Confirmed GraphQL: ${probe_url} (HTTP ${status})"
            fi
        fi

        # Also catch 301/302 redirects that point to a real GraphQL endpoint
        if [[ "$status" =~ ^(301|302)$ ]]; then
            redir_url=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -o /dev/null -D- "$probe_url" 2>/dev/null | grep -i '^location:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
            if [ -n "$redir_url" ]; then
                echo "[REDIRECT] ${probe_url} -> ${redir_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
            fi
        fi
    done
done

# ── Deduplicate endpoints ─────────────────────────────────────
sort -u -o "${OUT_DIR}/ap_graphql_endpoints.txt" "${OUT_DIR}/ap_graphql_endpoints.txt" 2>/dev/null || true
ep_count=$(count_lines "${OUT_DIR}/ap_graphql_endpoints.txt")
info "Total unique GraphQL endpoints discovered: ${ep_count}"

if [ "$ep_count" -eq 0 ]; then
    warn "No GraphQL endpoints found — skipping introspection and fingerprinting"
    log "GraphQL recon complete: 0 endpoints discovered"
    log "  ${OUT_DIR}/ap_graphql_endpoints.txt"
    log "  ${OUT_DIR}/ap_graphql_recon_findings.txt"
    exit 0
fi

# ══════════════════════════════════════════════════════════════
# Stage 3: Introspection testing
# ══════════════════════════════════════════════════════════════
info "Testing introspection on ${ep_count} endpoint(s)..."

INTROSPECTION_FULL='{__schema{types{name kind fields{name type{name kind ofType{name kind}}} inputFields{name type{name kind}} enumValues{name}}queryType{name fields{name}}mutationType{name fields{name}}subscriptionType{name fields{name}}}}'
INTROSPECTION_SIMPLE='{__schema{types{name}queryType{fields{name}}mutationType{fields{name}}}}'

introspection_count=0

while IFS= read -r gql_url; do
    [ -z "$gql_url" ] && continue
    info "  Testing: ${gql_url}"

    # ── POST introspection (most common method) ──
    post_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/json" \
        -d "{\"query\":\"${INTROSPECTION_FULL}\"}" \
        "$gql_url" 2>/dev/null || echo "")

    post_has_schema=false
    if echo "$post_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    types = schema.get('types', [])
    if len(types) > 0:
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
        post_has_schema=true
    fi

    # ── GET introspection ──
    encoded_query=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${INTROSPECTION_SIMPLE}'))" 2>/dev/null || echo "")
    get_resp=""
    get_has_schema=false
    if [ -n "$encoded_query" ]; then
        get_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            "${gql_url}?query=${encoded_query}" 2>/dev/null || echo "")

        if echo "$get_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    qt = schema.get('queryType', {})
    if qt and qt.get('fields'):
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
            get_has_schema=true
        fi
    fi

    # ── Record introspection results ──
    if $post_has_schema; then
        ((introspection_count++)) || true
        warn "  INTROSPECTION ENABLED (POST): ${gql_url}"
        echo "[HIGH] INTROSPECTION_ENABLED [POST] ${gql_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"

        # Extract type and field details
        echo "$post_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    types = schema.get('types', [])
    user_types = [t for t in types if not t['name'].startswith('__')]
    qt = schema.get('queryType', {})
    mt = schema.get('mutationType', {})
    st = schema.get('subscriptionType', {})
    print(f'  Total types: {len(types)} ({len(user_types)} user-defined)')
    if qt and qt.get('fields'):
        names = [f['name'] for f in qt['fields']]
        print(f'  Query fields ({len(names)}): {', '.join(names[:30])}')
        if len(names) > 30: print(f'    ... and {len(names)-30} more')
    if mt and mt.get('fields'):
        names = [f['name'] for f in mt['fields']]
        print(f'  Mutation fields ({len(names)}): {', '.join(names[:30])}')
        if len(names) > 30: print(f'    ... and {len(names)-30} more')
    if st and st.get('fields'):
        names = [f['name'] for f in st['fields']]
        print(f'  Subscription fields ({len(names)}): {', '.join(names[:20])}')
    # Flag sensitive-looking types
    sensitive = [t['name'] for t in user_types if any(kw in t['name'].lower() for kw in ('user','admin','auth','token','secret','password','credential','session','key','role','permission'))]
    if sensitive:
        print(f'  Sensitive types: {', '.join(sensitive)}')
except: pass
" >> "${OUT_DIR}/ap_graphql_recon_findings.txt" 2>/dev/null || true

        # Save full schema to file for downstream tools
        echo "$post_resp" > "${OUT_DIR}/ap_graphql_schema_${gql_url//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
    fi

    if $get_has_schema && ! $post_has_schema; then
        ((introspection_count++)) || true
        warn "  INTROSPECTION ENABLED (GET only): ${gql_url}"
        echo "[HIGH] INTROSPECTION_ENABLED [GET] ${gql_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"

        echo "$get_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    schema = d.get('data', {}).get('__schema', {})
    qt = schema.get('queryType', {})
    mt = schema.get('mutationType', {})
    if qt and qt.get('fields'):
        names = [f['name'] for f in qt['fields']]
        print(f'  Query fields ({len(names)}): {', '.join(names[:30])}')
    if mt and mt.get('fields'):
        names = [f['name'] for f in mt['fields']]
        print(f'  Mutation fields ({len(names)}): {', '.join(names[:30])}')
except: pass
" >> "${OUT_DIR}/ap_graphql_recon_findings.txt" 2>/dev/null || true
    fi

    if ! $post_has_schema && ! $get_has_schema; then
        echo "[INFO] INTROSPECTION_DISABLED ${gql_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
        info "    Introspection disabled on ${gql_url}"
    fi

done < "${OUT_DIR}/ap_graphql_endpoints.txt"

# ══════════════════════════════════════════════════════════════
# Stage 4: Engine fingerprinting via graphql-cop or manual
# ══════════════════════════════════════════════════════════════
info "Fingerprinting GraphQL engines..."

fingerprint_count=0

while IFS= read -r gql_url; do
    [ -z "$gql_url" ] && continue

    # ── graphql-cop fingerprinting (if available) ──
    if $HAS_GQL_COP; then
        info "  graphql-cop: ${gql_url}"
        cop_out=""
        if command -v graphql-cop &>/dev/null; then
            cop_out=$(graphql-cop -t "$gql_url" 2>/dev/null || echo "")
        elif [ -f "${BHEH_DIR}/graphql-cop/graphql-cop.py" ]; then
            cop_out=$(python3 "${BHEH_DIR}/graphql-cop/graphql-cop.py" -t "$gql_url" 2>/dev/null || echo "")
        fi

        if [ -n "$cop_out" ]; then
            echo "[GRAPHQL-COP] ${gql_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
            echo "$cop_out" | while IFS= read -r cop_line; do
                [ -z "$cop_line" ] && continue
                echo "  ${cop_line}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
            done
            ((fingerprint_count++)) || true
        fi
    fi

    # ── Manual engine fingerprinting ──
    # Different engines respond differently to malformed queries and specific fields
    engine="unknown"

    # Test 1: Error message fingerprinting
    err_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/json" \
        -d '{"query":"{ __INVALID_FIELD_FOR_FINGERPRINT__ }"}' \
        "$gql_url" 2>/dev/null || echo "")

    if echo "$err_resp" | grep -qi "graphql-yoga"; then
        engine="graphql-yoga"
    elif echo "$err_resp" | grep -qi "apollo"; then
        engine="apollo-server"
    elif echo "$err_resp" | grep -qi "graphene"; then
        engine="graphene (Python)"
    elif echo "$err_resp" | grep -qi "absinthe"; then
        engine="absinthe (Elixir)"
    elif echo "$err_resp" | grep -qi "graphql-ruby\|GraphQL::"; then
        engine="graphql-ruby"
    elif echo "$err_resp" | grep -qi "graphql-java\|GraphQLError"; then
        engine="graphql-java"
    elif echo "$err_resp" | grep -qi "Hasura"; then
        engine="hasura"
    elif echo "$err_resp" | grep -qi "dgraph\|Dgraph"; then
        engine="dgraph"
    elif echo "$err_resp" | grep -qi "ariadne"; then
        engine="ariadne (Python)"
    elif echo "$err_resp" | grep -qi "strawberry"; then
        engine="strawberry (Python)"
    elif echo "$err_resp" | grep -qi "juniper"; then
        engine="juniper (Rust)"
    fi

    # Test 2: Server header hints
    if [ "$engine" = "unknown" ]; then
        srv_header=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -X POST -H "Content-Type: application/json" \
            -d '{"query":"{__typename}"}' \
            -D- -o /dev/null "$gql_url" 2>/dev/null | grep -i '^server:\|^x-powered-by:' || echo "")

        if echo "$srv_header" | grep -qi "hasura"; then
            engine="hasura"
        elif echo "$srv_header" | grep -qi "express"; then
            engine="apollo-server (Express)"
        elif echo "$srv_header" | grep -qi "koa"; then
            engine="apollo-server (Koa)"
        elif echo "$srv_header" | grep -qi "gunicorn\|uvicorn\|daphne"; then
            engine="python-based (gunicorn/uvicorn)"
        fi
    fi

    # Test 3: Specific engine probes
    if [ "$engine" = "unknown" ]; then
        # Hasura console check
        hasura_check=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}" \
            "$(echo "$gql_url" | sed 's|/v1/graphql.*|/console|;s|/graphql.*|/console|')" \
            2>/dev/null || echo "000")
        if [ "$hasura_check" = "200" ]; then
            engine="hasura"
        fi
    fi

    echo "[FINGERPRINT] ${gql_url} engine=${engine}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
    if [ "$engine" != "unknown" ]; then
        log "  Engine: ${gql_url} -> ${engine}"
        ((fingerprint_count++)) || true
    else
        info "    Could not fingerprint engine for ${gql_url}"
    fi

    # ── Check for IDE/playground exposure ──
    for ide_suffix in "/playground" "/graphiql" "/altair" "/voyager" "/console"; do
        ide_base=$(echo "$gql_url" | grep -oP 'https?://[^/]+')
        ide_url="${ide_base}${ide_suffix}"
        ide_status=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}" "$ide_url" 2>/dev/null || echo "000")
        if [ "$ide_status" = "200" ]; then
            echo "[MEDIUM] GraphQL IDE exposed: ${ide_url}" >> "${OUT_DIR}/ap_graphql_recon_findings.txt"
            log "  IDE exposed: ${ide_url}"
        fi
    done

done < "${OUT_DIR}/ap_graphql_endpoints.txt"

# ══════════════════════════════════════════════════════════════
# Dedup & summary
# ══════════════════════════════════════════════════════════════
sort -u -o "${OUT_DIR}/ap_graphql_endpoints.txt" "${OUT_DIR}/ap_graphql_endpoints.txt" 2>/dev/null || true

final_ep_count=$(count_lines "${OUT_DIR}/ap_graphql_endpoints.txt")
findings_count=$(count_lines "${OUT_DIR}/ap_graphql_recon_findings.txt")

echo ""
log "GraphQL recon complete:"
log "  Endpoints discovered:  ${final_ep_count}"
log "  Introspection enabled: ${introspection_count}"
log "  Engines fingerprinted: ${fingerprint_count}"
log "  Total findings:        ${findings_count}"
log "Results:"
log "  ${OUT_DIR}/ap_graphql_endpoints.txt"
log "  ${OUT_DIR}/ap_graphql_recon_findings.txt"

if [ "$introspection_count" -gt 0 ]; then
    echo ""
    warn "HIGH severity — Introspection enabled endpoints:"
    grep '^\[HIGH\]' "${OUT_DIR}/ap_graphql_recon_findings.txt" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
