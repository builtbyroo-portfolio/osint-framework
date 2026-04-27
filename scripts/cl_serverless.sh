#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_serverless.sh — Serverless Function Discovery              ║
# ║  Lambda · Azure Functions · Vercel · Netlify · GCP CF          ║
# ║  Unauthenticated invocation · Info disclosure                  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_serverless.sh"
SCRIPT_DESC="Serverless Function Discovery"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover and test serverless function endpoints across cloud"
    echo "  providers. Tests for unauthenticated invocation and info leaks."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --keyword KEYWORD      Keyword for function name generation"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "4" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }

# ── Output files ──
SERVERLESS_FINDINGS="${OUT_DIR}/cl_serverless_findings.txt"
> "$SERVERLESS_FINDINGS"

# ── Derive keyword if not set ──
if [ -z "${KEYWORD:-}" ] && [ -n "${DOMAIN:-}" ]; then
    KEYWORD=$(echo "$DOMAIN" | sed -E 's/\.(com|net|org|io|co|dev|app|cloud|xyz|info|biz)$//;s/\.[^.]*$//')
fi

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$SERVERLESS_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helpers ──
probe_url() {
    local url="$1"
    curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000 0"
}

probe_full() {
    local url="$1"
    local method="${2:-GET}"
    local status size body headers
    headers=$(curl -sk -D- -o /dev/null -w "\n%{http_code} %{size_download}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" -X "$method" "$url" 2>/dev/null || echo "")
    echo "$headers"
}

probe_body() {
    local url="$1"
    curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

# ── Build target domain list ──
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("$d")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("$DOMAIN")
fi

# ── Common function paths ──
FUNCTION_PATHS=(
    "api" "api/v1" "api/v2" "api/health" "api/status" "api/info"
    "api/test" "api/debug" "api/ping" "api/echo" "api/webhook"
    "api/hello" "api/handler" "api/function" "api/trigger"
    "api/auth" "api/login" "api/user" "api/users" "api/data"
    "api/search" "api/config" "api/settings" "api/version"
    "api/graphql" "api/rest" "api/callback"
)

# ── Lambda/API Gateway function names ──
LAMBDA_FUNCTIONS=(
    "handler" "index" "main" "app" "function" "lambda"
    "webhook" "api" "auth" "login" "process" "worker"
    "notify" "email" "upload" "download" "resize"
    "generate" "validate" "verify" "check" "health"
)

# ════════════════════════════════════════════════════════════════
# STEP 1: Extract serverless URLs from existing data
# ════════════════════════════════════════════════════════════════
info "Step 1: Extracting serverless URLs from existing data..."

serverless_urls="${OUT_DIR}/_cl_serverless_urls.txt"
> "$serverless_urls"

# Search through URLs file and discovered URLs
for url_source in "${URLS_FILE:-}" "${OUT_DIR}/urls.txt" "${OUT_DIR}/all_urls.txt" "${OUT_DIR}/surface_urls.txt"; do
    [ -z "$url_source" ] && continue
    [ ! -f "$url_source" ] && continue

    # Lambda URLs
    grep -oP 'https?://[a-zA-Z0-9._-]+\.lambda-url\.[a-z0-9-]+\.on\.aws[^\s"<>]*' "$url_source" 2>/dev/null >> "$serverless_urls" || true

    # API Gateway
    grep -oP 'https?://[a-zA-Z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^\s"<>]*' "$url_source" 2>/dev/null >> "$serverless_urls" || true

    # Azure Functions
    grep -oP 'https?://[a-zA-Z0-9._-]+\.azurewebsites\.net[^\s"<>]*' "$url_source" 2>/dev/null >> "$serverless_urls" || true

    # GCP Cloud Functions
    grep -oP 'https?://[a-z0-9-]+\.cloudfunctions\.net[^\s"<>]*' "$url_source" 2>/dev/null >> "$serverless_urls" || true

    # Vercel
    grep -oP 'https?://[a-zA-Z0-9._-]+\.vercel\.app[^\s"<>]*' "$url_source" 2>/dev/null >> "$serverless_urls" || true

    # Netlify
    grep -oP 'https?://[a-zA-Z0-9._-]+\.netlify\.app[^\s"<>]*' "$url_source" 2>/dev/null >> "$serverless_urls" || true
done

# Also check JS files for serverless references
if [ -d "${OUT_DIR}/js_downloads" ] && [ "$(ls -A "${OUT_DIR}/js_downloads" 2>/dev/null)" ]; then
    grep -roPh 'https?://[a-zA-Z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$serverless_urls" || true
    grep -roPh 'https?://[a-zA-Z0-9._-]+\.lambda-url\.[a-z0-9-]+\.on\.aws[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$serverless_urls" || true
    grep -roPh 'https?://[a-zA-Z0-9._-]+\.azurewebsites\.net[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$serverless_urls" || true
    grep -roPh 'https?://[a-z0-9-]+\.cloudfunctions\.net[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$serverless_urls" || true
fi

sort -u -o "$serverless_urls" "$serverless_urls" 2>/dev/null || true
extracted_count=$(count_lines "$serverless_urls")
log "  Extracted ${extracted_count} serverless URLs from existing data"

# ════════════════════════════════════════════════════════════════
# STEP 2: Vercel/Netlify function discovery on target domains
# ════════════════════════════════════════════════════════════════
info "Step 2: Vercel/Netlify function discovery..."

vercel_netlify_hits=0
for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"

        # Quick connectivity check
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        # Vercel: /api/* endpoints
        for func_path in "${FUNCTION_PATHS[@]}"; do
            test_url="${base_url}/${func_path}"
            result=$(probe_url "$test_url")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
                # Check response headers for serverless indicators
                headers=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")

                is_serverless=false
                platform=""
                if echo "$headers" | grep -qi 'x-vercel\|x-now\|vercel'; then
                    is_serverless=true; platform="Vercel"
                elif echo "$headers" | grep -qi 'x-nf-\|netlify'; then
                    is_serverless=true; platform="Netlify"
                elif echo "$headers" | grep -qi 'x-amzn-\|x-amz-\|lambda'; then
                    is_serverless=true; platform="AWS Lambda/API Gateway"
                elif echo "$headers" | grep -qi 'x-azure-\|azure'; then
                    is_serverless=true; platform="Azure Functions"
                elif echo "$headers" | grep -qi 'x-cloud-trace-context\|function-execution-id'; then
                    is_serverless=true; platform="GCP Cloud Functions"
                fi

                if $is_serverless; then
                    ((vercel_netlify_hits++)) || true
                    echo "$test_url" >> "$serverless_urls"
                    tag_finding "MEDIUM" "$test_url" "Serverless function (${platform}) — 200 (${size}B)"
                fi
            elif [ "$status" = "401" ] || [ "$status" = "403" ]; then
                # Function exists but requires auth
                headers=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")
                if echo "$headers" | grep -qi 'x-vercel\|x-now\|x-nf-\|netlify\|x-amzn-\|lambda\|x-azure-\|function-execution-id'; then
                    echo "$test_url" >> "$serverless_urls"
                    tag_finding "INFO" "$test_url" "Serverless function (auth required, ${status})"
                fi
            fi
        done

        # Netlify: /.netlify/functions/* endpoints
        for func in "${LAMBDA_FUNCTIONS[@]}"; do
            test_url="${base_url}/.netlify/functions/${func}"
            result=$(probe_url "$test_url")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" != "000" ] && [ "$status" != "404" ]; then
                ((vercel_netlify_hits++)) || true
                echo "$test_url" >> "$serverless_urls"

                if [ "$status" = "200" ]; then
                    tag_finding "MEDIUM" "$test_url" "Netlify function '${func}' — unauthenticated (200, ${size}B)"
                elif [ "$status" = "401" ] || [ "$status" = "403" ]; then
                    tag_finding "INFO" "$test_url" "Netlify function '${func}' exists (${status})"
                else
                    tag_finding "INFO" "$test_url" "Netlify function '${func}' — status ${status}"
                fi
            fi
        done

        break  # Use first working scheme
    done
done

log "  Vercel/Netlify discovery: ${vercel_netlify_hits} functions found"

# ════════════════════════════════════════════════════════════════
# STEP 3: Azure Functions probing
# ════════════════════════════════════════════════════════════════
info "Step 3: Azure Functions probing..."

azure_func_hits=0

# Probe keyword-based Azure Functions sites
if [ -n "${KEYWORD:-}" ]; then
    azure_func_domains=(
        "${KEYWORD}.azurewebsites.net"
        "${KEYWORD}-api.azurewebsites.net"
        "${KEYWORD}-func.azurewebsites.net"
        "${KEYWORD}-functions.azurewebsites.net"
        "${KEYWORD}-dev.azurewebsites.net"
        "${KEYWORD}-staging.azurewebsites.net"
        "${KEYWORD}-prod.azurewebsites.net"
    )

    for az_domain in "${azure_func_domains[@]}"; do
        base_url="https://${az_domain}"
        result=$(probe_url "$base_url")
        status=$(echo "$result" | awk '{print $1}')

        if [ "$status" != "000" ] && [ "$status" != "404" ]; then
            ((azure_func_hits++)) || true
            echo "$base_url" >> "$serverless_urls"
            tag_finding "MEDIUM" "$base_url" "Azure app service exists (${status})"

            # Probe function endpoints
            for func_path in "api/HttpTrigger" "api/HttpTrigger1" "api/webhook" "api/health" "api/function" "api/handler"; do
                func_url="${base_url}/${func_path}"
                func_result=$(probe_url "$func_url")
                func_status=$(echo "$func_result" | awk '{print $1}')
                func_size=$(echo "$func_result" | awk '{print $2}')

                if [ "$func_status" = "200" ] && [ "${func_size%.*}" -gt 0 ] 2>/dev/null; then
                    tag_finding "HIGH" "$func_url" "Azure Function unauthenticated — ${func_path} (200, ${func_size}B)"
                elif [ "$func_status" = "401" ] || [ "$func_status" = "403" ]; then
                    tag_finding "INFO" "$func_url" "Azure Function exists — ${func_path} (${func_status})"
                fi
            done
        fi
    done
fi

log "  Azure Functions: ${azure_func_hits} sites found"

# ════════════════════════════════════════════════════════════════
# STEP 4: Test discovered serverless URLs for unauthenticated access
# ════════════════════════════════════════════════════════════════
info "Step 4: Testing serverless URLs for unauthenticated invocation..."

sort -u -o "$serverless_urls" "$serverless_urls" 2>/dev/null || true
unauth_hits=0

while IFS= read -r url; do
    [ -z "$url" ] && continue

    # GET test
    get_result=$(probe_url "$url")
    get_status=$(echo "$get_result" | awk '{print $1}')
    get_size=$(echo "$get_result" | awk '{print $2}')

    # POST test
    post_result=$(curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/json" -d '{"test":true}' \
        "$url" 2>/dev/null || echo "000 0")
    post_status=$(echo "$post_result" | awk '{print $1}')
    post_size=$(echo "$post_result" | awk '{print $2}')

    if [ "$get_status" = "200" ] || [ "$post_status" = "200" ]; then
        ((unauth_hits++)) || true
        method="GET"
        resp_size="$get_size"
        [ "$post_status" = "200" ] && method="POST" && resp_size="$post_size"

        # Check response for info disclosure
        body=$(probe_body "$url")
        info_leak=""
        if echo "$body" | grep -qiP '(runtime|memory|region|function_name|aws_lambda|execution_id|cold_start|request_id)'; then
            info_leak=" [INFO LEAK detected]"
        fi

        # Skip if already tagged by earlier steps
        if ! grep -qF "$url" "$SERVERLESS_FINDINGS" 2>/dev/null; then
            tag_finding "HIGH" "$url" "Unauthenticated serverless invocation (${method} 200, ${resp_size}B)${info_leak}"
        fi
    fi

    # Check error responses for runtime disclosure
    if [ "$get_status" = "500" ] || [ "$post_status" = "500" ]; then
        body=$(probe_body "$url")
        if echo "$body" | grep -qiP '(traceback|stack trace|runtime|node\.js|python|\.NET|java\.lang)'; then
            tag_finding "MEDIUM" "$url" "Serverless function error disclosure — runtime/stack trace in 500 response"
        fi
    fi

done < "$serverless_urls"

log "  Unauthenticated invocation: ${unauth_hits} functions accessible"

# ════════════════════════════════════════════════════════════════
# STEP 5: GCP Cloud Functions probing
# ════════════════════════════════════════════════════════════════
info "Step 5: GCP Cloud Functions probing..."

gcp_func_hits=0

# Check extracted GCP function URLs
gcp_urls=$(grep -oP 'https?://[a-z0-9-]+\.cloudfunctions\.net[^\s]*' "$serverless_urls" 2>/dev/null | sort -u)
if [ -n "$gcp_urls" ]; then
    while IFS= read -r gcp_url; do
        [ -z "$gcp_url" ] && continue
        result=$(probe_url "$gcp_url")
        status=$(echo "$result" | awk '{print $1}')
        size=$(echo "$result" | awk '{print $2}')

        if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
            ((gcp_func_hits++)) || true
            if ! grep -qF "$gcp_url" "$SERVERLESS_FINDINGS" 2>/dev/null; then
                tag_finding "HIGH" "$gcp_url" "GCP Cloud Function unauthenticated (200, ${size}B)"
            fi
        fi
    done <<< "$gcp_urls"
fi

# Keyword-based GCP function probing
if [ -n "${KEYWORD:-}" ]; then
    AWS_REGIONS=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
    GCP_REGIONS=("us-central1" "us-east1" "europe-west1" "asia-east1")

    for region in "${GCP_REGIONS[@]}"; do
        for func in "handler" "api" "webhook" "auth" "function"; do
            gcp_url="https://${region}-${KEYWORD}.cloudfunctions.net/${func}"
            result=$(probe_url "$gcp_url")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" != "000" ] && [ "$status" != "404" ] && [ "$status" != "403" ]; then
                ((gcp_func_hits++)) || true
                tag_finding "MEDIUM" "$gcp_url" "GCP Cloud Function '${func}' in ${region} (${status}, ${size}B)"
            fi
        done
    done
fi

log "  GCP Cloud Functions: ${gcp_func_hits} functions found"

# ── Cleanup ──
rm -f "$serverless_urls"

# ── Dedup output ──
[ -f "$SERVERLESS_FINDINGS" ] && sort -u -o "$SERVERLESS_FINDINGS" "$SERVERLESS_FINDINGS" 2>/dev/null || true

# ── Summary ──
total_findings=$(count_lines "$SERVERLESS_FINDINGS")
high_count=$(grep -c '^\[HIGH\]' "$SERVERLESS_FINDINGS" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$SERVERLESS_FINDINGS" 2>/dev/null || echo 0)
info_count=$(grep -c '^\[INFO\]' "$SERVERLESS_FINDINGS" 2>/dev/null || echo 0)

log "Serverless function discovery complete:"
log "  Total findings:  ${total_findings}"
log "    HIGH:          ${high_count}"
log "    MEDIUM:        ${medium_count}"
log "    INFO:          ${info_count}"
log "  Output: ${SERVERLESS_FINDINGS}"
