#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_cloud_enum.sh — Cloud Asset Enumeration                  ║
# ║  cloud_enum + manual S3/Azure/GCP bucket probing              ║
# ║  Keyword variations · Open listing detection                  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_cloud_enum.sh"
SCRIPT_DESC="Cloud Asset Enumeration"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Enumerate cloud storage assets (S3, Azure Blob, GCP Storage) using"
    echo "  cloud_enum and manual probing. Generates keyword variations for"
    echo "  comprehensive bucket discovery."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --keyword KEYWORD      Keyword for bucket/resource name generation"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "1" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${KEYWORD:-}" ]; then
    err "Provide --domain, --domains, or --keyword"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }
has_cloud_enum=false
check_tool cloud_enum 2>/dev/null && has_cloud_enum=true

# ── Output files ──
CLOUD_ASSETS="${OUT_DIR}/cl_cloud_assets.txt"
CLOUD_FINDINGS="${OUT_DIR}/cl_cloud_enum_findings.txt"
> "$CLOUD_ASSETS"
> "$CLOUD_FINDINGS"

# ── Derive keyword from domain if not provided ──
if [ -z "${KEYWORD:-}" ]; then
    if [ -n "${DOMAIN:-}" ]; then
        # Strip TLD: example.com -> example, sub.example.co.uk -> sub.example
        KEYWORD=$(echo "$DOMAIN" | sed -E 's/\.(com|net|org|io|co|dev|app|cloud|xyz|info|biz|us|uk|de|fr|co\.uk|com\.au|co\.jp)$//;s/\.[^.]*$//')
        log "Derived keyword from domain: ${KEYWORD}"
    elif [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
        # Use first domain in file
        first_domain=$(head -1 "$DOMAINS_FILE" | sed 's/\*\.//')
        KEYWORD=$(echo "$first_domain" | sed -E 's/\.(com|net|org|io|co|dev|app|cloud|xyz|info|biz|us|uk|de|fr|co\.uk|com\.au|co\.jp)$//;s/\.[^.]*$//')
        log "Derived keyword from first domain: ${KEYWORD}"
    fi
fi

if [ -z "${KEYWORD:-}" ]; then
    err "Could not determine keyword — provide --keyword explicitly"
    exit 1
fi

# ── Build keyword variations ──
KEYWORD_VARIATIONS=(
    "$KEYWORD"
    "${KEYWORD}-dev"
    "${KEYWORD}-staging"
    "${KEYWORD}-prod"
    "${KEYWORD}-backup"
    "${KEYWORD}-assets"
    "${KEYWORD}-uploads"
    "${KEYWORD}-data"
    "${KEYWORD}-cdn"
    "${KEYWORD}-media"
    "${KEYWORD}-static"
)

info "Base keyword: ${KEYWORD}"
info "Testing ${#KEYWORD_VARIATIONS[@]} keyword variations"

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$CLOUD_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helper: curl with status + response body check ──
probe_url() {
    local url="$1"
    curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000 0"
}

probe_body() {
    local url="$1"
    curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

# ════════════════════════════════════════════════════════════════
# STEP 1: cloud_enum (if available)
# ════════════════════════════════════════════════════════════════
info "Step 1: cloud_enum automated scanning..."

if $has_cloud_enum; then
    cloud_enum_out="${OUT_DIR}/cloud_enum_raw.txt"
    > "$cloud_enum_out"

    # Build keyword file for cloud_enum
    keyword_file="${OUT_DIR}/_cl_keywords.txt"
    printf '%s\n' "${KEYWORD_VARIATIONS[@]}" > "$keyword_file"

    info "  Running cloud_enum with ${#KEYWORD_VARIATIONS[@]} keywords..."
    cloud_enum -k "$keyword_file" -l "$cloud_enum_out" 2>/dev/null || true

    if [ -s "$cloud_enum_out" ]; then
        ce_count=$(count_lines "$cloud_enum_out")
        log "  cloud_enum found ${ce_count} results"
        # Extract bucket/blob URLs to assets file
        grep -oP 'https?://[^\s]+' "$cloud_enum_out" 2>/dev/null >> "$CLOUD_ASSETS" || true
        # Copy findings
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            [[ "$line" =~ ^# ]] && continue
            url=$(echo "$line" | grep -oP 'https?://[^\s]+' || echo "$line")
            tag_finding "MEDIUM" "$url" "cloud_enum discovery"
        done < "$cloud_enum_out"
    else
        warn "  cloud_enum returned no results"
    fi

    rm -f "$keyword_file"
else
    warn "  cloud_enum not installed — using manual probing only"
fi

# ════════════════════════════════════════════════════════════════
# STEP 2: Manual S3 bucket probing
# ════════════════════════════════════════════════════════════════
info "Step 2: Manual S3 bucket probing..."

s3_hits=0
for kw in "${KEYWORD_VARIATIONS[@]}"; do
    # Format 1: https://BUCKET.s3.amazonaws.com
    s3_url1="https://${kw}.s3.amazonaws.com"
    result=$(probe_url "$s3_url1")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" != "000" ] && [ "$status" != "404" ]; then
        echo "$s3_url1" >> "$CLOUD_ASSETS"
        ((s3_hits++)) || true

        if [ "$status" = "200" ]; then
            # Check for open listing (XML ListBucketResult)
            body=$(probe_body "$s3_url1")
            if echo "$body" | grep -q 'ListBucketResult\|<Contents>'; then
                tag_finding "HIGH" "$s3_url1" "S3 bucket LISTABLE (open listing) — ${size}B"
            else
                tag_finding "MEDIUM" "$s3_url1" "S3 bucket exists and accessible (200) — ${size}B"
            fi
        elif [ "$status" = "403" ]; then
            tag_finding "INFO" "$s3_url1" "S3 bucket exists (403 Forbidden)"
        elif [[ "$status" =~ ^(301|302|307)$ ]]; then
            tag_finding "INFO" "$s3_url1" "S3 bucket exists (redirect ${status})"
        fi
    fi

    # Format 2: https://s3.amazonaws.com/BUCKET
    s3_url2="https://s3.amazonaws.com/${kw}"
    result=$(probe_url "$s3_url2")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" != "000" ] && [ "$status" != "404" ]; then
        echo "$s3_url2" >> "$CLOUD_ASSETS"
        ((s3_hits++)) || true

        if [ "$status" = "200" ]; then
            body=$(probe_body "$s3_url2")
            if echo "$body" | grep -q 'ListBucketResult\|<Contents>'; then
                tag_finding "HIGH" "$s3_url2" "S3 bucket LISTABLE (path-style) — ${size}B"
            else
                tag_finding "MEDIUM" "$s3_url2" "S3 bucket accessible (path-style, 200) — ${size}B"
            fi
        elif [ "$status" = "403" ]; then
            tag_finding "INFO" "$s3_url2" "S3 bucket exists (path-style, 403)"
        fi
    fi
done

log "  S3 probing: ${s3_hits} buckets found"

# ════════════════════════════════════════════════════════════════
# STEP 3: Manual Azure Blob Storage probing
# ════════════════════════════════════════════════════════════════
info "Step 3: Manual Azure Blob Storage probing..."

azure_hits=0
for kw in "${KEYWORD_VARIATIONS[@]}"; do
    azure_url="https://${kw}.blob.core.windows.net"
    result=$(probe_url "$azure_url")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" != "000" ] && [ "$status" != "404" ]; then
        echo "$azure_url" >> "$CLOUD_ASSETS"
        ((azure_hits++)) || true

        if [ "$status" = "200" ]; then
            tag_finding "MEDIUM" "$azure_url" "Azure Blob storage account exists (200) — ${size}B"
        elif [ "$status" = "400" ]; then
            # 400 = exists but no container specified
            tag_finding "INFO" "$azure_url" "Azure Blob storage account exists (400 — no container)"
        elif [ "$status" = "403" ]; then
            tag_finding "INFO" "$azure_url" "Azure Blob storage account exists (403)"
        fi
    fi

    # Also probe with container listing
    azure_list_url="https://${kw}.blob.core.windows.net/?comp=list"
    result=$(probe_url "$azure_list_url")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
        body=$(probe_body "$azure_list_url")
        if echo "$body" | grep -q 'EnumerationResults\|<Containers>'; then
            tag_finding "HIGH" "$azure_list_url" "Azure container listing ENABLED — ${size}B"
        fi
    fi
done

log "  Azure probing: ${azure_hits} storage accounts found"

# ════════════════════════════════════════════════════════════════
# STEP 4: Manual GCP Storage probing
# ════════════════════════════════════════════════════════════════
info "Step 4: Manual GCP Storage probing..."

gcp_hits=0
for kw in "${KEYWORD_VARIATIONS[@]}"; do
    gcp_url="https://storage.googleapis.com/${kw}"
    result=$(probe_url "$gcp_url")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" != "000" ] && [ "$status" != "404" ]; then
        echo "$gcp_url" >> "$CLOUD_ASSETS"
        ((gcp_hits++)) || true

        if [ "$status" = "200" ]; then
            body=$(probe_body "$gcp_url")
            if echo "$body" | grep -q 'ListBucketResult\|<Contents>'; then
                tag_finding "HIGH" "$gcp_url" "GCP bucket LISTABLE — ${size}B"
            else
                tag_finding "MEDIUM" "$gcp_url" "GCP bucket accessible (200) — ${size}B"
            fi
        elif [ "$status" = "403" ]; then
            tag_finding "INFO" "$gcp_url" "GCP bucket exists (403)"
        fi
    fi
done

log "  GCP probing: ${gcp_hits} buckets found"

# ════════════════════════════════════════════════════════════════
# STEP 5: Extract cloud references from existing URL/JS files
# ════════════════════════════════════════════════════════════════
info "Step 5: Extracting cloud references from URL/JS files..."

ref_hits=0
urls_to_scan=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    urls_to_scan="$URLS_FILE"
elif [ -f "${OUT_DIR}/urls.txt" ]; then
    urls_to_scan="${OUT_DIR}/urls.txt"
fi

if [ -n "$urls_to_scan" ]; then
    # Extract S3 URLs from discovered URLs
    grep -oP 'https?://[a-zA-Z0-9._-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"<>]*' "$urls_to_scan" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true
    grep -oP 'https?://s3[a-zA-Z0-9.-]*\.amazonaws\.com/[a-zA-Z0-9._-]+[^\s"<>]*' "$urls_to_scan" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true

    # Extract Azure Blob URLs
    grep -oP 'https?://[a-zA-Z0-9._-]+\.blob\.core\.windows\.net[^\s"<>]*' "$urls_to_scan" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true

    # Extract GCP URLs
    grep -oP 'https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+[^\s"<>]*' "$urls_to_scan" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true

    # Extract DigitalOcean Spaces
    grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z0-9]+\.digitaloceanspaces\.com[^\s"<>]*' "$urls_to_scan" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true

    ref_hits=$(wc -l < "$CLOUD_ASSETS" 2>/dev/null | tr -d ' ' || echo 0)
fi

# Also scan JS downloads if they exist
if [ -d "${OUT_DIR}/js_downloads" ] && [ "$(ls -A "${OUT_DIR}/js_downloads" 2>/dev/null)" ]; then
    grep -roPh 'https?://[a-zA-Z0-9._-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true
    grep -roPh 'https?://[a-zA-Z0-9._-]+\.blob\.core\.windows\.net[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true
    grep -roPh 'https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+[^\s"'"'"'<>]*' "${OUT_DIR}/js_downloads/" 2>/dev/null | sort -u >> "$CLOUD_ASSETS" || true
fi

log "  Cloud references extracted from files: ${ref_hits} total assets"

# ── Dedup output files ──
for f in "$CLOUD_ASSETS" "$CLOUD_FINDINGS"; do
    [ -f "$f" ] && sort -u -o "$f" "$f" 2>/dev/null || true
done

# ── Summary ──
total_assets=$(count_lines "$CLOUD_ASSETS")
total_findings=$(count_lines "$CLOUD_FINDINGS")
high_count=$(grep -c '^\[HIGH\]' "$CLOUD_FINDINGS" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$CLOUD_FINDINGS" 2>/dev/null || echo 0)
info_count=$(grep -c '^\[INFO\]' "$CLOUD_FINDINGS" 2>/dev/null || echo 0)

log "Cloud asset enumeration complete:"
log "  Total cloud assets:  ${total_assets}"
log "  Total findings:      ${total_findings}"
log "    HIGH:              ${high_count}"
log "    MEDIUM:            ${medium_count}"
log "    INFO:              ${info_count}"
log "  Output: ${CLOUD_ASSETS}"
log "  Output: ${CLOUD_FINDINGS}"
