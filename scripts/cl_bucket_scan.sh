#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_bucket_scan.sh — Deep Bucket Permission Testing           ║
# ║  s3scanner + gcpbucketbrute + manual ACL/listing checks       ║
# ║  Permission classification: READ_ONLY · LIST_OK · WRITE_OK   ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_bucket_scan.sh"
SCRIPT_DESC="Deep Bucket Permission Testing"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test discovered cloud storage buckets for permission misconfigurations."
    echo "  Reads cl_cloud_assets.txt from Phase 1 for bucket URLs."
    echo "  Classifies: READ_ONLY, LIST_OK, ACL_READABLE."
    echo "  Does NOT perform write operations."
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

phase_header "2" "$SCRIPT_DESC"

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }
has_s3scanner=false
has_gcpbrute=false
check_tool s3scanner 2>/dev/null && has_s3scanner=true
check_tool gcpbucketbrute 2>/dev/null && has_gcpbrute=true

# ── Output files ──
BUCKET_FINDINGS="${OUT_DIR}/cl_bucket_scan_findings.txt"
> "$BUCKET_FINDINGS"

# ── Input: cloud assets from phase 1 ──
CLOUD_ASSETS="${OUT_DIR}/cl_cloud_assets.txt"
if [ ! -s "$CLOUD_ASSETS" ]; then
    warn "cl_cloud_assets.txt not found or empty — nothing to scan"
    warn "Run cl_cloud_enum.sh (Phase 1) first to discover cloud assets"
    log "Bucket scan complete: 0 findings"
    log "  Output: ${BUCKET_FINDINGS}"
    exit 0
fi

total_assets=$(count_lines "$CLOUD_ASSETS")
info "Loaded ${total_assets} cloud assets from Phase 1"

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$BUCKET_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helper ──
probe_url() {
    local url="$1"
    curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000 0"
}

probe_body() {
    local url="$1"
    curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

probe_headers() {
    local url="$1"
    curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

# ── Extract bucket names from URLs ──
extract_s3_buckets() {
    local file="$1"
    # Format: BUCKET.s3.amazonaws.com or s3.amazonaws.com/BUCKET
    grep -oP '(?<=https?://)[a-zA-Z0-9._-]+(?=\.s3[a-zA-Z0-9.-]*\.amazonaws\.com)' "$file" 2>/dev/null || true
    grep -oP '(?<=s3[a-zA-Z0-9.-]*\.amazonaws\.com/)[a-zA-Z0-9._-]+' "$file" 2>/dev/null || true
}

extract_azure_accounts() {
    local file="$1"
    grep -oP '(?<=https?://)[a-zA-Z0-9._-]+(?=\.blob\.core\.windows\.net)' "$file" 2>/dev/null || true
}

extract_gcp_buckets() {
    local file="$1"
    grep -oP '(?<=storage\.googleapis\.com/)[a-zA-Z0-9._-]+' "$file" 2>/dev/null || true
}

# ════════════════════════════════════════════════════════════════
# STEP 1: s3scanner (if available)
# ════════════════════════════════════════════════════════════════
info "Step 1: Automated S3 scanning..."

s3_buckets_file="${OUT_DIR}/_cl_s3_buckets.txt"
extract_s3_buckets "$CLOUD_ASSETS" | sort -u > "$s3_buckets_file"
s3_bucket_count=$(count_lines "$s3_buckets_file")

if $has_s3scanner && [ "$s3_bucket_count" -gt 0 ]; then
    info "  Running s3scanner on ${s3_bucket_count} S3 buckets..."
    s3scanner_out="${OUT_DIR}/s3scanner_results.txt"
    s3scanner --bucket-file "$s3_buckets_file" 2>/dev/null > "$s3scanner_out" || true

    if [ -s "$s3scanner_out" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            bucket=$(echo "$line" | awk '{print $1}')
            perms=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ *//')

            case "${perms,,}" in
                *write*|*full_control*)
                    tag_finding "CRITICAL" "https://${bucket}.s3.amazonaws.com" "S3 bucket WRITABLE — ${perms}"
                    ;;
                *read*|*list*)
                    tag_finding "HIGH" "https://${bucket}.s3.amazonaws.com" "S3 bucket READABLE — ${perms}"
                    ;;
                *)
                    tag_finding "MEDIUM" "https://${bucket}.s3.amazonaws.com" "S3 bucket result — ${perms}"
                    ;;
            esac
        done < "$s3scanner_out"
        log "  s3scanner: $(count_lines "$s3scanner_out") results"
    fi
else
    if [ "$s3_bucket_count" -eq 0 ]; then
        info "  No S3 buckets to scan"
    else
        warn "  s3scanner not installed — using manual probing"
    fi
fi

# ════════════════════════════════════════════════════════════════
# STEP 2: gcpbucketbrute (if available)
# ════════════════════════════════════════════════════════════════
info "Step 2: GCP bucket scanning..."

gcp_buckets_file="${OUT_DIR}/_cl_gcp_buckets.txt"
extract_gcp_buckets "$CLOUD_ASSETS" | sort -u > "$gcp_buckets_file"
gcp_bucket_count=$(count_lines "$gcp_buckets_file")

if $has_gcpbrute && [ -n "${KEYWORD:-}" ]; then
    info "  Running gcpbucketbrute with keyword: ${KEYWORD}"
    gcpbrute_out="${OUT_DIR}/gcpbucketbrute_results.txt"
    gcpbucketbrute -keyword "$KEYWORD" 2>/dev/null > "$gcpbrute_out" || true

    if [ -s "$gcpbrute_out" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            [[ "$line" =~ ^# ]] && continue
            bucket_url=$(echo "$line" | grep -oP 'https?://[^\s]+' || echo "")
            if [ -n "$bucket_url" ]; then
                tag_finding "MEDIUM" "$bucket_url" "gcpbucketbrute discovery"
            fi
        done < "$gcpbrute_out"
        log "  gcpbucketbrute: $(count_lines "$gcpbrute_out") results"
    fi
elif [ "$gcp_bucket_count" -eq 0 ]; then
    info "  No GCP buckets to scan"
else
    warn "  gcpbucketbrute not installed — using manual probing"
fi

# ════════════════════════════════════════════════════════════════
# STEP 3: Manual S3 permission testing
# ════════════════════════════════════════════════════════════════
info "Step 3: Manual S3 permission testing..."

s3_tested=0
while IFS= read -r bucket; do
    [ -z "$bucket" ] && continue
    ((s3_tested++)) || true
    bucket_url="https://${bucket}.s3.amazonaws.com"

    # HEAD request — does it exist?
    head_result=$(curl -sk -o /dev/null -w "%{http_code}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -I "$bucket_url" 2>/dev/null || echo "000")

    if [ "$head_result" = "000" ] || [ "$head_result" = "404" ]; then
        continue
    fi

    # GET request — is it listable?
    get_result=$(probe_url "$bucket_url")
    get_status=$(echo "$get_result" | awk '{print $1}')
    get_size=$(echo "$get_result" | awk '{print $2}')

    if [ "$get_status" = "200" ]; then
        body=$(probe_body "$bucket_url")
        if echo "$body" | grep -q 'ListBucketResult\|<Contents>'; then
            # Count objects in listing
            obj_count=$(echo "$body" | grep -c '<Key>' 2>/dev/null || echo 0)
            tag_finding "HIGH" "$bucket_url" "LIST_OK — S3 bucket listing enabled (${obj_count} objects, ${get_size}B)"
        else
            tag_finding "MEDIUM" "$bucket_url" "READ_ONLY — S3 bucket returns 200 (${get_size}B)"
        fi
    elif [ "$get_status" = "403" ]; then
        # Bucket exists but not listable — check ACL
        :
    fi

    # Check ACL: GET ?acl
    acl_result=$(probe_url "${bucket_url}/?acl")
    acl_status=$(echo "$acl_result" | awk '{print $1}')
    acl_size=$(echo "$acl_result" | awk '{print $2}')

    if [ "$acl_status" = "200" ] && [ "${acl_size%.*}" -gt 0 ] 2>/dev/null; then
        acl_body=$(probe_body "${bucket_url}/?acl")
        if echo "$acl_body" | grep -q 'AccessControlPolicy\|<Grant>'; then
            # Check for public grants
            if echo "$acl_body" | grep -q 'AllUsers\|AuthenticatedUsers'; then
                tag_finding "HIGH" "${bucket_url}/?acl" "ACL_READABLE — public grants detected"
            else
                tag_finding "MEDIUM" "${bucket_url}/?acl" "ACL_READABLE — ACL exposed (no public grants)"
            fi
        fi
    fi

done < "$s3_buckets_file"

log "  S3 manual testing: ${s3_tested} buckets tested"

# ════════════════════════════════════════════════════════════════
# STEP 4: Azure Blob permission testing
# ════════════════════════════════════════════════════════════════
info "Step 4: Azure Blob permission testing..."

azure_accounts_file="${OUT_DIR}/_cl_azure_accounts.txt"
extract_azure_accounts "$CLOUD_ASSETS" | sort -u > "$azure_accounts_file"
azure_tested=0

while IFS= read -r account; do
    [ -z "$account" ] && continue
    ((azure_tested++)) || true
    base_url="https://${account}.blob.core.windows.net"

    # Check container listing
    list_url="${base_url}/?comp=list"
    result=$(probe_url "$list_url")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
        body=$(probe_body "$list_url")
        if echo "$body" | grep -q 'EnumerationResults\|<Containers>'; then
            # Extract container names
            containers=$(echo "$body" | grep -oP '<Name>\K[^<]+' 2>/dev/null | head -20)
            container_count=$(echo "$containers" | grep -c . 2>/dev/null || echo 0)
            tag_finding "HIGH" "$list_url" "Azure container listing ENABLED — ${container_count} containers"

            # Probe each discovered container for blob listing
            while IFS= read -r container; do
                [ -z "$container" ] && continue
                blob_list_url="${base_url}/${container}?restype=container&comp=list"
                blob_result=$(probe_url "$blob_list_url")
                blob_status=$(echo "$blob_result" | awk '{print $1}')
                blob_size=$(echo "$blob_result" | awk '{print $2}')

                if [ "$blob_status" = "200" ] && [ "${blob_size%.*}" -gt 0 ] 2>/dev/null; then
                    blob_body=$(probe_body "$blob_list_url")
                    if echo "$blob_body" | grep -q 'EnumerationResults\|<Blobs>'; then
                        blob_count=$(echo "$blob_body" | grep -c '<Name>' 2>/dev/null || echo 0)
                        tag_finding "HIGH" "$blob_list_url" "Azure blob listing — container '${container}' (${blob_count} blobs)"
                    fi
                fi
            done <<< "$containers"
        fi
    elif [ "$status" = "403" ]; then
        # Account exists, try common container names
        for container in "public" "uploads" "images" "media" "assets" "files" "data" "backup" "static" "cdn"; do
            container_url="${base_url}/${container}?restype=container&comp=list"
            c_result=$(probe_url "$container_url")
            c_status=$(echo "$c_result" | awk '{print $1}')
            c_size=$(echo "$c_result" | awk '{print $2}')

            if [ "$c_status" = "200" ] && [ "${c_size%.*}" -gt 0 ] 2>/dev/null; then
                c_body=$(probe_body "$container_url")
                if echo "$c_body" | grep -q 'EnumerationResults\|<Blobs>'; then
                    tag_finding "HIGH" "$container_url" "Azure blob listing — container '${container}' accessible"
                fi
            fi
        done
    fi

done < "$azure_accounts_file"

log "  Azure testing: ${azure_tested} accounts tested"

# ════════════════════════════════════════════════════════════════
# STEP 5: GCP bucket permission testing
# ════════════════════════════════════════════════════════════════
info "Step 5: GCP bucket permission testing..."

gcp_tested=0
while IFS= read -r bucket; do
    [ -z "$bucket" ] && continue
    ((gcp_tested++)) || true
    gcp_url="https://storage.googleapis.com/${bucket}"

    result=$(probe_url "$gcp_url")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')

    if [ "$status" = "200" ]; then
        body=$(probe_body "$gcp_url")
        if echo "$body" | grep -q 'ListBucketResult\|<Contents>'; then
            obj_count=$(echo "$body" | grep -c '<Key>' 2>/dev/null || echo 0)
            tag_finding "HIGH" "$gcp_url" "LIST_OK — GCP bucket listing enabled (${obj_count} objects)"
        else
            tag_finding "MEDIUM" "$gcp_url" "READ_ONLY — GCP bucket returns 200 (${size}B)"
        fi
    elif [ "$status" = "403" ]; then
        tag_finding "INFO" "$gcp_url" "GCP bucket exists (403 — authenticated access only)"
    fi

    # Check IAM policy (unauthenticated)
    iam_url="https://www.googleapis.com/storage/v1/b/${bucket}/iam"
    iam_result=$(probe_url "$iam_url")
    iam_status=$(echo "$iam_result" | awk '{print $1}')

    if [ "$iam_status" = "200" ]; then
        iam_body=$(probe_body "$iam_url")
        if echo "$iam_body" | grep -q 'allUsers\|allAuthenticatedUsers'; then
            tag_finding "HIGH" "$iam_url" "GCP bucket IAM policy exposes public access"
        else
            tag_finding "MEDIUM" "$iam_url" "GCP bucket IAM policy readable"
        fi
    fi

done < "$gcp_buckets_file"

log "  GCP testing: ${gcp_tested} buckets tested"

# ── Cleanup temp files ──
rm -f "$s3_buckets_file" "$azure_accounts_file" "$gcp_buckets_file"

# ── Dedup output ──
[ -f "$BUCKET_FINDINGS" ] && sort -u -o "$BUCKET_FINDINGS" "$BUCKET_FINDINGS" 2>/dev/null || true

# ── Summary ──
total_findings=$(count_lines "$BUCKET_FINDINGS")
critical_count=$(grep -c '^\[CRITICAL\]' "$BUCKET_FINDINGS" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$BUCKET_FINDINGS" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$BUCKET_FINDINGS" 2>/dev/null || echo 0)
info_count=$(grep -c '^\[INFO\]' "$BUCKET_FINDINGS" 2>/dev/null || echo 0)

log "Bucket permission testing complete:"
log "  Total findings:  ${total_findings}"
log "    CRITICAL:      ${critical_count}"
log "    HIGH:          ${high_count}"
log "    MEDIUM:        ${medium_count}"
log "    INFO:          ${info_count}"
log "  Output: ${BUCKET_FINDINGS}"
