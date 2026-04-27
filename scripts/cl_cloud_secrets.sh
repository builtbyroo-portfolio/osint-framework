#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_cloud_secrets.sh — Cloud Secret & Credential Scanning     ║
# ║  AWS keys · Azure creds · GCP service accounts · Firebase     ║
# ║  Stripe · Twilio · Heroku · Public-key filtering               ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_cloud_secrets.sh"
SCRIPT_DESC="Cloud Secret & Credential Scanning"
MAX_JS="${MAX_JS:-200}"
MAX_PAGES="${MAX_PAGES:-20}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Scan JavaScript files, HTML source, and config endpoints for"
    echo "  cloud credentials and API keys. Filters out public-by-design"
    echo "  keys (analytics, tag managers, reCAPTCHA site keys)."
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

phase_header "8" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }
has_aws_cli=false
check_tool aws 2>/dev/null && has_aws_cli=true

# ── Output files ──
SECRETS_FINDINGS="${OUT_DIR}/cl_cloud_secrets_findings.txt"
> "$SECRETS_FINDINGS"

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$SECRETS_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helpers ──
probe_body() {
    local url="$1"
    curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

# ── Build target list ──
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("$d")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("$DOMAIN")
fi

# ── Credential regex patterns ──
# Format: "name|regex|severity|description"
CREDENTIAL_PATTERNS=(
    "AWS_ACCESS_KEY|AKIA[A-Z0-9]{16}|CRITICAL|AWS Access Key ID"
    "AWS_SECRET_NEAR_AKIA|(?:aws_secret|secret_key|SecretAccessKey|aws_secret_access_key)['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9/+=]{40})|CRITICAL|AWS Secret Access Key (near context)"
    "AZURE_CONN_STRING|AccountName=[a-zA-Z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,}|CRITICAL|Azure Storage Connection String"
    "AZURE_SAS_TOKEN|sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&s[a-z]=[a-zA-Z0-9%&=]+|HIGH|Azure SAS Token"
    "GCP_SERVICE_ACCOUNT|[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.iam\\.gserviceaccount\\.com|HIGH|GCP Service Account"
    "GCP_API_KEY|AIzaSy[A-Za-z0-9_-]{33}|MEDIUM|Google API Key (check scope/restrictions)"
    "FIREBASE_CONFIG|apiKey.*authDomain.*projectId|HIGH|Firebase Configuration Block"
    "FIREBASE_API_KEY|(?:firebase|firebaseConfig)[^}]*apiKey['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9_-]+)|HIGH|Firebase API Key"
    "HEROKU_API_KEY|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|HIGH|Heroku API Key (UUID format near context)"
    "STRIPE_SECRET|sk_live_[A-Za-z0-9]{24,}|CRITICAL|Stripe Secret Key (live)"
    "STRIPE_RESTRICTED|rk_live_[A-Za-z0-9]{24,}|CRITICAL|Stripe Restricted Key (live)"
    "TWILIO_API_KEY|SK[a-f0-9]{32}|HIGH|Twilio API Key"
    "TWILIO_ACCOUNT_SID|AC[a-f0-9]{32}|MEDIUM|Twilio Account SID"
    "SENDGRID_API_KEY|SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}|CRITICAL|SendGrid API Key"
    "SLACK_TOKEN|xox[bpras]-[A-Za-z0-9-]{10,}|CRITICAL|Slack Token"
    "SLACK_WEBHOOK|https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|HIGH|Slack Webhook URL"
    "GITHUB_TOKEN|gh[pousr]_[A-Za-z0-9_]{36,}|CRITICAL|GitHub Personal Access Token"
    "GITLAB_TOKEN|glpat-[A-Za-z0-9_-]{20,}|CRITICAL|GitLab Personal Access Token"
    "MAILGUN_API_KEY|key-[a-z0-9]{32}|HIGH|Mailgun API Key"
    "SQUARE_ACCESS_TOKEN|sq0atp-[A-Za-z0-9_-]{22,}|CRITICAL|Square Access Token"
    "SQUARE_OAUTH_SECRET|sq0csp-[A-Za-z0-9_-]{43}|CRITICAL|Square OAuth Secret"
    "SHOPIFY_ACCESS_TOKEN|shpat_[a-fA-F0-9]{32}|CRITICAL|Shopify Access Token"
    "SHOPIFY_SHARED_SECRET|shpss_[a-fA-F0-9]{32}|CRITICAL|Shopify Shared Secret"
    'PAYPAL_BRAINTREE_TOKEN|access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}|CRITICAL|PayPal/Braintree Access Token'
    "PRIVATE_KEY|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|CRITICAL|Private Key"
    "MONGODB_URI|mongodb(\\+srv)?://[a-zA-Z0-9._:%-]+@[a-zA-Z0-9._-]+|CRITICAL|MongoDB Connection String"
    "POSTGRES_URI|postgres(ql)?://[a-zA-Z0-9._:%-]+@[a-zA-Z0-9._-]+|CRITICAL|PostgreSQL Connection String"
    "MYSQL_URI|mysql://[a-zA-Z0-9._:%-]+@[a-zA-Z0-9._-]+|CRITICAL|MySQL Connection String"
    "JWT_SECRET|(?:jwt[_-]?secret|JWT_SECRET)['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9+/=_-]{16,})|CRITICAL|JWT Secret"
    "GENERIC_API_KEY|(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9_-]{20,})|MEDIUM|Generic API Key"
    "GENERIC_PASSWORD|(?:password|passwd|pwd)['\"]?\\s*[:=]\\s*['\"]?([^'\"\\s]{8,})|HIGH|Hardcoded Password"
    "GENERIC_SECRET|(?:secret|token|auth)[_-]?(?:key|token|secret)?['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9+/=_-]{20,})|MEDIUM|Generic Secret/Token"
)

# ── Public-by-design patterns to FILTER OUT ──
PUBLIC_KEY_PATTERNS=(
    "UA-[0-9]+-[0-9]+"          # Google Analytics Universal
    "G-[A-Z0-9]{10,}"          # Google Analytics GA4
    "GT-[A-Z0-9]{6,}"          # Google Tag Manager ID
    "GTM-[A-Z0-9]{6,}"         # Google Tag Manager Container
    "AW-[0-9]{9,}"             # Google Ads
    "ca-pub-[0-9]+"            # Google AdSense
    "6L[a-zA-Z0-9_-]{38}"     # reCAPTCHA site key (public)
    "pk_live_[A-Za-z0-9]+"     # Stripe publishable key (public)
    "pk_test_[A-Za-z0-9]+"     # Stripe test publishable key
    "sb-[a-z0-9]+-[0-9]+"     # PayPal sandbox
    "AAAAAA[A-Za-z0-9]+"       # Firebase Messaging (public)
)

# Noise filter regex — things that are public by design
NOISE_FILTER='(google-analytics|googletagmanager|gtag|UA-[0-9]+-[0-9]+|G-[A-Z0-9]+|GT-[A-Z0-9]+|GTM-[A-Z0-9]+|AW-[0-9]+|ca-pub-[0-9]+|fbq|_fbp|fb-root|facebook\.com/tr|connect\.facebook\.net|amplitude\.com|segment\.com|segment\.io|mixpanel|heapanalytics|hotjar|fullstory|logrocket|bugsnag|sentry\.io.*public|datadogrumjs|intercom|zendesk|statuspage|recaptcha.*sitekey|grecaptcha|pk_live_|pk_test_|Amplitude|ReadMe|readme\.io)'

# ════════════════════════════════════════════════════════════════
# STEP 1: Scan JS files for credentials
# ════════════════════════════════════════════════════════════════
info "Step 1: Scanning JavaScript files for cloud credentials..."

js_secret_hits=0

# Use existing JS downloads if available
js_scan_dir="${OUT_DIR}/js_downloads"
if [ ! -d "$js_scan_dir" ] || [ -z "$(ls -A "$js_scan_dir" 2>/dev/null)" ]; then
    # Download JS files for scanning
    js_scan_dir="${OUT_DIR}/js_secret_downloads"
    mkdir -p "$js_scan_dir"

    js_urls=""
    if [ -f "${OUT_DIR}/js_files.txt" ] && [ -s "${OUT_DIR}/js_files.txt" ]; then
        js_urls="${OUT_DIR}/js_files.txt"
    elif [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
        grep -iP '\.(js|mjs)(\?|$)' "$URLS_FILE" 2>/dev/null | sort -u > "${OUT_DIR}/_cl_js_for_secrets.txt" || true
        js_urls="${OUT_DIR}/_cl_js_for_secrets.txt"
    fi

    if [ -n "$js_urls" ] && [ -f "$js_urls" ] && [ -s "$js_urls" ]; then
        js_count=$(count_lines "$js_urls")
        info "  Downloading ${js_count} JS files (max ${MAX_JS})..."
        head -"${MAX_JS}" "$js_urls" | xargs -P "${THREADS}" -I{} bash -c '
            url="$1"; fname=$(echo "$url" | md5sum | cut -c1-8).js
            curl -sk --max-time 10 "$url" -o "'"${js_scan_dir}"'/${fname}" 2>/dev/null || true
        ' _ {} 2>/dev/null || true
        dl_count=$(ls "${js_scan_dir}/"*.js 2>/dev/null | wc -l 2>/dev/null || echo 0)
        log "  Downloaded ${dl_count} JS files"
    fi
fi

if [ -d "$js_scan_dir" ] && [ "$(ls -A "$js_scan_dir" 2>/dev/null)" ]; then
    info "  Scanning JS files with credential patterns..."

    for pattern_entry in "${CREDENTIAL_PATTERNS[@]}"; do
        pat_name=$(echo "$pattern_entry" | cut -d'|' -f1)
        pat_regex=$(echo "$pattern_entry" | cut -d'|' -f2)
        pat_sev=$(echo "$pattern_entry" | cut -d'|' -f3)
        pat_desc=$(echo "$pattern_entry" | cut -d'|' -f4)

        matches=$(grep -roPhi "$pat_regex" "$js_scan_dir/" 2>/dev/null | head -20 || true)
        if [ -n "$matches" ]; then
            while IFS= read -r match_line; do
                [ -z "$match_line" ] && continue
                # Extract just the match (after the filename:)
                match_val=$(echo "$match_line" | sed 's/^[^:]*://')
                source_file=$(echo "$match_line" | cut -d: -f1)

                # Filter out noise / public-by-design keys
                if echo "$match_val" | grep -qiP "$NOISE_FILTER"; then
                    continue
                fi

                # Filter out reCAPTCHA site keys (6L prefix, public)
                if echo "$match_val" | grep -qP '^6L[a-zA-Z0-9_-]{38}$'; then
                    continue
                fi

                # Filter Stripe publishable keys (public)
                if echo "$match_val" | grep -qP '^pk_(live|test)_'; then
                    continue
                fi

                # Truncate long matches for readability
                display_val="${match_val:0:80}"
                [ ${#match_val} -gt 80 ] && display_val="${display_val}..."

                ((js_secret_hits++)) || true
                tag_finding "$pat_sev" "JS:${source_file##*/}" "${pat_desc}: ${display_val}"
            done <<< "$matches"
        fi
    done

    log "  JS credential scan: ${js_secret_hits} findings"
fi

# ════════════════════════════════════════════════════════════════
# STEP 2: Scan HTML source and config endpoints
# ════════════════════════════════════════════════════════════════
info "Step 2: Scanning HTML source and config endpoints..."

html_secret_hits=0
CONFIG_PATHS=(
    "/" "/config.js" "/config.json" "/app-config.js" "/env.js"
    "/settings.js" "/runtime-config.js" "/assets/config.js"
    "/static/config.js" "/js/config.js" "/__ENV.js"
    "/api/config" "/api/settings" "/api/v1/config"
    "/_next/data" "/manifest.json" "/asset-manifest.json"
)

for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"

        # Quick connectivity check
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        for config_path in "${CONFIG_PATHS[@]}"; do
            test_url="${base_url}${config_path}"
            body=$(probe_body "$test_url")
            [ -z "$body" ] && continue
            [ ${#body} -lt 20 ] && continue

            for pattern_entry in "${CREDENTIAL_PATTERNS[@]}"; do
                pat_name=$(echo "$pattern_entry" | cut -d'|' -f1)
                pat_regex=$(echo "$pattern_entry" | cut -d'|' -f2)
                pat_sev=$(echo "$pattern_entry" | cut -d'|' -f3)
                pat_desc=$(echo "$pattern_entry" | cut -d'|' -f4)

                matches=$(echo "$body" | grep -oPi "$pat_regex" 2>/dev/null | head -5 || true)
                if [ -n "$matches" ]; then
                    while IFS= read -r match_val; do
                        [ -z "$match_val" ] && continue

                        # Filter noise
                        if echo "$match_val" | grep -qiP "$NOISE_FILTER"; then
                            continue
                        fi
                        # Filter reCAPTCHA site keys
                        if echo "$match_val" | grep -qP '^6L[a-zA-Z0-9_-]{38}$'; then
                            continue
                        fi
                        # Filter Stripe publishable keys
                        if echo "$match_val" | grep -qP '^pk_(live|test)_'; then
                            continue
                        fi

                        display_val="${match_val:0:80}"
                        [ ${#match_val} -gt 80 ] && display_val="${display_val}..."

                        ((html_secret_hits++)) || true
                        tag_finding "$pat_sev" "$test_url" "${pat_desc}: ${display_val}"
                    done <<< "$matches"
                fi
            done
        done

        break  # Use first working scheme
    done
done

log "  HTML/config scan: ${html_secret_hits} findings"

# ════════════════════════════════════════════════════════════════
# STEP 3: Firebase-specific configuration scanning
# ════════════════════════════════════════════════════════════════
info "Step 3: Firebase configuration scanning..."

firebase_hits=0
for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        # Fetch homepage and common Firebase config locations
        for page in "/" "/index.html" "/__/firebase/init.js" "/__/firebase/init.json"; do
            body=$(probe_body "${base_url}${page}")
            [ -z "$body" ] && continue

            # Check for Firebase config block
            firebase_config=$(echo "$body" | python3 -c "
import sys, re, json
content = sys.stdin.read()
# Look for firebaseConfig or firebase.initializeApp patterns
patterns = [
    r'(?:firebaseConfig|firebase\.initializeApp)\s*\(\s*(\{[^}]+\})',
    r'(?:var|const|let)\s+(?:firebaseConfig|config)\s*=\s*(\{[^}]+\})',
    r'\"apiKey\"\s*:\s*\"([^\"]+)\".*?\"authDomain\"\s*:\s*\"([^\"]+)\".*?\"projectId\"\s*:\s*\"([^\"]+)\"'
]
for pat in patterns[:2]:
    m = re.search(pat, content, re.DOTALL)
    if m:
        try:
            config_str = m.group(1)
            # Clean up JS to valid JSON
            config_str = re.sub(r'(\w+):', r'\"\1\":', config_str)
            config_str = config_str.replace(\"'\", '\"')
            print(config_str)
            break
        except: pass
m = re.search(patterns[2], content, re.DOTALL)
if m:
    print(json.dumps({'apiKey': m.group(1), 'authDomain': m.group(2), 'projectId': m.group(3)}))
" 2>/dev/null || echo "")

            if [ -n "$firebase_config" ] && [ "$firebase_config" != "{}" ]; then
                ((firebase_hits++)) || true
                # Extract project ID
                project_id=$(echo "$firebase_config" | grep -oP '"projectId"\s*:\s*"\K[^"]+' | head -1 || echo "unknown")
                tag_finding "HIGH" "${base_url}${page}" "Firebase config exposed — project: ${project_id}"

                # Check if Firestore/RTDB is publicly accessible
                if [ -n "$project_id" ] && [ "$project_id" != "unknown" ]; then
                    # Firestore REST API
                    firestore_url="https://firestore.googleapis.com/v1/projects/${project_id}/databases/(default)/documents"
                    fs_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$firestore_url" 2>/dev/null || echo "000")
                    if [ "$fs_status" = "200" ]; then
                        tag_finding "CRITICAL" "$firestore_url" "Firebase Firestore publicly readable — project: ${project_id}"
                    fi

                    # Realtime Database
                    rtdb_url="https://${project_id}-default-rtdb.firebaseio.com/.json"
                    rtdb_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$rtdb_url" 2>/dev/null || echo "000")
                    if [ "$rtdb_status" = "200" ]; then
                        rtdb_body=$(probe_body "$rtdb_url")
                        if [ "$rtdb_body" != "null" ] && [ -n "$rtdb_body" ]; then
                            tag_finding "CRITICAL" "$rtdb_url" "Firebase Realtime Database publicly readable — project: ${project_id}"
                        fi
                    fi

                    # Storage bucket
                    storage_url="https://firebasestorage.googleapis.com/v0/b/${project_id}.appspot.com/o"
                    st_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$storage_url" 2>/dev/null || echo "000")
                    if [ "$st_status" = "200" ]; then
                        tag_finding "HIGH" "$storage_url" "Firebase Storage bucket listing enabled — project: ${project_id}"
                    fi
                fi
            fi
        done

        break  # Use first working scheme
    done
done

log "  Firebase scan: ${firebase_hits} configurations found"

# ════════════════════════════════════════════════════════════════
# STEP 4: AWS key validation (if aws CLI available)
# ════════════════════════════════════════════════════════════════
info "Step 4: AWS key validation..."

aws_validated=0
if $has_aws_cli; then
    # Extract all AKIA keys from findings
    akia_keys=$(grep -oP 'AKIA[A-Z0-9]{16}' "$SECRETS_FINDINGS" 2>/dev/null | sort -u || true)

    if [ -n "$akia_keys" ]; then
        info "  Validating discovered AWS Access Key IDs..."
        while IFS= read -r akia; do
            [ -z "$akia" ] && continue
            # We can only validate if we also found the secret key
            # Just flag the AKIA as found for manual validation
            ((aws_validated++)) || true
            info "  AWS key found: ${akia} — manual validation recommended (need secret key)"
        done <<< "$akia_keys"
    fi
else
    # Check findings for AKIA keys and suggest validation
    akia_count=$(grep -c 'AKIA[A-Z0-9]\{16\}' "$SECRETS_FINDINGS" 2>/dev/null | tr -d '[:space:]' || echo 0)
    [[ -z "$akia_count" ]] && akia_count=0
    if [ "$akia_count" -gt 0 ]; then
        warn "  aws CLI not installed — cannot validate ${akia_count} AWS keys"
        warn "  Install aws-cli and run: aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ..."
    fi
fi

log "  AWS key validation: ${aws_validated} keys flagged"

# ════════════════════════════════════════════════════════════════
# STEP 5: Cloud-specific config endpoint scanning
# ════════════════════════════════════════════════════════════════
info "Step 5: Cloud-specific configuration endpoints..."

cloud_config_hits=0
CLOUD_CONFIG_PATHS=(
    "/.well-known/assetlinks.json|Android asset links|MEDIUM"
    "/.well-known/apple-app-site-association|iOS app config|MEDIUM"
    "/robots.txt|Robots.txt (may leak paths)|INFO"
    "/sitemap.xml|Sitemap (may leak paths)|INFO"
    "/.env|Environment variables|CRITICAL"
    "/.env.production|Production env vars|CRITICAL"
    "/.env.staging|Staging env vars|CRITICAL"
    "/wp-config.php.bak|WordPress config backup|CRITICAL"
    "/server-info|Apache server info|HIGH"
    "/server-status|Apache server status|HIGH"
    "/elmah.axd|ELMAH error log (.NET)|HIGH"
    "/trace.axd|ASP.NET trace|HIGH"
    "/phpinfo.php|PHP info page|HIGH"
    "/info.php|PHP info page|HIGH"
    "/.git/config|Git repository config|CRITICAL"
    "/.svn/entries|SVN entries|HIGH"
    "/.DS_Store|macOS metadata|MEDIUM"
    "/debug/vars|Go debug vars|HIGH"
    "/debug/pprof|Go pprof endpoint|HIGH"
)

for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        for entry in "${CLOUD_CONFIG_PATHS[@]}"; do
            path=$(echo "$entry" | cut -d'|' -f1)
            desc=$(echo "$entry" | cut -d'|' -f2)
            sev=$(echo "$entry" | cut -d'|' -f3)

            test_url="${base_url}${path}"
            result=$(curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
                --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null || echo "000 0")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" = "200" ] && [ "${size%.*}" -gt 50 ] 2>/dev/null; then
                # Validate content to avoid false positives from custom error pages
                body=$(probe_body "$test_url" | head -10)
                is_valid=false

                case "$path" in
                    /.env|/.env.production|/.env.staging)
                        echo "$body" | grep -qP '^\s*[A-Z_]+=|^#\s*[A-Z]' && is_valid=true ;;
                    /.git/config)
                        echo "$body" | grep -qi '\[core\]\|repositoryformatversion' && is_valid=true ;;
                    /.svn/entries)
                        echo "$body" | grep -qP '^\d+$|dir$' && is_valid=true ;;
                    /phpinfo.php|/info.php)
                        echo "$body" | grep -qi 'phpinfo\|PHP Version' && is_valid=true ;;
                    /debug/vars|/debug/pprof)
                        echo "$body" | grep -qP 'cmdline|memstats|profile|goroutine' && is_valid=true ;;
                    /server-info|/server-status)
                        echo "$body" | grep -qi 'Apache Server\|Server Version' && is_valid=true ;;
                    /elmah.axd|/trace.axd)
                        echo "$body" | grep -qi 'error\|trace\|ELMAH\|System\.Web' && is_valid=true ;;
                    *)
                        is_valid=true ;;
                esac

                if $is_valid; then
                    ((cloud_config_hits++)) || true
                    tag_finding "$sev" "$test_url" "${desc} (${size}B)"
                fi
            fi
        done

        break  # Use first working scheme
    done
done

log "  Cloud config scan: ${cloud_config_hits} findings"

# ── Cleanup ──
rm -f "${OUT_DIR}/_cl_js_for_secrets.txt"
# Only clean up if we created the download dir in this script
if [ -d "${OUT_DIR}/js_secret_downloads" ]; then
    rm -rf "${OUT_DIR}/js_secret_downloads" 2>/dev/null || true
fi

# ── Dedup output ──
[ -f "$SECRETS_FINDINGS" ] && sort -u -o "$SECRETS_FINDINGS" "$SECRETS_FINDINGS" 2>/dev/null || true

# ── Summary ──
total_findings=$(count_lines "$SECRETS_FINDINGS")
critical_count=$(grep -c '^\[CRITICAL\]' "$SECRETS_FINDINGS" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$SECRETS_FINDINGS" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$SECRETS_FINDINGS" 2>/dev/null || echo 0)

log "Cloud secret scanning complete:"
log "  Total findings:   ${total_findings}"
log "    CRITICAL:       ${critical_count}"
log "    HIGH:           ${high_count}"
log "    MEDIUM:         ${medium_count}"
log "  JS secrets:       ${js_secret_hits}"
log "  HTML/config:      ${html_secret_hits}"
log "  Firebase configs: ${firebase_hits}"
log "  Cloud configs:    ${cloud_config_hits}"
log "  Output: ${SECRETS_FINDINGS}"
