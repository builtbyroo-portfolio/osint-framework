#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_sri_check.sh — Subresource Integrity Check                ║
# ║  External script/style audit · CDN integrity= verification    ║
# ║  Missing SRI detection · DO_NOT_SUBMIT tagging (P5)           ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_sri_check.sh"
SCRIPT_DESC="Subresource Integrity Check"
MAX_PAGES="${MAX_PAGES:-30}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Check external scripts and stylesheets for Subresource Integrity"
    echo "  (SRI) attributes. External CDN resources without integrity= are"
    echo "  vulnerable to CDN compromise. Tagged as DO_NOT_SUBMIT (P5 alone)."
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

phase_header "7" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }

# ── Output files ──
SRI_FINDINGS="${OUT_DIR}/cl_sri_check_findings.txt"
> "$SRI_FINDINGS"

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$SRI_FINDINGS"
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

# ── Known CDN domains (external resources loaded from these need SRI) ──
CDN_DOMAINS=(
    "cdnjs.cloudflare.com"
    "cdn.jsdelivr.net"
    "unpkg.com"
    "code.jquery.com"
    "stackpath.bootstrapcdn.com"
    "maxcdn.bootstrapcdn.com"
    "cdn.bootcss.com"
    "ajax.googleapis.com"
    "ajax.aspnetcdn.com"
    "cdn.datatables.net"
    "use.fontawesome.com"
    "kit.fontawesome.com"
    "fonts.googleapis.com"
    "cdn.tailwindcss.com"
    "cdn.rawgit.com"
    "rawcdn.githack.com"
    "gitcdn.github.io"
    "cdn.shopify.com"
    "assets.adobedtm.com"
    "static.cloudflareinsights.com"
    "cdn.segment.com"
    "js.stripe.com"
    "checkout.stripe.com"
    "maps.googleapis.com"
    "platform.twitter.com"
    "connect.facebook.net"
    "www.googletagmanager.com"
    "www.google-analytics.com"
    "cdn.amplitude.com"
    "cdn.heapanalytics.com"
    "cdn.mxpnl.com"
)

# Build CDN domain regex for matching
cdn_pattern=$(printf '%s|' "${CDN_DOMAINS[@]}" | sed 's/\./\\./g;s/|$//')

# ── Pages to scan ──
SCAN_PAGES=("/" "/index.html" "/home" "/login" "/signup" "/register" "/app" "/dashboard" "/about" "/contact" "/pricing")

# ════════════════════════════════════════════════════════════════
# STEP 1: Fetch and analyze pages for external resources
# ════════════════════════════════════════════════════════════════
info "Step 1: Scanning pages for external script and style references..."

total_external=0
total_with_sri=0
total_without_sri=0
total_scripts_no_sri=0
total_styles_no_sri=0

# Track unique resources
resource_tracking="${OUT_DIR}/_cl_sri_resources.txt"
> "$resource_tracking"

for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"

        # Quick connectivity check
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        info "  Scanning ${domain} (${#SCAN_PAGES[@]} pages)..."

        page_count=0
        for page in "${SCAN_PAGES[@]}"; do
            [ "$page_count" -ge "$MAX_PAGES" ] && break
            ((page_count++)) || true

            page_url="${base_url}${page}"
            body=$(probe_body "$page_url")
            [ -z "$body" ] && continue

            # ── Extract <script> tags ──
            # Use python for reliable HTML tag parsing
            sri_py_script="${OUT_DIR}/_cl_sri_extract.py"
            cat > "$sri_py_script" << 'PYEOF'
import sys, re
from urllib.parse import urlparse

content = sys.stdin.read()
page_url = sys.argv[1]
domain = sys.argv[2]

attr_re = r'''[\"\']([^\"\']+)[\"\']'''

script_pattern = r'<script[^>]*>'
for match in re.finditer(script_pattern, content, re.IGNORECASE):
    tag = match.group()
    src_match = re.search(r'src=' + attr_re, tag, re.IGNORECASE)
    if not src_match:
        continue
    src = src_match.group(1)
    if src.startswith('//'):
        src = 'https:' + src
    elif src.startswith('/'):
        parts = page_url.split('/', 3)
        src = parts[0] + '//' + parts[2] + src
    elif not src.startswith('http'):
        continue
    parsed = urlparse(src)
    if parsed.hostname and parsed.hostname != domain and not parsed.hostname.endswith('.' + domain):
        has_integrity = bool(re.search(r'integrity=', tag, re.IGNORECASE))
        print(f'SCRIPT|{src}|{has_integrity}|{page_url}')

link_pattern = r'<link[^>]*>'
for match in re.finditer(link_pattern, content, re.IGNORECASE):
    tag = match.group()
    if not re.search(r'rel=' + attr_re, tag, re.IGNORECASE):
        continue
    rel_match = re.search(r'rel=' + attr_re, tag, re.IGNORECASE)
    if rel_match and 'stylesheet' not in rel_match.group(1).lower():
        continue
    href_match = re.search(r'href=' + attr_re, tag, re.IGNORECASE)
    if not href_match:
        continue
    href = href_match.group(1)
    if href.startswith('//'):
        href = 'https:' + href
    elif href.startswith('/'):
        parts = page_url.split('/', 3)
        href = parts[0] + '//' + parts[2] + href
    elif not href.startswith('http'):
        continue
    parsed = urlparse(href)
    if parsed.hostname and parsed.hostname != domain and not parsed.hostname.endswith('.' + domain):
        has_integrity = bool(re.search(r'integrity=', tag, re.IGNORECASE))
        print(f'STYLE|{href}|{has_integrity}|{page_url}')
PYEOF

            python3 "$sri_py_script" "$page_url" "$domain" <<< "$body" 2>/dev/null | while IFS='|' read -r res_type res_url has_integrity source_page; do
                [ -z "$res_url" ] && continue

                # Dedup — track unique resources
                dedup_key="${res_type}|${res_url}"
                if grep -qF "$dedup_key" "$resource_tracking" 2>/dev/null; then
                    continue
                fi
                echo "$dedup_key" >> "$resource_tracking"

                ((total_external++)) || true

                if [ "$has_integrity" = "True" ]; then
                    ((total_with_sri++)) || true
                else
                    ((total_without_sri++)) || true

                    # Determine if this is a known CDN
                    is_cdn=false
                    res_host=$(echo "$res_url" | grep -oP '(?<=://)[^/]+' | head -1)
                    for cdn in "${CDN_DOMAINS[@]}"; do
                        if [ "$res_host" = "$cdn" ] || echo "$res_host" | grep -qF "$cdn"; then
                            is_cdn=true
                            break
                        fi
                    done

                    if [ "$res_type" = "SCRIPT" ]; then
                        ((total_scripts_no_sri++)) || true
                        if $is_cdn; then
                            tag_finding "LOW" "$res_url" "[DO_NOT_SUBMIT] CDN script without SRI (from ${source_page})"
                        else
                            tag_finding "LOW" "$res_url" "[DO_NOT_SUBMIT] External script without SRI — ${res_host} (from ${source_page})"
                        fi
                    elif [ "$res_type" = "STYLE" ]; then
                        ((total_styles_no_sri++)) || true
                        if $is_cdn; then
                            tag_finding "LOW" "$res_url" "[DO_NOT_SUBMIT] CDN stylesheet without SRI (from ${source_page})"
                        else
                            tag_finding "LOW" "$res_url" "[DO_NOT_SUBMIT] External stylesheet without SRI — ${res_host} (from ${source_page})"
                        fi
                    fi
                fi
            done

        done

        break  # Use first working scheme
    done
done

# ════════════════════════════════════════════════════════════════
# STEP 2: Additional URL-based scanning
# ════════════════════════════════════════════════════════════════
info "Step 2: Scanning additional URLs from input file..."

url_page_count=0
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    # Only scan HTML pages, not JS/CSS/image files
    grep -viP '\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|pdf|zip)(\?|$)' "$URLS_FILE" 2>/dev/null | head -"$MAX_PAGES" | while IFS= read -r page_url; do
        [ -z "$page_url" ] && continue
        ((url_page_count++)) || true

        body=$(probe_body "$page_url")
        [ -z "$body" ] && continue

        # Extract domain from page URL
        page_domain=$(echo "$page_url" | grep -oP '(?<=://)[^/]+' | head -1)
        [ -z "$page_domain" ] && continue

        # Quick check for script tags with external src but no integrity
        echo "$body" | grep -oP '<script[^>]+src=["\x27][^"\x27]+["\x27][^>]*>' 2>/dev/null | while IFS= read -r tag; do
            src=$(echo "$tag" | grep -oP 'src=["\x27]\K[^"\x27]+' | head -1)
            [ -z "$src" ] && continue

            # Resolve
            case "$src" in
                http://*|https://*) ;;
                //*) src="https:${src}" ;;
                *) continue ;;
            esac

            src_host=$(echo "$src" | grep -oP '(?<=://)[^/]+' | head -1)
            [ -z "$src_host" ] && continue
            [ "$src_host" = "$page_domain" ] && continue

            # Check if integrity is present
            if ! echo "$tag" | grep -qi 'integrity='; then
                dedup_key="SCRIPT|${src}"
                if ! grep -qF "$dedup_key" "$resource_tracking" 2>/dev/null; then
                    echo "$dedup_key" >> "$resource_tracking"
                    ((total_external++)) || true
                    ((total_without_sri++)) || true
                    ((total_scripts_no_sri++)) || true
                    tag_finding "LOW" "$src" "[DO_NOT_SUBMIT] External script without SRI (from ${page_url})"
                fi
            fi
        done
    done
fi

# ════════════════════════════════════════════════════════════════
# STEP 3: SRI coverage summary per domain
# ════════════════════════════════════════════════════════════════
info "Step 3: Computing SRI coverage statistics..."

# Re-count from findings file since subshell increments don't propagate
total_external=$(count_lines "$resource_tracking" | tr -d '[:space:]')
total_without_sri=$(grep -c '\[DO_NOT_SUBMIT\]' "$SRI_FINDINGS" 2>/dev/null | tr -d '[:space:]' || echo 0)
[[ -z "$total_external" ]] && total_external=0
[[ -z "$total_without_sri" ]] && total_without_sri=0
total_with_sri=$((total_external - total_without_sri))
total_scripts_no_sri=$(grep -c 'External script without SRI\|CDN script without SRI' "$SRI_FINDINGS" 2>/dev/null || echo 0)
total_styles_no_sri=$(grep -c 'External stylesheet without SRI\|CDN stylesheet without SRI' "$SRI_FINDINGS" 2>/dev/null || echo 0)

if [ "$total_external" -gt 0 ]; then
    coverage_pct=$((total_with_sri * 100 / total_external))
else
    coverage_pct=0
fi

# Add summary header to findings
{
    echo "# ═══ SRI Coverage Summary ═══"
    echo "# Total external resources: ${total_external}"
    echo "# With SRI (integrity=):    ${total_with_sri}"
    echo "# Without SRI:              ${total_without_sri}"
    echo "#   Scripts without SRI:    ${total_scripts_no_sri}"
    echo "#   Styles without SRI:     ${total_styles_no_sri}"
    echo "# SRI coverage:             ${coverage_pct}%"
    echo "# NOTE: Missing SRI alone = P5 (DO_NOT_SUBMIT)"
    echo "# Only reportable if chained with CDN compromise evidence"
    echo "# ═══════════════════════════"
    echo ""
} | cat - "$SRI_FINDINGS" > "${OUT_DIR}/_cl_sri_tmp.txt" && mv "${OUT_DIR}/_cl_sri_tmp.txt" "$SRI_FINDINGS"

# ── Cleanup ──
rm -f "$resource_tracking" "${OUT_DIR}/_cl_sri_extract.py"

# ── Dedup output ──
# Don't dedup the whole file since we added a header

# ── Summary ──
log "Subresource Integrity check complete:"
log "  Total external resources:  ${total_external}"
log "  With SRI (integrity=):     ${total_with_sri}"
log "  Without SRI:               ${total_without_sri}"
log "    Scripts without SRI:     ${total_scripts_no_sri}"
log "    Styles without SRI:      ${total_styles_no_sri}"
log "  SRI coverage:              ${coverage_pct}%"
log "  NOTE: All findings tagged [DO_NOT_SUBMIT] — P5 unless chained"
log "  Output: ${SRI_FINDINGS}"
