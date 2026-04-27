#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_js_audit.sh — JavaScript Library Vulnerability Audit       ║
# ║  retire.js · Version extraction · CVE cross-reference          ║
# ║  CSP analysis · CDN pattern detection                          ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_js_audit.sh"
SCRIPT_DESC="JavaScript Library Vulnerability Audit"
MAX_JS="${MAX_JS:-200}"
MAX_PAGES="${MAX_PAGES:-20}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Audit JavaScript libraries for known vulnerabilities. Collects"
    echo "  JS file URLs, extracts library versions, scans with retire.js,"
    echo "  and cross-references against known CVEs."
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

phase_header "5" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }
has_retire=false
check_tool retire 2>/dev/null && has_retire=true

# ── Output files ──
JS_AUDIT_FINDINGS="${OUT_DIR}/cl_js_audit_findings.txt"
JS_INVENTORY="${OUT_DIR}/cl_js_inventory.txt"
> "$JS_AUDIT_FINDINGS"
> "$JS_INVENTORY"

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$JS_AUDIT_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helpers ──
probe_body() {
    local url="$1"
    curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

probe_headers() {
    local url="$1"
    curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
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

# ════════════════════════════════════════════════════════════════
# STEP 1: Collect JS file URLs
# ════════════════════════════════════════════════════════════════
info "Step 1: Collecting JavaScript file URLs..."

js_urls_file="${OUT_DIR}/_cl_js_urls.txt"
> "$js_urls_file"

# Source 1: Existing JS file list from previous phases
if [ -f "${OUT_DIR}/js_files.txt" ] && [ -s "${OUT_DIR}/js_files.txt" ]; then
    cat "${OUT_DIR}/js_files.txt" >> "$js_urls_file"
    log "  Added $(count_lines "${OUT_DIR}/js_files.txt") JS URLs from previous phases"
fi

# Source 2: URLs file
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    grep -iP '\.(js|mjs)(\?|$)' "$URLS_FILE" 2>/dev/null >> "$js_urls_file" || true
fi

# Source 3: Spider target homepages for script tags
COMMON_PAGES=("/" "/index.html" "/home" "/login" "/app" "/dashboard")

for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"

        # Quick connectivity check
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        page_count=0
        for page in "${COMMON_PAGES[@]}"; do
            [ "$page_count" -ge "$MAX_PAGES" ] && break
            ((page_count++)) || true

            page_url="${base_url}${page}"
            body=$(probe_body "$page_url")
            [ -z "$body" ] && continue

            # Extract script src attributes
            echo "$body" | grep -oP '<script[^>]+src=["'"'"']\K[^"'"'"']+' 2>/dev/null | while IFS= read -r src; do
                [ -z "$src" ] && continue
                # Resolve relative URLs
                case "$src" in
                    http://*|https://*)
                        echo "$src" >> "$js_urls_file"
                        ;;
                    //*)
                        echo "https:${src}" >> "$js_urls_file"
                        ;;
                    /*)
                        echo "${base_url}${src}" >> "$js_urls_file"
                        ;;
                    *)
                        echo "${base_url}/${src}" >> "$js_urls_file"
                        ;;
                esac
            done
        done

        break  # Use first working scheme
    done
done

sort -u -o "$js_urls_file" "$js_urls_file" 2>/dev/null || true
js_url_count=$(count_lines "$js_urls_file")
log "  Total JS URLs collected: ${js_url_count}"

# ════════════════════════════════════════════════════════════════
# STEP 2: retire.js scanning
# ════════════════════════════════════════════════════════════════
info "Step 2: retire.js vulnerability scanning..."

if $has_retire && [ "$js_url_count" -gt 0 ]; then
    retire_out="${OUT_DIR}/retire_results.json"
    retire_txt="${OUT_DIR}/retire_results.txt"
    > "$retire_txt"

    # Scan JS URLs
    info "  Running retire.js on ${js_url_count} JS URLs (max ${MAX_JS})..."
    head -"${MAX_JS}" "$js_urls_file" | while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue
        retire --jsuri "$js_url" --outputformat json 2>/dev/null || true
    done > "$retire_out" 2>/dev/null || true

    # Parse retire.js results
    if [ -s "$retire_out" ]; then
        python3 -c "
import json, sys
try:
    findings = []
    for line in open(sys.argv[1]):
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            if isinstance(data, list):
                for item in data:
                    results = item.get('results', [])
                    component = item.get('component', 'unknown')
                    version = item.get('version', '?')
                    for r in results:
                        for v in r.get('vulnerabilities', []):
                            sev = v.get('severity', 'medium').upper()
                            info_str = v.get('info', [''])[0] if v.get('info') else ''
                            cve = ''
                            ids = v.get('identifiers', {})
                            if ids.get('CVE'):
                                cve = ids['CVE'][0] if isinstance(ids['CVE'], list) else ids['CVE']
                            summary = v.get('info', ['no summary'])[0]
                            findings.append(f'{sev}|{component}|{version}|{cve}|{summary}')
        except json.JSONDecodeError:
            continue
    for f in sorted(set(findings)):
        print(f)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" "$retire_out" 2>/dev/null | while IFS='|' read -r sev comp ver cve summary; do
            echo "${comp} ${ver} — ${cve} ${summary}" >> "$retire_txt"
            # Map retire severity to our severity
            case "${sev,,}" in
                critical) tag_finding "CRITICAL" "${comp}@${ver}" "retire.js: ${cve} — ${summary}" ;;
                high)     tag_finding "HIGH" "${comp}@${ver}" "retire.js: ${cve} — ${summary}" ;;
                medium)   tag_finding "MEDIUM" "${comp}@${ver}" "retire.js: ${cve} — ${summary}" ;;
                *)        tag_finding "LOW" "${comp}@${ver}" "retire.js: ${cve} — ${summary}" ;;
            esac
        done
        log "  retire.js: $(count_lines "$retire_txt") vulnerability findings"
    else
        info "  retire.js returned no results"
    fi
else
    if ! $has_retire; then
        warn "  retire.js not installed — using manual version extraction"
    fi
fi

# ════════════════════════════════════════════════════════════════
# STEP 3: Manual JS library version extraction
# ════════════════════════════════════════════════════════════════
info "Step 3: Manual JavaScript library version extraction..."

# Download JS files for analysis
mkdir -p "${OUT_DIR}/js_audit_downloads"
dl_count=0
if [ "$js_url_count" -gt 0 ]; then
    info "  Downloading JS files for version extraction (max ${MAX_JS})..."
    head -"${MAX_JS}" "$js_urls_file" | xargs -P "${THREADS}" -I{} bash -c '
        url="$1"; fname=$(echo "$url" | md5sum | cut -c1-8).js
        curl -sk --max-time 10 "$url" -o "'"${OUT_DIR}"'/js_audit_downloads/${fname}" 2>/dev/null || true
    ' _ {} 2>/dev/null || true
    dl_count=$(ls "${OUT_DIR}/js_audit_downloads/"*.js 2>/dev/null | wc -l 2>/dev/null || echo 0)
    log "  Downloaded ${dl_count} JS files"
fi

# Version extraction patterns
# Format: "library|regex_pattern|known_vulnerable_versions"
VERSION_PATTERNS=(
    "jQuery|jquery[/ ]*v?([0-9]+\.[0-9]+\.[0-9]+)|<1.12.0,<2.2.0,<3.5.0"
    "Angular|angular[./]?v?([0-9]+\.[0-9]+\.[0-9]+)|<1.6.9"
    "AngularJS|angular\.js v([0-9]+\.[0-9]+\.[0-9]+)|<1.6.9"
    "React|react[.-]v?([0-9]+\.[0-9]+\.[0-9]+)|<16.4.2"
    "Bootstrap|Bootstrap v([0-9]+\.[0-9]+\.[0-9]+)|<3.4.0,<4.3.1"
    "Lodash|lodash ([0-9]+\.[0-9]+\.[0-9]+)|<4.17.21"
    "Moment.js|moment\.js.*?([0-9]+\.[0-9]+\.[0-9]+)|<2.29.4"
    "Handlebars|handlebars v([0-9]+\.[0-9]+\.[0-9]+)|<4.7.7"
    "Vue.js|Vue\.js v([0-9]+\.[0-9]+\.[0-9]+)|<2.6.14"
    "DOMPurify|DOMPurify ([0-9]+\.[0-9]+\.[0-9]+)|<2.3.6"
    "Underscore|Underscore\.js ([0-9]+\.[0-9]+\.[0-9]+)|<1.13.2"
    "Backbone|Backbone\.js ([0-9]+\.[0-9]+\.[0-9]+)|<1.3.3"
    "Ember|Ember ([0-9]+\.[0-9]+\.[0-9]+)|<3.24.0"
    "Knockout|Knockout JavaScript library v([0-9]+\.[0-9]+\.[0-9]+)|<3.5.0"
    "D3|d3 v([0-9]+\.[0-9]+\.[0-9]+)|<0.0.0"
    "Select2|select2 ([0-9]+\.[0-9]+\.[0-9]+)|<4.0.9"
    "Chart.js|Chart\.js v([0-9]+\.[0-9]+\.[0-9]+)|<0.0.0"
    "TinyMCE|tinymce.*?([0-9]+\.[0-9]+\.[0-9]+)|<5.10.0"
    "CKEditor|ckeditor.*?([0-9]+\.[0-9]+\.[0-9]+)|<4.18.0"
    "Dojo|dojo.*?([0-9]+\.[0-9]+\.[0-9]+)|<1.16.0"
    "Prototype.js|Prototype JavaScript framework, version ([0-9]+\.[0-9]+\.[0-9]+)|<1.7.3"
    "YUI|YUI ([0-9]+\.[0-9]+\.[0-9]+)|<3.18.1"
)

lib_found=0
if [ -d "${OUT_DIR}/js_audit_downloads" ] && [ "$dl_count" -gt 0 ]; then
    info "  Extracting library versions from downloaded JS files..."

    for pattern_entry in "${VERSION_PATTERNS[@]}"; do
        lib_name=$(echo "$pattern_entry" | cut -d'|' -f1)
        regex=$(echo "$pattern_entry" | cut -d'|' -f2)

        # Search all downloaded JS files
        matches=$(grep -roPhi "$regex" "${OUT_DIR}/js_audit_downloads/" 2>/dev/null | head -5 || true)

        if [ -n "$matches" ]; then
            while IFS= read -r match; do
                [ -z "$match" ] && continue
                # Extract just the version number
                version=$(echo "$match" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                [ -z "$version" ] && continue

                ((lib_found++)) || true
                echo "${lib_name} ${version}" >> "$JS_INVENTORY"

                # Cross-reference version with CDN URL patterns for additional context
                source_file=$(echo "$match" | cut -d: -f1 2>/dev/null | head -1)
                tag_finding "INFO" "${lib_name}@${version}" "Library detected — ${lib_name} version ${version}"
            done <<< "$matches"
        fi
    done

    # Dedup inventory
    sort -u -o "$JS_INVENTORY" "$JS_INVENTORY" 2>/dev/null || true
    log "  Extracted ${lib_found} library version entries"
fi

# ════════════════════════════════════════════════════════════════
# STEP 4: CDN URL version extraction
# ════════════════════════════════════════════════════════════════
info "Step 4: CDN URL version extraction..."

cdn_hits=0
if [ "$js_url_count" -gt 0 ]; then
    # Extract versions from CDN URLs directly (faster than downloading)
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        # Common CDN patterns with version in URL
        # cdnjs.cloudflare.com/ajax/libs/LIBRARY/VERSION/
        cdn_match=$(echo "$url" | grep -oP 'cdnjs\.cloudflare\.com/ajax/libs/([a-zA-Z0-9._-]+)/([0-9]+\.[0-9]+\.[0-9]+)' 2>/dev/null || true)
        if [ -n "$cdn_match" ]; then
            lib=$(echo "$cdn_match" | grep -oP 'libs/\K[a-zA-Z0-9._-]+(?=/)')
            ver=$(echo "$cdn_match" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+$')
            if [ -n "$lib" ] && [ -n "$ver" ]; then
                ((cdn_hits++)) || true
                echo "${lib} ${ver} (cdnjs)" >> "$JS_INVENTORY"
            fi
        fi

        # jsdelivr.net/npm/PACKAGE@VERSION
        cdn_match=$(echo "$url" | grep -oP 'jsdelivr\.net/npm/([a-zA-Z0-9@._-]+)@([0-9]+\.[0-9]+\.[0-9]+)' 2>/dev/null || true)
        if [ -n "$cdn_match" ]; then
            lib=$(echo "$cdn_match" | grep -oP 'npm/\K[a-zA-Z0-9._-]+(?=@)')
            ver=$(echo "$cdn_match" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+$')
            if [ -n "$lib" ] && [ -n "$ver" ]; then
                ((cdn_hits++)) || true
                echo "${lib} ${ver} (jsdelivr)" >> "$JS_INVENTORY"
            fi
        fi

        # unpkg.com/PACKAGE@VERSION
        cdn_match=$(echo "$url" | grep -oP 'unpkg\.com/([a-zA-Z0-9@._-]+)@([0-9]+\.[0-9]+\.[0-9]+)' 2>/dev/null || true)
        if [ -n "$cdn_match" ]; then
            lib=$(echo "$cdn_match" | grep -oP 'unpkg\.com/\K[a-zA-Z0-9._-]+(?=@)')
            ver=$(echo "$cdn_match" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+$')
            if [ -n "$lib" ] && [ -n "$ver" ]; then
                ((cdn_hits++)) || true
                echo "${lib} ${ver} (unpkg)" >> "$JS_INVENTORY"
            fi
        fi

        # code.jquery.com/jquery-VERSION.min.js
        cdn_match=$(echo "$url" | grep -oP 'code\.jquery\.com/jquery-([0-9]+\.[0-9]+\.[0-9]+)' 2>/dev/null || true)
        if [ -n "$cdn_match" ]; then
            ver=$(echo "$cdn_match" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+$')
            if [ -n "$ver" ]; then
                ((cdn_hits++)) || true
                echo "jQuery ${ver} (code.jquery.com)" >> "$JS_INVENTORY"
            fi
        fi
    done < "$js_urls_file"

    log "  CDN version extraction: ${cdn_hits} library versions from URLs"
fi

# Dedup inventory
sort -u -o "$JS_INVENTORY" "$JS_INVENTORY" 2>/dev/null || true

# ════════════════════════════════════════════════════════════════
# STEP 5: CSP header analysis for script-src restrictions
# ════════════════════════════════════════════════════════════════
info "Step 5: CSP header analysis..."

csp_file="${OUT_DIR}/_cl_csp_analysis.txt"
> "$csp_file"

for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        headers=$(curl -sk -D- -o /dev/null --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "${scheme}://${domain}/" 2>/dev/null || echo "")
        [ -z "$headers" ] && continue

        csp=$(echo "$headers" | grep -i '^content-security-policy:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        if [ -n "$csp" ]; then
            echo "DOMAIN: ${domain}" >> "$csp_file"
            echo "CSP: ${csp}" >> "$csp_file"
            echo "" >> "$csp_file"

            # Analyze script-src
            script_src=$(echo "$csp" | grep -oP "script-src[^;]+" || true)
            if [ -n "$script_src" ]; then
                # Check for unsafe-inline
                if echo "$script_src" | grep -q "'unsafe-inline'"; then
                    tag_finding "MEDIUM" "https://${domain}" "CSP allows 'unsafe-inline' in script-src"
                fi
                # Check for unsafe-eval
                if echo "$script_src" | grep -q "'unsafe-eval'"; then
                    tag_finding "MEDIUM" "https://${domain}" "CSP allows 'unsafe-eval' in script-src"
                fi
                # Check for wildcard
                if echo "$script_src" | grep -qP '\s\*\s|\s\*$'; then
                    tag_finding "MEDIUM" "https://${domain}" "CSP script-src contains wildcard (*)"
                fi
                # Check for data: URIs
                if echo "$script_src" | grep -q "data:"; then
                    tag_finding "MEDIUM" "https://${domain}" "CSP allows data: URIs in script-src"
                fi
                log "  ${domain}: script-src = ${script_src}"
            else
                # No script-src = default-src applies (or no restriction)
                default_src=$(echo "$csp" | grep -oP "default-src[^;]+" || true)
                if [ -z "$default_src" ]; then
                    tag_finding "LOW" "https://${domain}" "CSP present but no script-src or default-src directive"
                fi
            fi
        else
            info "  ${domain}: No CSP header"
        fi

        break  # Use first working scheme
    done
done

# ── Cleanup ──
rm -f "$js_urls_file" "$csp_file"
rm -rf "${OUT_DIR}/js_audit_downloads" 2>/dev/null || true

# ── Dedup output ──
for f in "$JS_AUDIT_FINDINGS" "$JS_INVENTORY"; do
    [ -f "$f" ] && sort -u -o "$f" "$f" 2>/dev/null || true
done

# ── Summary ──
total_findings=$(count_lines "$JS_AUDIT_FINDINGS")
inventory_count=$(count_lines "$JS_INVENTORY")
critical_count=$(grep -c '^\[CRITICAL\]' "$JS_AUDIT_FINDINGS" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$JS_AUDIT_FINDINGS" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$JS_AUDIT_FINDINGS" 2>/dev/null || echo 0)

log "JavaScript library audit complete:"
log "  Total findings:   ${total_findings}"
log "    CRITICAL:       ${critical_count}"
log "    HIGH:           ${high_count}"
log "    MEDIUM:         ${medium_count}"
log "  JS inventory:     ${inventory_count} libraries"
log "  Output: ${JS_AUDIT_FINDINGS}"
log "  Output: ${JS_INVENTORY}"
