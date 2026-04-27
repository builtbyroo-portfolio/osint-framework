#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_backup_config.sh — Backup & Config File Discovery        ║
# ║  Dynamic backup variants · Config probes · Source maps       ║
# ║  DB dumps (SecLists) · CMS configs · Severity tagging        ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_backup_config.sh"
SCRIPT_DESC="Backup & Config File Discovery"

MAX_BACKUP_URLS=200

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover backup files, config files, source maps, DB dumps, and"
    echo "  CMS configuration files. Reads ac_content_findings.txt from Phase 2"
    echo "  to generate dynamic backup variants."
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

phase_header "4" "$SCRIPT_DESC"

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

if [ "${#targets[@]}" -eq 0 ]; then
    err "No targets resolved from --domain or --domains"
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }
has_ffuf=false
check_tool ffuf 2>/dev/null && has_ffuf=true

# ── Output files ──
BACKUP_FINDINGS="${OUT_DIR}/ac_backup_findings.txt"
SOURCEMAP_FINDINGS="${OUT_DIR}/ac_sourcemap_findings.txt"
> "$BACKUP_FINDINGS"
> "$SOURCEMAP_FINDINGS"

CONTENT_FINDINGS="${OUT_DIR}/ac_content_findings.txt"
mkdir -p "${OUT_DIR}/ffuf_backup"

# ── Severity tag helper ──
# Usage: tag_severity "CRITICAL" "url" "description"
tag_severity() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$BACKUP_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

tag_sourcemap() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$SOURCEMAP_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helper: curl with status + size ──
# Returns "STATUS SIZE" on stdout
probe_url() {
    local url="$1"
    curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
        --max-time 10 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000 0"
}

# ════════════════════════════════════════════════════════════════
# STEP 1: Dynamic backup variants from content findings
# ════════════════════════════════════════════════════════════════
info "Step 1: Dynamic backup variants from discovered content..."

BACKUP_SUFFIXES=(.bak .old .orig .save "~" .swp .sav .backup)

if [ -s "$CONTENT_FINDINGS" ]; then
    # Extract URLs from content findings (format: "STATUS [SIZEb] URL")
    discovered_urls=$(grep -oP 'https?://[^\s]+' "$CONTENT_FINDINGS" 2>/dev/null | sort -u | head -"$MAX_BACKUP_URLS")
    url_count=$(echo "$discovered_urls" | grep -c . 2>/dev/null || echo 0)
    info "  Extracted ${url_count} URLs (cap: ${MAX_BACKUP_URLS}), testing ${#BACKUP_SUFFIXES[@]} suffixes each"

    backup_hits=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        for suffix in "${BACKUP_SUFFIXES[@]}"; do
            test_url="${url}${suffix}"
            result=$(probe_url "$test_url")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
                ((backup_hits++)) || true
                tag_severity "MEDIUM" "$test_url" "Backup file (${suffix}) — ${size}B"
            fi
        done
    done <<< "$discovered_urls"

    log "  Backup variant probing: ${backup_hits} hits"
else
    warn "  ac_content_findings.txt not found or empty — skipping dynamic backup variants"
fi

# ════════════════════════════════════════════════════════════════
# STEP 2: Config file probing
# ════════════════════════════════════════════════════════════════
info "Step 2: Config file probing..."

# Config paths with severity classification
# Format: "path|severity|description"
CONFIG_PATHS=(
    ".env|CRITICAL|Environment config (.env)"
    ".env.local|CRITICAL|Local environment config"
    ".env.production|CRITICAL|Production environment config"
    ".env.staging|CRITICAL|Staging environment config"
    ".env.development|CRITICAL|Development environment config"
    ".env.backup|CRITICAL|Backup environment config"
    ".git/config|CRITICAL|Git config (repo metadata)"
    ".git/HEAD|CRITICAL|Git HEAD (confirms .git exposure)"
    ".svn/entries|HIGH|SVN entries (version control)"
    ".htaccess|HIGH|Apache .htaccess config"
    ".htpasswd|HIGH|Apache password file"
    "web.config|HIGH|IIS/ASP.NET config"
    "web.config.bak|HIGH|IIS config backup"
    "wp-config.php.bak|HIGH|WordPress config backup"
    "configuration.php.bak|HIGH|Joomla config backup"
    "config.php.bak|HIGH|PHP config backup"
    "settings.py|HIGH|Django settings"
    ".DS_Store|MEDIUM|macOS directory metadata"
    "package.json|MEDIUM|Node.js package manifest"
    "composer.json|MEDIUM|PHP Composer manifest"
    "Gemfile|MEDIUM|Ruby Gemfile"
    "requirements.txt|MEDIUM|Python requirements"
    "Dockerfile|MEDIUM|Docker build file"
    "docker-compose.yml|MEDIUM|Docker Compose config"
)

config_hits=0
for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
    info "  Probing ${host} for ${#CONFIG_PATHS[@]} config paths..."

    for entry in "${CONFIG_PATHS[@]}"; do
        path=$(echo "$entry" | cut -d'|' -f1)
        severity=$(echo "$entry" | cut -d'|' -f2)
        desc=$(echo "$entry" | cut -d'|' -f3)

        test_url="${base_url}/${path}"
        result=$(probe_url "$test_url")
        status=$(echo "$result" | awk '{print $1}')
        size=$(echo "$result" | awk '{print $2}')

        if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
            ((config_hits++)) || true

            # Upgrade severity for .git and .env if they have real content
            if [[ "$path" == .git/* ]] || [[ "$path" == .env* ]]; then
                # Verify it has meaningful content (not just an error page)
                body_sample=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$test_url" 2>/dev/null | head -5)
                case "$path" in
                    .git/config)
                        if echo "$body_sample" | grep -qi '\[core\]\|repositoryformatversion'; then
                            tag_severity "CRITICAL" "$test_url" "${desc} — confirmed git repo (${size}B)"
                        else
                            tag_severity "MEDIUM" "$test_url" "${desc} — 200 but unconfirmed content (${size}B)"
                        fi
                        continue
                        ;;
                    .git/HEAD)
                        if echo "$body_sample" | grep -qP '^ref: refs/'; then
                            tag_severity "CRITICAL" "$test_url" "${desc} — confirmed git HEAD (${size}B)"
                        else
                            tag_severity "MEDIUM" "$test_url" "${desc} — 200 but unconfirmed content (${size}B)"
                        fi
                        continue
                        ;;
                    .env*)
                        if echo "$body_sample" | grep -qP '^\s*[A-Z_]+='; then
                            tag_severity "CRITICAL" "$test_url" "${desc} — confirmed env vars (${size}B)"
                        else
                            tag_severity "MEDIUM" "$test_url" "${desc} — 200 but unconfirmed content (${size}B)"
                        fi
                        continue
                        ;;
                esac
            fi

            tag_severity "$severity" "$test_url" "${desc} (${size}B)"
        fi
    done
done
log "  Config probing: ${config_hits} hits across ${#targets[@]} targets"

# ════════════════════════════════════════════════════════════════
# STEP 3: Source map discovery
# ════════════════════════════════════════════════════════════════
info "Step 3: Source map discovery..."

sourcemap_hits=0
if [ -s "$CONTENT_FINDINGS" ]; then
    # Extract .js URLs from content findings
    js_urls=$(grep -oP 'https?://[^\s]+\.js(?:\?[^\s]*)?' "$CONTENT_FINDINGS" 2>/dev/null | sort -u)
    js_count=$(echo "$js_urls" | grep -c . 2>/dev/null || echo 0)
    info "  Found ${js_count} JS URLs in content findings"

    while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue
        # Strip query string for .map append
        base_js=$(echo "$js_url" | sed 's/\?.*$//')
        map_url="${base_js}.map"

        result=$(probe_url "$map_url")
        status=$(echo "$result" | awk '{print $1}')
        size=$(echo "$result" | awk '{print $2}')

        if [ "$status" = "200" ] && [ "${size%.*}" -gt 0 ] 2>/dev/null; then
            ((sourcemap_hits++)) || true
            tag_sourcemap "MEDIUM" "$map_url" "Source map exposed (${size}B)"
        fi
    done <<< "$js_urls"
else
    warn "  ac_content_findings.txt not found — skipping source map probing"
fi
log "  Source map discovery: ${sourcemap_hits} hits"

# ════════════════════════════════════════════════════════════════
# STEP 4: Database dump discovery (ffuf + SecLists)
# ════════════════════════════════════════════════════════════════
info "Step 4: Database dump discovery..."

DB_WORDLIST="${SECLISTS}/Discovery/Web-Content/Common-DB-Backups.txt"

if $has_ffuf && [ -f "$DB_WORDLIST" ]; then
    db_wl_lines=$(wc -l < "$DB_WORDLIST" | tr -d ' ')
    info "  Using Common-DB-Backups.txt (${db_wl_lines} entries)"

    for base_url in "${targets[@]}"; do
        host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
        out_json="${OUT_DIR}/ffuf_backup/${host}_db_dumps.json"

        ffuf -u "${base_url}/FUZZ" -w "$DB_WORDLIST" \
            "${HUNT_UA_ARGS[@]}" \
            -mc 200 -fs 0 \
            -t "$THREADS" -o "$out_json" -of json \
            -timeout 10 2>/dev/null || true

        if [ -s "$out_json" ]; then
            python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    for r in data.get('results', []):
        url = r.get('url', '')
        length = r.get('length', 0)
        if length > 0:
            print(f'{url}|{length}')
except: pass
" "$out_json" 2>/dev/null | while IFS='|' read -r url size; do
                tag_severity "CRITICAL" "$url" "Database dump (${size}B)"
            done
        fi
    done
else
    if ! $has_ffuf; then
        warn "  ffuf not installed — skipping DB dump fuzzing"
    elif [ ! -f "$DB_WORDLIST" ]; then
        warn "  Common-DB-Backups.txt not found at ${DB_WORDLIST}"
    fi
fi

# ════════════════════════════════════════════════════════════════
# STEP 5: CMS configuration file discovery (ffuf + SecLists)
# ════════════════════════════════════════════════════════════════
info "Step 5: CMS configuration file discovery..."

CMS_CONFIG_WL="${SECLISTS}/Discovery/Web-Content/CMS/cms-configuration-files.txt"

if $has_ffuf && [ -f "$CMS_CONFIG_WL" ]; then
    cms_wl_lines=$(wc -l < "$CMS_CONFIG_WL" | tr -d ' ')
    info "  Using cms-configuration-files.txt (${cms_wl_lines} entries)"

    for base_url in "${targets[@]}"; do
        host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
        out_json="${OUT_DIR}/ffuf_backup/${host}_cms_configs.json"

        ffuf -u "${base_url}/FUZZ" -w "$CMS_CONFIG_WL" \
            "${HUNT_UA_ARGS[@]}" \
            -mc 200 -fs 0 \
            -t "$THREADS" -o "$out_json" -of json \
            -timeout 10 2>/dev/null || true

        if [ -s "$out_json" ]; then
            python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    for r in data.get('results', []):
        url = r.get('url', '')
        length = r.get('length', 0)
        if length > 0:
            print(f'{url}|{length}')
except: pass
" "$out_json" 2>/dev/null | while IFS='|' read -r url size; do
                tag_severity "HIGH" "$url" "CMS config file (${size}B)"
            done
        fi
    done
else
    if ! $has_ffuf; then
        warn "  ffuf not installed — skipping CMS config fuzzing"
    elif [ ! -f "$CMS_CONFIG_WL" ]; then
        warn "  cms-configuration-files.txt not found at ${CMS_CONFIG_WL}"
    fi
fi

# ── Dedup output files ──
for f in "$BACKUP_FINDINGS" "$SOURCEMAP_FINDINGS"; do
    [ -f "$f" ] && sort -u -o "$f" "$f" 2>/dev/null || true
done

# ── Summary ──
backup_count=$(count_lines "$BACKUP_FINDINGS")
sourcemap_count=$(count_lines "$SOURCEMAP_FINDINGS")
critical_count=$(grep -c '^\[CRITICAL\]' "$BACKUP_FINDINGS" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$BACKUP_FINDINGS" 2>/dev/null || echo 0)
medium_count=$(grep -c '^\[MEDIUM\]' "$BACKUP_FINDINGS" 2>/dev/null || echo 0)

log "Backup & config discovery complete:"
log "  Total findings:  ${backup_count}"
log "    CRITICAL:      ${critical_count}"
log "    HIGH:          ${high_count}"
log "    MEDIUM:        ${medium_count}"
log "  Source maps:     ${sourcemap_count}"
log "  Output: ${BACKUP_FINDINGS}"
log "  Output: ${SOURCEMAP_FINDINGS}"
