#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  recon.sh — Subdomain Enumeration, URL & Endpoint Discovery  ║
# ║  Replaces hunt.sh Phase 1 + Phase 2                          ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="recon.sh"
SCRIPT_DESC="Recon — Subdomains, URLs, Dorking, Nmap"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Subdomain enumeration, live host discovery, URL collection."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Single target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

# Build domains list
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    DOMAINS_CLEAN=$(sed 's/\*\.//' "$DOMAINS_FILE" | sort -u)
elif [ -n "${DOMAIN:-}" ]; then
    DOMAINS_CLEAN=$(echo "$DOMAIN" | sed 's/\*\.//')
else
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

phase_header 1 "$SCRIPT_DESC"

# ── Subdomain Enumeration ──
info "Running subfinder..."
echo "$DOMAINS_CLEAN" | subfinder -silent -all 2>/dev/null | sort -u > "${OUT_DIR}/subdomains_raw.txt"
log "Subdomains (raw): $(count_lines "${OUT_DIR}/subdomains_raw.txt")"

# ── Subdomain Permutation (alterx) ──
if check_tool alterx 2>/dev/null; then
    info "Running alterx (subdomain permutation from discovered patterns)..."
    cat "${OUT_DIR}/subdomains_raw.txt" | alterx -silent 2>/dev/null | sort -u > "${OUT_DIR}/subdomains_permuted.txt"
    perm_count=$(count_lines "${OUT_DIR}/subdomains_permuted.txt")
    log "Permuted subdomains: ${perm_count}"
else
    > "${OUT_DIR}/subdomains_permuted.txt"
fi

# ── DNS Resolution + Wildcard Filtering (dnsx) ──
if check_tool dnsx 2>/dev/null; then
    info "Running dnsx (DNS resolution + wildcard filtering)..."
    cat "${OUT_DIR}/subdomains_raw.txt" "${OUT_DIR}/subdomains_permuted.txt" 2>/dev/null | \
        sort -u | dnsx -silent -a -resp -wd 2>/dev/null | \
        awk '{print $1}' | sort -u > "${OUT_DIR}/subdomains.txt"
    log "Subdomains (resolved, wildcards filtered): $(count_lines "${OUT_DIR}/subdomains.txt")"
else
    cp "${OUT_DIR}/subdomains_raw.txt" "${OUT_DIR}/subdomains.txt"
    log "Subdomains (no DNS filtering): $(count_lines "${OUT_DIR}/subdomains.txt")"
fi

# ── CNAME Chain Resolution (subdomain takeover detection) ──
if check_tool dnsx 2>/dev/null; then
    info "Running dnsx CNAME resolution (takeover detection)..."
    dnsx -l "${OUT_DIR}/subdomains.txt" -cname -silent -retry 2 \
        -o "${OUT_DIR}/cname_records.txt" 2>/dev/null || true
    log "CNAME records: $(count_lines "${OUT_DIR}/cname_records.txt")"

    # Check for dangling CNAMEs (NXDOMAIN on CNAME targets)
    if [ -s "${OUT_DIR}/cname_records.txt" ]; then
        info "Checking for dangling CNAMEs (NXDOMAIN)..."
        > "${OUT_DIR}/dangling_cnames.txt"
        while IFS= read -r line; do
            subdomain=$(echo "$line" | awk '{print $1}')
            cname_target=$(echo "$line" | awk '{print $NF}')
            # Check if CNAME target resolves
            if ! dig +short "$cname_target" 2>/dev/null | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
                echo "DANGLING: ${subdomain} -> ${cname_target}" >> "${OUT_DIR}/dangling_cnames.txt"
            fi
        done < "${OUT_DIR}/cname_records.txt"
        dangling_count=$(count_lines "${OUT_DIR}/dangling_cnames.txt")
        if [ "$dangling_count" -gt 0 ]; then
            warn "FOUND ${dangling_count} dangling CNAMEs (potential subdomain takeover!)"
        fi
    fi
fi

# ── Live Host Discovery ──
info "Running httpx (live host detection + tech fingerprint + headers)..."
httpx-pd -l "${OUT_DIR}/subdomains.txt" -silent -threads "${THREADS}" \
    "${HUNT_UA_ARGS[@]}" \
    -status-code -title -tech-detect -content-length \
    -server -cname -cdn \
    -include-response-header -json \
    -o "${OUT_DIR}/live_hosts_json.txt" 2>/dev/null || true

# Also run plain text output for downstream compatibility
httpx-pd -l "${OUT_DIR}/subdomains.txt" -silent -threads "${THREADS}" \
    "${HUNT_UA_ARGS[@]}" \
    -status-code -title -tech-detect -content-length \
    -o "${OUT_DIR}/live_hosts_raw.txt" 2>/dev/null || true

grep -oP 'https?://[^\s\[\]]+' "${OUT_DIR}/live_hosts_raw.txt" 2>/dev/null | sort -u > "${OUT_DIR}/urls.txt"
log "Live URLs: $(count_lines "${OUT_DIR}/urls.txt")"

# ── Extract info disclosure from response headers ──
if [ -s "${OUT_DIR}/live_hosts_json.txt" ]; then
    info "Analyzing response headers for info disclosure..."
    python3 -c "
import json, sys
disclosure_headers = [
    'x-datacenter', 'x-hosting-region', 'x-backend', 'x-server',
    'x-powered-by', 'x-aspnet-version', 'x-debug', 'x-varnish',
    'x-cache-key', 'x-real-ip', 'x-forwarded-server',
    'originip', 'origin-hostname', 'x-amz-bucket-region',
    'x-envoy-upstream-service-time', 'x-generator'
]
cors_issues = []
info_disclosures = []
for line in open('${OUT_DIR}/live_hosts_json.txt'):
    try:
        d = json.loads(line.strip())
        url = d.get('url', d.get('input', ''))
        headers = d.get('header', {})
        # Flatten header dict (httpx returns lists)
        flat = {}
        for k, v in headers.items():
            flat[k.lower()] = v if isinstance(v, str) else (v[0] if v else '')
        # Check info disclosure headers
        for h in disclosure_headers:
            if h in flat and flat[h]:
                info_disclosures.append(f'{url} | {h}: {flat[h]}')
        # Check CORS misconfiguration
        acao = flat.get('access-control-allow-origin', '')
        acac = flat.get('access-control-allow-credentials', '')
        if acao == '*' or (acac.lower() == 'true' and acao and acao != url.split('/')[0] + '//' + url.split('/')[2]):
            cors_issues.append(f'{url} | ACAO={acao} ACAC={acac}')
    except: pass
if info_disclosures:
    with open('${OUT_DIR}/header_info_disclosure.txt', 'w') as f:
        f.write('\n'.join(info_disclosures) + '\n')
    print(f'Header info disclosures: {len(info_disclosures)}')
if cors_issues:
    with open('${OUT_DIR}/cors_passive_findings.txt', 'w') as f:
        f.write('\n'.join(cors_issues) + '\n')
    print(f'Passive CORS issues: {len(cors_issues)}')
" 2>/dev/null || true
    log "Header analysis complete"
fi

# ── URL Discovery (gau + katana in parallel) ──
info "Running gau (Wayback Machine + Common Crawl)..."
echo "$DOMAINS_CLEAN" | gau --threads "${THREADS}" \
    --blacklist png,jpg,gif,svg,woff,woff2,ttf,eot,ico,css \
    2>/dev/null | sort -u > "${OUT_DIR}/gau_urls.txt" &
gau_pid=$!

info "Running katana (live crawl + JS endpoint extraction)..."
katana -list "${OUT_DIR}/urls.txt" -silent -jc -d 3 -ct "${THREADS}" \
    "${HUNT_UA_ARGS[@]}" \
    -o "${OUT_DIR}/katana_urls.txt" 2>/dev/null &
katana_pid=$!

# ── Arjun (hidden parameter discovery) ──
if check_tool arjun 2>/dev/null; then
    info "Running arjun (hidden parameter discovery on top 10 targets)..."
    mkdir -p "${OUT_DIR}/arjun"
    head -10 "${OUT_DIR}/urls.txt" 2>/dev/null | while read -r url; do
        arjun -u "$url" -q -oJ "${OUT_DIR}/arjun/$(echo "$url" | md5sum | cut -c1-8).json" \
            --stable -t "${THREADS}" 2>/dev/null || true
    done &
    arjun_pid=$!
fi

wait $gau_pid 2>/dev/null || true
wait $katana_pid 2>/dev/null || true
wait ${arjun_pid:-0} 2>/dev/null || true

log "gau: $(count_lines "${OUT_DIR}/gau_urls.txt") historical URLs"
log "katana: $(count_lines "${OUT_DIR}/katana_urls.txt") crawled URLs"

# Merge all URLs
cat "${OUT_DIR}/gau_urls.txt" "${OUT_DIR}/katana_urls.txt" 2>/dev/null | sort -u > "${OUT_DIR}/all_urls.txt"
log "Total unique URLs: $(count_lines "${OUT_DIR}/all_urls.txt")"

# Extract JS files
grep -iP '\.(js|mjs)(\?|$)' "${OUT_DIR}/all_urls.txt" 2>/dev/null | sort -u > "${OUT_DIR}/js_files.txt"
log "JavaScript files: $(count_lines "${OUT_DIR}/js_files.txt")"

# ── JS Endpoint Extraction (xnLinkFinder) ──
if check_tool xnLinkFinder 2>/dev/null && [ -s "${OUT_DIR}/js_files.txt" ]; then
    info "Running xnLinkFinder (JS endpoint + parameter extraction)..."
    js_count=$(count_lines "${OUT_DIR}/js_files.txt")
    head -100 "${OUT_DIR}/js_files.txt" | xnLinkFinder -i - \
        -o "${OUT_DIR}/js_endpoints.txt" \
        -op "${OUT_DIR}/js_parameters.txt" \
        -sf "$(echo "$DOMAINS_CLEAN" | head -1)" \
        2>/dev/null || true
    log "JS endpoints: $(count_lines "${OUT_DIR}/js_endpoints.txt")"
    log "JS parameters: $(count_lines "${OUT_DIR}/js_parameters.txt")"
    # Merge JS endpoints into all URLs
    if [ -s "${OUT_DIR}/js_endpoints.txt" ]; then
        cat "${OUT_DIR}/js_endpoints.txt" >> "${OUT_DIR}/all_urls.txt"
        sort -u -o "${OUT_DIR}/all_urls.txt" "${OUT_DIR}/all_urls.txt"
    fi
fi

# Extract parameterized URLs
grep '=' "${OUT_DIR}/all_urls.txt" 2>/dev/null | sort -u > "${OUT_DIR}/parameterized_urls.txt"
log "Parameterized URLs: $(count_lines "${OUT_DIR}/parameterized_urls.txt")"

# ── BHEH: ZoomeyeSearch ──
if check_bheh "ZoomeyeSearch" || command -v zoomeyesearch &>/dev/null; then
    info "Running ZoomeyeSearch (internet-wide asset discovery)..."
    while IFS= read -r domain; do
        clean_domain=$(echo "$domain" | sed 's/\*\.//')
        if command -v zoomeyesearch &>/dev/null; then
            zoomeyesearch --domain "$clean_domain" \
                -o "${OUT_DIR}/zoomeye_${clean_domain}.txt" \
                2>/dev/null || true
        fi
    done <<< "$DOMAINS_CLEAN"
    zoom_count=$(cat "${OUT_DIR}"/zoomeye_*.txt 2>/dev/null | wc -l || echo 0)
    log "ZoomeyeSearch: ${zoom_count} results"
fi

# ── Nmap (top ports, fast SYN scan) ──
if check_tool nmap 2>/dev/null; then
    info "Running nmap (top 1000 ports, fast scan)..."
    sed 's|https\?://||;s|/.*||;s|:.*||' "${OUT_DIR}/urls.txt" | sort -u | head -30 > "${OUT_DIR}/target_ips.txt"
    sudo nmap -sS -T4 --top-ports 1000 --open -iL "${OUT_DIR}/target_ips.txt" \
        -oN "${OUT_DIR}/nmap_results.txt" -oG "${OUT_DIR}/nmap_greppable.txt" \
        2>/dev/null || true
    open_ports=$(grep -c "open" "${OUT_DIR}/nmap_greppable.txt" 2>/dev/null || echo 0)
    log "Nmap open ports found: ${open_ports}"
fi

# ── Summary ──
echo ""
log "Recon complete. Key outputs:"
log "  Subdomains:         ${OUT_DIR}/subdomains.txt"
log "  Live URLs:          ${OUT_DIR}/urls.txt"
log "  All URLs:           ${OUT_DIR}/all_urls.txt"
log "  Parameterized URLs: ${OUT_DIR}/parameterized_urls.txt"
log "  JS files:           ${OUT_DIR}/js_files.txt"
