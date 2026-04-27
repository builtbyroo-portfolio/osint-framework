#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_vhost_discovery.sh — Virtual Host Discovery              ║
# ║  Host header fuzzing with ffuf + internal pattern probing    ║
# ║  Standard (5K) → Deep (20K, --deep) → Pattern probe → Verify║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_vhost_discovery.sh"
SCRIPT_DESC="Virtual Host Discovery"
DEEP_MODE="${DEEP_MODE:-false}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover hidden virtual hosts via Host header fuzzing (ffuf)"
    echo "  and internal naming pattern probes. Verifies with re-probe."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --deep                 Also fuzz with top-20000 wordlist"
    echo "  --submitted FILE       Submitted findings tracker"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"

# Custom arg parsing to handle --deep flag
DOMAIN="${DOMAIN:-}"
DOMAINS_FILE="${DOMAINS_FILE:-}"
OUT_DIR="${OUT_DIR:-./out}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)   DOMAIN="$2"; shift 2 ;;
        --domains)     DOMAINS_FILE="$2"; shift 2 ;;
        -o|--out)      OUT_DIR="$2"; shift 2 ;;
        -t|--threads)  THREADS="$2"; shift 2 ;;
        --deep)        DEEP_MODE=true; shift ;;
        --submitted)   SUBMITTED_FILE="$2"; shift 2 ;;
        -h|--help)     script_usage; exit 0 ;;
        *)             shift ;;  # ignore unknown (passed from orchestrator)
    esac
done
mkdir -p "$OUT_DIR"

phase_header "5" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

if ! check_tool ffuf 2>/dev/null; then
    err "ffuf is required for vhost discovery"
    exit 1
fi

if ! check_tool dig 2>/dev/null; then
    err "dig is required for DNS resolution"
    exit 1
fi

# Build domain list
DOMAIN_LIST="${OUT_DIR}/_ac_vhost_domains.txt"
> "$DOMAIN_LIST"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" >> "$DOMAIN_LIST"
elif [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" >> "$DOMAIN_LIST"
fi

# Wordlists
WL_5K="${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"
WL_20K="${SECLISTS}/Discovery/DNS/subdomains-top1million-20000.txt"

# Internal naming patterns to probe
INTERNAL_PREFIXES=(
    dev staging qa admin internal api test uat stage sandbox beta demo
)

# Output files
FINDINGS_FILE="${OUT_DIR}/ac_vhost_findings.txt"
RAW_VHOSTS="${OUT_DIR}/_ac_vhost_raw.txt"
mkdir -p "${OUT_DIR}/ffuf_vhost"

> "$FINDINGS_FILE"
> "$RAW_VHOSTS"

HAS_HTTPX=false
if command -v httpx-pd &>/dev/null; then
    HAS_HTTPX=true
fi

# ── Helper: get baseline response size ──
get_baseline_size() {
    local domain="$1" ip="$2"
    local size
    size=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
        --resolve "${domain}:443:${ip}" \
        -o /dev/null -w "%{size_download}" \
        "https://${ip}/" -H "Host: ${domain}" 2>/dev/null || echo "0")
    # Fallback to HTTP if HTTPS gives 0
    if [ "$size" = "0" ] || [ -z "$size" ]; then
        size=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            --resolve "${domain}:80:${ip}" \
            -o /dev/null -w "%{size_download}" \
            "http://${ip}/" -H "Host: ${domain}" 2>/dev/null || echo "0")
    fi
    echo "$size"
}

# ── Helper: run ffuf vhost fuzzing ──
run_vhost_ffuf() {
    local tier_name="$1"
    local wordlist="$2"
    local domain="$3"
    local ip="$4"
    local baseline_size="$5"

    if [ ! -f "$wordlist" ]; then
        warn "${tier_name}: wordlist not found: ${wordlist}"
        return
    fi

    local wl_lines
    wl_lines=$(wc -l < "$wordlist" | tr -d ' ')
    info "${tier_name}: ${wl_lines} words against ${domain} (${ip}), filter size=${baseline_size}"

    local out_json="${OUT_DIR}/ffuf_vhost/${domain}_${tier_name}.json"

    # Try HTTPS first
    ffuf -u "https://${ip}/" \
        -H "Host: FUZZ.${domain}" \
        -w "$wordlist" \
        "${HUNT_UA_ARGS[@]}" \
        -fs "$baseline_size" \
        -t "$THREADS" \
        -o "$out_json" -of json \
        -timeout 10 2>/dev/null || true

    # If no results from HTTPS, try HTTP
    if [ ! -s "$out_json" ] || ! python3 -c "
import json, sys
data = json.load(open(sys.argv[1]))
sys.exit(0 if data.get('results') else 1)
" "$out_json" 2>/dev/null; then
        ffuf -u "http://${ip}/" \
            -H "Host: FUZZ.${domain}" \
            -w "$wordlist" \
            "${HUNT_UA_ARGS[@]}" \
            -fs "$baseline_size" \
            -t "$THREADS" \
            -o "$out_json" -of json \
            -timeout 10 2>/dev/null || true
    fi

    # Parse results
    if [ -s "$out_json" ]; then
        python3 -c "
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    domain = sys.argv[2]
    for r in data.get('results', []):
        inp = r.get('input', {})
        fuzz_val = inp.get('FUZZ', '') if isinstance(inp, dict) else ''
        status = r.get('status', 0)
        length = r.get('length', 0)
        words = r.get('words', 0)
        vhost = f'{fuzz_val}.{domain}'
        print(vhost)
except: pass
" "$out_json" "$domain" 2>/dev/null >> "$RAW_VHOSTS"
    fi
}

# ── Helper: probe internal naming patterns ──
probe_internal_patterns() {
    local domain="$1"
    local ip="$2"
    local baseline_size="$3"

    info "Probing internal naming patterns for ${domain}..."

    for prefix in "${INTERNAL_PREFIXES[@]}"; do
        local vhost="${prefix}.${domain}"
        local status size title

        # HTTPS probe
        local resp
        resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
            --resolve "${vhost}:443:${ip}" \
            -o /dev/null -w "%{http_code}|%{size_download}" \
            "https://${ip}/" -H "Host: ${vhost}" 2>/dev/null || echo "000|0")

        status="${resp%%|*}"
        size="${resp##*|}"

        # Fallback to HTTP
        if [ "$status" = "000" ] || [ -z "$status" ]; then
            resp=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" \
                --resolve "${vhost}:80:${ip}" \
                -o /dev/null -w "%{http_code}|%{size_download}" \
                "http://${ip}/" -H "Host: ${vhost}" 2>/dev/null || echo "000|0")
            status="${resp%%|*}"
            size="${resp##*|}"
        fi

        # Skip if same as baseline or non-responsive
        [ "$status" = "000" ] && continue
        [ "$size" = "$baseline_size" ] && continue

        # Different response size = potential vhost
        log "  Pattern hit: ${vhost} — HTTP ${status}, ${size}B (baseline: ${baseline_size}B)"
        echo "$vhost" >> "$RAW_VHOSTS"
    done
}

# ── Helper: verify discovered vhosts ──
verify_vhost() {
    local vhost="$1"
    local status title body_preview

    # Try HTTPS then HTTP
    local resp_headers body
    resp_headers=$(curl -sk -D- --max-time 10 "${HUNT_UA_CURL[@]}" \
        -o /dev/null -w "%{http_code}" \
        "https://${vhost}/" 2>/dev/null || echo "000")

    if [ "$resp_headers" = "000" ]; then
        resp_headers=$(curl -sk -D- --max-time 10 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}" \
            "http://${vhost}/" 2>/dev/null || echo "000")
    fi
    status="$resp_headers"

    # Get title from body
    body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "https://${vhost}/" 2>/dev/null || \
           curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "http://${vhost}/" 2>/dev/null || echo "")
    title=$(echo "$body" | grep -oP '<title[^>]*>\K[^<]+' | head -1 | tr -d '\r\n' || echo "")
    [ -z "$title" ] && title="(no title)"

    echo "${status}|${vhost}|${title}"
}

# ══════════════════════════════════════════════════════════════
# Main: iterate over each domain
# ══════════════════════════════════════════════════════════════

total_found=0

while IFS= read -r domain; do
    [ -z "$domain" ] && continue

    info "Processing domain: ${domain}"

    # ── Step 1: Resolve IP ──
    ip=$(dig +short "$domain" A 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+$' | head -1)
    if [ -z "$ip" ]; then
        warn "Could not resolve ${domain} — skipping"
        continue
    fi
    log "Resolved ${domain} → ${ip}"

    # ── Step 2: Get baseline response size ──
    baseline_size=$(get_baseline_size "$domain" "$ip")
    if [ "$baseline_size" = "0" ] || [ -z "$baseline_size" ]; then
        warn "Could not get baseline response for ${domain} — using size 0 filter (may produce noise)"
        baseline_size="0"
    fi
    info "Baseline response size: ${baseline_size} bytes"

    # ── Step 3: ffuf Host header fuzzing — Standard (5K) ──
    if [ -f "$WL_5K" ]; then
        run_vhost_ffuf "vhost_5k" "$WL_5K" "$domain" "$ip" "$baseline_size"
    else
        warn "Standard wordlist not found: ${WL_5K}"
    fi

    # ── Step 4: ffuf Host header fuzzing — Deep (20K, --deep only) ──
    if $DEEP_MODE; then
        if [ -f "$WL_20K" ]; then
            run_vhost_ffuf "vhost_20k" "$WL_20K" "$domain" "$ip" "$baseline_size"
        else
            warn "Deep wordlist not found: ${WL_20K}"
        fi
    else
        info "Deep mode (20K words) — skipped (use --deep to enable)"
    fi

    # ── Step 5: Probe internal naming patterns ──
    probe_internal_patterns "$domain" "$ip" "$baseline_size"

done < "$DOMAIN_LIST"

# ── Dedup raw vhosts ──
if [ -s "$RAW_VHOSTS" ]; then
    sort -u -o "$RAW_VHOSTS" "$RAW_VHOSTS"
    discovered_count=$(count_lines "$RAW_VHOSTS")
    log "Discovered ${discovered_count} unique vhost candidates"
else
    info "No virtual hosts discovered"
    rm -f "$RAW_VHOSTS" "$DOMAIN_LIST"
    log "Results: ${FINDINGS_FILE}"
    exit 0
fi

# ── Verification phase ──
info "Verifying discovered vhosts..."

if $HAS_HTTPX; then
    info "Using httpx-pd for batch verification..."

    # Generate URL list for httpx
    HTTPX_INPUT="${OUT_DIR}/_ac_vhost_httpx_input.txt"
    while IFS= read -r vhost; do
        [ -z "$vhost" ] && continue
        echo "https://${vhost}"
        echo "http://${vhost}"
    done < "$RAW_VHOSTS" > "$HTTPX_INPUT"

    httpx-pd -l "$HTTPX_INPUT" -silent -status-code -title -content-length \
        "${HUNT_UA_ARGS[@]}" \
        -threads "$THREADS" -timeout 10 2>/dev/null | \
    while IFS= read -r line; do
        echo "$line" >> "$FINDINGS_FILE"
        log "  VERIFIED: ${line}"
        ((total_found++)) || true
    done

    rm -f "$HTTPX_INPUT"
else
    info "httpx-pd not available — verifying with curl (slower)..."

    while IFS= read -r vhost; do
        [ -z "$vhost" ] && continue

        result=$(verify_vhost "$vhost")
        status="${result%%|*}"
        rest="${result#*|}"
        host="${rest%%|*}"
        title="${rest#*|}"

        # Skip non-responsive
        [ "$status" = "000" ] && continue

        line="[${status}] ${host} — ${title}"
        echo "$line" >> "$FINDINGS_FILE"
        log "  VERIFIED: ${line}"
        ((total_found++)) || true
    done < "$RAW_VHOSTS"
fi

# ── Dedup and filter submitted ──
sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE"

if [ -f "$SUBMITTED_FILE" ] && [ -s "$SUBMITTED_FILE" ]; then
    FILTERED="${OUT_DIR}/_ac_vhost_filtered.txt"
    filter_submitted "$FINDINGS_FILE" "$FILTERED"
    mv "$FILTERED" "$FINDINGS_FILE"
fi

# ── Cleanup ──
rm -f "$RAW_VHOSTS" "$DOMAIN_LIST"

# ── Summary ──
final_count=$(count_lines "$FINDINGS_FILE")
log "Virtual host discovery complete"
log "  Verified vhosts: ${final_count}"
log "  Results: ${FINDINGS_FILE}"
if $DEEP_MODE; then
    log "  Mode: deep (5K + 20K wordlists)"
else
    log "  Mode: standard (5K wordlist, use --deep for 20K)"
fi
