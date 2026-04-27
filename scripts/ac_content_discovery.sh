#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_content_discovery.sh — Tiered Content Discovery          ║
# ║  Tier 1 (7K) → Tier 2 (20K) → Tier 3 (220K, --deep)        ║
# ║  CMS-specific lists · Recursive · Result classification      ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_content_discovery.sh"
SCRIPT_DESC="Tiered Content Discovery"

DEEP_MODE="${DEEP_MODE:-false}"
RECURSIVE_MODE="${RECURSIVE_MODE:-false}"
MAX_RECURSIVE_DIRS=20

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Multi-tier content discovery with ffuf. Classifies results into"
    echo "  403 URLs, login panels, and interesting endpoints for downstream phases."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --deep                 Enable Tier 3 (DirBuster-medium, 220K words)"
    echo "  --recursive            Re-fuzz discovered directories one level deep"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"

# Override parse_common_args to handle --deep/--recursive
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
        --recursive)   RECURSIVE_MODE=true; shift ;;
        --submitted)   SUBMITTED_FILE="$2"; shift 2 ;;
        -h|--help)     script_usage; exit 0 ;;
        *)             shift ;;  # ignore unknown (passed from orchestrator)
    esac
done
mkdir -p "$OUT_DIR"

phase_header "2" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

if ! check_tool ffuf 2>/dev/null; then
    err "ffuf is required for content discovery"
    exit 1
fi

# Build target list
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("https://${d}")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("https://${DOMAIN}")
fi

# SecLists paths
WL_COMMON="${SECLISTS}/Discovery/Web-Content/common.txt"
WL_QUICKHITS="${SECLISTS}/Discovery/Web-Content/quickhits.txt"
WL_BIG="${SECLISTS}/Discovery/Web-Content/big.txt"
WL_DIRBUSTER="${SECLISTS}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"

# Output files
> "${OUT_DIR}/ac_content_findings.txt"
> "${OUT_DIR}/ac_403_urls.txt"
> "${OUT_DIR}/ac_login_panels.txt"
> "${OUT_DIR}/ac_interesting_endpoints.txt"
mkdir -p "${OUT_DIR}/ffuf_content"

# Login/admin pattern for classification
LOGIN_PATTERN='(login|signin|sign-in|auth|admin|panel|dashboard|manage|manager|console|portal|backend|phpmyadmin|adminer|grafana|jenkins|kibana|webmail|cpanel|plesk|wp-admin|wp-login)'

# ── ffuf runner function ──
run_ffuf_tier() {
    local tier_name="$1"
    local wordlist="$2"
    local thread_count="${3:-$THREADS}"

    if [ ! -f "$wordlist" ]; then
        warn "${tier_name}: wordlist not found: ${wordlist}"
        return
    fi

    local wl_lines
    wl_lines=$(wc -l < "$wordlist" | tr -d ' ')
    info "${tier_name}: ${wl_lines} words, ${thread_count} threads"

    for base_url in "${targets[@]}"; do
        local host
        host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
        local out_json="${OUT_DIR}/ffuf_content/${host}_${tier_name}.json"

        ffuf -u "${base_url}/FUZZ" -w "$wordlist" \
            "${HUNT_UA_ARGS[@]}" \
            -mc 200,201,301,302,401,403,405,500 -fc 404 \
            -t "$thread_count" -o "$out_json" -of json \
            -timeout 10 2>/dev/null || true

        # Parse results
        if [ -s "$out_json" ]; then
            python3 -c "
import json, sys, re
try:
    data = json.load(open(sys.argv[1]))
    login_re = re.compile(r'${LOGIN_PATTERN}', re.I)
    for r in data.get('results', []):
        url = r.get('url', '')
        status = r.get('status', 0)
        length = r.get('length', 0)
        words = r.get('words', 0)
        line = f'{status} [{length}B] {url}'
        print(f'CONTENT|{line}')
        if status == 403:
            print(f'403|{url}')
        if login_re.search(url):
            print(f'LOGIN|{url}')
        if status in (200, 301, 302) and length > 0:
            print(f'INTERESTING|{url}')
except: pass
" "$out_json" 2>/dev/null | while IFS='|' read -r tag value; do
                case "$tag" in
                    CONTENT)     echo "$value" >> "${OUT_DIR}/ac_content_findings.txt" ;;
                    403)         echo "$value" >> "${OUT_DIR}/ac_403_urls.txt" ;;
                    LOGIN)       echo "$value" >> "${OUT_DIR}/ac_login_panels.txt" ;;
                    INTERESTING) echo "$value" >> "${OUT_DIR}/ac_interesting_endpoints.txt" ;;
                esac
            done
        fi
    done
}

# ── Tier 1: Fast scan (~7K words) ──
# Merge common.txt + quickhits.txt into a temporary wordlist
TIER1_WL="${OUT_DIR}/_tier1_merged.txt"
cat "$WL_COMMON" "$WL_QUICKHITS" 2>/dev/null | sort -u > "$TIER1_WL"
run_ffuf_tier "tier1_fast" "$TIER1_WL"

# ── Tier 2: Medium scan (~20K words) ──
run_ffuf_tier "tier2_medium" "$WL_BIG"

# ── Tier 3: Deep scan (~220K words, --deep only) ──
if $DEEP_MODE; then
    run_ffuf_tier "tier3_deep" "$WL_DIRBUSTER" 15
else
    info "Tier 3 (DirBuster-medium, 220K words) — skipped (use --deep to enable)"
fi

# ── CMS-specific wordlists from Phase 1 ──
CMS_WL_FILE="${OUT_DIR}/ac_cms_wordlists.txt"
if [ -s "$CMS_WL_FILE" ]; then
    info "Running CMS-specific wordlists from fingerprinting..."
    cms_idx=0
    while IFS= read -r cms_wl; do
        [ -z "$cms_wl" ] || [ ! -f "$cms_wl" ] && continue
        ((cms_idx++)) || true
        run_ffuf_tier "cms_${cms_idx}" "$cms_wl"
    done < "$CMS_WL_FILE"
else
    info "No CMS-specific wordlists (Phase 1 did not detect CMS)"
fi

# ── Recursive mode: re-fuzz discovered directories ──
if $RECURSIVE_MODE; then
    info "Recursive mode: re-fuzzing discovered directories..."
    # Extract unique directories from content findings (301/302 responses)
    DISCOVERED_DIRS="${OUT_DIR}/_discovered_dirs.txt"
    grep -oP 'https?://[^\s]+' "${OUT_DIR}/ac_content_findings.txt" 2>/dev/null | \
        grep -v '\.' | sort -u | head -"$MAX_RECURSIVE_DIRS" > "$DISCOVERED_DIRS" || true

    dir_count=$(wc -l < "$DISCOVERED_DIRS" 2>/dev/null | tr -d ' ' || echo 0)
    if [ "$dir_count" -gt 0 ]; then
        info "Re-fuzzing ${dir_count} discovered directories (cap: ${MAX_RECURSIVE_DIRS})..."
        rec_idx=0
        while IFS= read -r dir_url; do
            [ -z "$dir_url" ] && continue
            ((rec_idx++)) || true
            # Ensure trailing slash
            [[ "$dir_url" != */ ]] && dir_url="${dir_url}/"
            local host
            host=$(echo "$dir_url" | sed 's|https\?://||;s|/.*||')
            local out_json="${OUT_DIR}/ffuf_content/${host}_recursive_${rec_idx}.json"

            ffuf -u "${dir_url}FUZZ" -w "$WL_COMMON" \
                "${HUNT_UA_ARGS[@]}" \
                -mc 200,201,301,302,401,403,405,500 -fc 404 \
                -t "$THREADS" -o "$out_json" -of json \
                -timeout 10 2>/dev/null || true

            if [ -s "$out_json" ]; then
                python3 -c "
import json, sys, re
try:
    data = json.load(open(sys.argv[1]))
    login_re = re.compile(r'${LOGIN_PATTERN}', re.I)
    for r in data.get('results', []):
        url = r.get('url', '')
        status = r.get('status', 0)
        length = r.get('length', 0)
        line = f'{status} [{length}B] {url}'
        print(f'CONTENT|{line}')
        if status == 403: print(f'403|{url}')
        if login_re.search(url): print(f'LOGIN|{url}')
        if status in (200, 301, 302) and length > 0: print(f'INTERESTING|{url}')
except: pass
" "$out_json" 2>/dev/null | while IFS='|' read -r tag value; do
                    case "$tag" in
                        CONTENT)     echo "[RECURSIVE] $value" >> "${OUT_DIR}/ac_content_findings.txt" ;;
                        403)         echo "$value" >> "${OUT_DIR}/ac_403_urls.txt" ;;
                        LOGIN)       echo "$value" >> "${OUT_DIR}/ac_login_panels.txt" ;;
                        INTERESTING) echo "$value" >> "${OUT_DIR}/ac_interesting_endpoints.txt" ;;
                    esac
                done
            fi
        done < "$DISCOVERED_DIRS"
    else
        info "No directories found for recursive fuzzing"
    fi
    rm -f "$DISCOVERED_DIRS"
fi

# ── Dedup output files ──
for f in ac_content_findings.txt ac_403_urls.txt ac_login_panels.txt ac_interesting_endpoints.txt; do
    sort -u -o "${OUT_DIR}/${f}" "${OUT_DIR}/${f}" 2>/dev/null || true
done

# Cleanup temp files
rm -f "$TIER1_WL"

content_count=$(count_lines "${OUT_DIR}/ac_content_findings.txt")
forbidden_count=$(count_lines "${OUT_DIR}/ac_403_urls.txt")
login_count=$(count_lines "${OUT_DIR}/ac_login_panels.txt")
interesting_count=$(count_lines "${OUT_DIR}/ac_interesting_endpoints.txt")

log "Content discovery: ${content_count} total endpoints"
log "  403 URLs:              ${forbidden_count} → Phase 6"
log "  Login panels:          ${login_count} → Phases 7, 10"
log "  Interesting endpoints: ${interesting_count} → Phases 8, 9"
