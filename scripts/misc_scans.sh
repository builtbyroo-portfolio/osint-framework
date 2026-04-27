#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  misc_scans.sh — CRLF, Nikto, Dir Fuzzing, 403 Bypass       ║
# ║  Bundled miscellaneous scans                                  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="misc_scans.sh"
SCRIPT_DESC="CRLF + Nikto + Dir Fuzzing + 403 Bypass"
MAX_FUZZ_TARGETS="${MAX_FUZZ_TARGETS:-25}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Run CRLF injection, nikto, directory fuzzing, 403 bypass."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

WORDLIST_WEB="${SECLISTS}/Discovery/Web-Content/common.txt"
WORDLIST_API="${SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt"

phase_header "MISC" "$SCRIPT_DESC"

urls_input="${URLS_FILE:-${OUT_DIR}/urls.txt}"
if [ ! -f "$urls_input" ] && [ -n "${DOMAIN:-}" ]; then
    echo "https://${DOMAIN}" > "${OUT_DIR}/_misc_targets.txt"
    urls_input="${OUT_DIR}/_misc_targets.txt"
fi

if [ ! -f "$urls_input" ]; then
    err "Provide --urls or --domain"
    script_usage
    exit 1
fi

> "${OUT_DIR}/misc_findings.txt"

# ═══ CRLF Injection ═══
param_urls="${OUT_DIR}/parameterized_urls.txt"
param_count=0
[ -f "$param_urls" ] && param_count=$(count_lines "$param_urls")

if check_tool crlfuzz 2>/dev/null && [ "$param_count" -gt 0 ]; then
    info "Running crlfuzz (CRLF injection)..."
    head -50 "$param_urls" | crlfuzz -s \
        "${HUNT_UA_ARGS[@]}" \
        -o "${OUT_DIR}/crlfuzz_results.txt" 2>/dev/null || true
    crlf_count=$(count_lines "${OUT_DIR}/crlfuzz_results.txt")
    log "CRLF findings: ${crlf_count}"

    if [ "$crlf_count" -gt 0 ]; then
        echo "# --- CRLF Injection ---" >> "${OUT_DIR}/misc_findings.txt"
        cat "${OUT_DIR}/crlfuzz_results.txt" >> "${OUT_DIR}/misc_findings.txt"
    fi
else
    [ "$param_count" -eq 0 ] && warn "No parameterized URLs for CRLF testing"
fi

# ═══ Directory & API Fuzzing ═══
if check_tool ffuf 2>/dev/null; then
    # Filter to high-value non-standard hosts
    grep -vP '(www\.|blog\.|help\.|support\.|status\.|docs\.|marketing\.)' \
        "$urls_input" | head -"${MAX_FUZZ_TARGETS}" > "${OUT_DIR}/fuzz_targets.txt" 2>/dev/null || true
    fuzz_count=$(count_lines "${OUT_DIR}/fuzz_targets.txt")
    info "Fuzzing ${fuzz_count} high-value targets..."

    if [ ! -f "$WORDLIST_WEB" ]; then
        WORDLIST_WEB="/usr/share/wordlists/dirb/common.txt"
    fi

    if [ -f "$WORDLIST_WEB" ]; then
        mkdir -p "${OUT_DIR}/ffuf"
        while read -r target; do
            [ -z "$target" ] && continue
            host=$(echo "$target" | sed 's|https\?://||;s|/.*||')
            ffuf -u "${target}/FUZZ" -w "$WORDLIST_WEB" \
                "${HUNT_UA_ARGS[@]}" \
                -mc 200,201,301,302,401,403,405,500 -fc 404 \
                -t "${THREADS}" -s -o "${OUT_DIR}/ffuf/${host}.json" -of json \
                2>/dev/null || true
        done < "${OUT_DIR}/fuzz_targets.txt"

        # API endpoint fuzzing
        if [ -f "$WORDLIST_API" ]; then
            info "Fuzzing API endpoints..."
            while read -r target; do
                [ -z "$target" ] && continue
                host=$(echo "$target" | sed 's|https\?://||;s|/.*||')
                ffuf -u "${target}/FUZZ" -w "$WORDLIST_API" \
                    "${HUNT_UA_ARGS[@]}" \
                    -mc 200,201,301,302,401,405,500 -fc 404,403 \
                    -t "${THREADS}" -s -o "${OUT_DIR}/ffuf/api_${host}.json" -of json \
                    2>/dev/null || true
            done < "${OUT_DIR}/fuzz_targets.txt"
        fi

        # Merge ffuf results
        python3 -c "
import sys, json, glob
for f in glob.glob('${OUT_DIR}/ffuf/*.json'):
    try:
        data = json.load(open(f))
        for r in data.get('results', []):
            print(f\"{r.get('status','')} {r.get('length','')} {r.get('url','')}\")
    except: pass
" 2>/dev/null | sort -u > "${OUT_DIR}/ffuf_all_results.txt" || true

        ffuf_count=$(count_lines "${OUT_DIR}/ffuf_all_results.txt")
        log "ffuf results: ${ffuf_count} endpoints"

        if [ "$ffuf_count" -gt 0 ]; then
            echo "# --- Directory/API Fuzzing ---" >> "${OUT_DIR}/misc_findings.txt"
            cat "${OUT_DIR}/ffuf_all_results.txt" >> "${OUT_DIR}/misc_findings.txt"
        fi
    else
        warn "No wordlist found, skipping ffuf"
    fi
fi

# ═══ Nikto ═══
if check_tool nikto 2>/dev/null; then
    head -5 "$urls_input" > "${OUT_DIR}/nikto_targets.txt"
    target_count=$(count_lines "${OUT_DIR}/nikto_targets.txt")
    info "Running nikto on top ${target_count} targets (this is slow)..."

    mkdir -p "${OUT_DIR}/nikto"
    while read -r target; do
        [ -z "$target" ] && continue
        host=$(echo "$target" | sed 's|https\?://||;s|/.*||')
        nikto -h "$target" -nointeractive -maxtime 120 \
            "${HUNT_UA_NIKTO[@]}" \
            -output "${OUT_DIR}/nikto/${host}.txt" 2>/dev/null || true
    done < "${OUT_DIR}/nikto_targets.txt"

    nikto_count=$(grep -rl "OSVDB\|+ /" "${OUT_DIR}/nikto/" 2>/dev/null | wc -l || echo 0)
    log "Nikto: scanned ${target_count} targets, ${nikto_count} with findings"

    if [ "$nikto_count" -gt 0 ]; then
        echo "# --- Nikto ---" >> "${OUT_DIR}/misc_findings.txt"
        cat "${OUT_DIR}"/nikto/*.txt >> "${OUT_DIR}/misc_findings.txt" 2>/dev/null || true
    fi
fi

# ═══ CORS Misconfiguration Scanning ═══
# NOTE: CORS has 0% acceptance rate (4/4 rejected: Chime, SEEK, Indeed x2).
# Only CORS_CRIT (origin reflected + credentials=true) is worth manual review,
# and ONLY if the endpoint returns sensitive user data (not public content).
# All CORS findings are tagged DO_NOT_SUBMIT by default.
info "Scanning for CORS misconfiguration (credentials + sensitive data only)..."
> "${OUT_DIR}/cors_findings.txt"
head -50 "$urls_input" | while read -r target_url; do
    [ -z "$target_url" ] && continue
    # Test with arbitrary origin
    cors_headers=$(curl -sk -D- -o /dev/null --max-time 8 \
        "${HUNT_UA_CURL[@]}" \
        -H "Origin: https://evil.com" "$target_url" 2>/dev/null)
    acao=$(echo "$cors_headers" | grep -i 'access-control-allow-origin' | head -1 | tr -d '\r')
    acac=$(echo "$cors_headers" | grep -i 'access-control-allow-credentials' | head -1 | tr -d '\r')

    if echo "$acao" | grep -qi "evil.com"; then
        if echo "$acac" | grep -qi "true"; then
            # Only CRIT is worth investigating — and only with sensitive data proof
            echo "[DO_NOT_SUBMIT:CORS_NEEDS_DATA_THEFT_POC] CORS_CRIT: ${target_url} | Origin reflected + Credentials=true — MUST build HTML PoC stealing sensitive session data to submit" >> "${OUT_DIR}/cors_findings.txt"
        fi
        # CORS_MED (no credentials) = never reportable, don't even log
    fi
    # Wildcard CORS = browser prevents credentials, never reportable
done

cors_count=$(count_lines "${OUT_DIR}/cors_findings.txt")
log "CORS findings: ${cors_count} (all tagged DO_NOT_SUBMIT — need manual data theft PoC)"
if [ "$cors_count" -gt 0 ]; then
    warn "CORS findings detected but tagged DO_NOT_SUBMIT — 0% acceptance without data theft PoC"
    echo "# --- CORS Misconfiguration (DO NOT SUBMIT without data theft PoC) ---" >> "${OUT_DIR}/misc_findings.txt"
    cat "${OUT_DIR}/cors_findings.txt" >> "${OUT_DIR}/misc_findings.txt"
fi

# ═══ Response Header Info Disclosure ═══
info "Checking for sensitive response header disclosure..."
> "${OUT_DIR}/header_disclosure_findings.txt"
head -30 "$urls_input" | while read -r target_url; do
    [ -z "$target_url" ] && continue
    headers=$(curl -sk -D- -o /dev/null --max-time 8 "$target_url" 2>/dev/null | tr -d '\r')
    # Check for origin IP disclosure
    echo "$headers" | grep -iP '^(originip|origin-hostname|x-real-ip|x-backend-server):' | while read -r h; do
        echo "ORIGIN_IP: ${target_url} | ${h}" >> "${OUT_DIR}/header_disclosure_findings.txt"
    done
    # Check for datacenter / infrastructure headers
    echo "$headers" | grep -iP '^(x-datacenter|x-hosting-region|x-server-name|x-varnish-fwd-server|x-forwarded-server|x-debug|x-tzla-edge-server):' | while read -r h; do
        echo "INFRA_LEAK: ${target_url} | ${h}" >> "${OUT_DIR}/header_disclosure_findings.txt"
    done
    # Check for version disclosure
    echo "$headers" | grep -iP '^(x-powered-by|x-aspnet-version|x-generator):' | while read -r h; do
        echo "VERSION_LEAK: ${target_url} | ${h}" >> "${OUT_DIR}/header_disclosure_findings.txt"
    done
done

header_disc_count=$(count_lines "${OUT_DIR}/header_disclosure_findings.txt")
log "Header disclosure findings: ${header_disc_count}"
if [ "$header_disc_count" -gt 0 ]; then
    echo "# --- Response Header Info Disclosure ---" >> "${OUT_DIR}/misc_findings.txt"
    cat "${OUT_DIR}/header_disclosure_findings.txt" >> "${OUT_DIR}/misc_findings.txt"
fi

# ═══ 403 Bypass Testing ═══
info "Collecting 403 URLs..."
> "${OUT_DIR}/403_urls.txt"
if [ -f "${OUT_DIR}/live_hosts_raw.txt" ]; then
    grep -i "\[403\]" "${OUT_DIR}/live_hosts_raw.txt" 2>/dev/null | \
        grep -oP 'https?://[^\s\[\]]+' >> "${OUT_DIR}/403_urls.txt" || true
fi
if [ -f "${OUT_DIR}/ffuf_all_results.txt" ]; then
    grep "^403 " "${OUT_DIR}/ffuf_all_results.txt" 2>/dev/null | \
        awk '{print $3}' >> "${OUT_DIR}/403_urls.txt" || true
fi
sort -u -o "${OUT_DIR}/403_urls.txt" "${OUT_DIR}/403_urls.txt"
count_403=$(count_lines "${OUT_DIR}/403_urls.txt")

if [ "$count_403" -gt 0 ]; then
    info "Testing ${count_403} forbidden URLs for bypass..."
    > "${OUT_DIR}/403_bypasses.txt"
    head -50 "${OUT_DIR}/403_urls.txt" | while read -r url; do
        for bypass in \
            "${url}/" "${url}/." "${url}/..;/" "${url}%20" "${url}%09" \
            "${url}..;/" "${url};/" "${url}/.randomstring"; do
            status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$bypass" 2>/dev/null)
            if [[ "$status" =~ ^(200|301|302)$ ]]; then
                echo "${status} ${bypass}" >> "${OUT_DIR}/403_bypasses.txt"
            fi
        done
        # Header bypasses
        for header in "X-Original-URL: /" "X-Rewrite-URL: /" "X-Forwarded-For: 127.0.0.1"; do
            status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -H "$header" "$url" 2>/dev/null)
            if [[ "$status" =~ ^(200|301|302)$ ]]; then
                echo "${status} ${url} [${header}]" >> "${OUT_DIR}/403_bypasses.txt"
            fi
        done
    done

    bypass_count=$(count_lines "${OUT_DIR}/403_bypasses.txt")
    log "403 bypass findings: ${bypass_count}"

    if [ "$bypass_count" -gt 0 ]; then
        echo "# --- 403 Bypass ---" >> "${OUT_DIR}/misc_findings.txt"
        cat "${OUT_DIR}/403_bypasses.txt" >> "${OUT_DIR}/misc_findings.txt"
    fi
else
    warn "No 403 URLs to test"
fi

log "Total misc findings: $(count_lines "${OUT_DIR}/misc_findings.txt")"
log "Misc results: ${OUT_DIR}/misc_findings.txt"
