#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_content_spoof.sh — Content Spoofing / HTML Injection     ║
# ║  Reflected content in error pages, search, and messages      ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_content_spoof.sh"
SCRIPT_DESC="Content Spoofing / HTML Injection"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test for reflected content in 404 pages, search results,"
    echo "  and error messages. Injects benign HTML to detect rendering."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with surface URLs (from Phase 1)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "5" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

urls_input="${URLS_FILE:-${OUT_DIR}/surface_urls.txt}"
findings_file="${OUT_DIR}/content_spoof_findings.txt"
> "$findings_file"

# ── Build base URLs from domains ──
base_urls="${OUT_DIR}/spoof_base_urls.txt"
> "$base_urls"

# Extract unique base URLs
if [ -s "$urls_input" ]; then
    grep -oP 'https?://[^/]+' "$urls_input" | sort -u >> "$base_urls"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "https://${DOMAIN}" >> "$base_urls"
fi
sort -u -o "$base_urls" "$base_urls"

if [ ! -s "$base_urls" ]; then
    warn "No base URLs to test — skipping"
    exit 0
fi

base_count=$(count_lines "$base_urls")
log "Testing ${base_count} base URLs for content spoofing"

# ── Benign test payloads (no XSS — just HTML rendering detection) ──
# These are safe to inject: they don't execute scripts
CANARY="se_spoof_test_$(date +%s)"
HTML_PAYLOAD="<h1>${CANARY}</h1>"
HTML_ENCODED="%3Ch1%3E${CANARY}%3C%2Fh1%3E"
TEXT_PAYLOAD="${CANARY}"

tested=0
found=0

while IFS= read -r base_url; do
    [ -z "$base_url" ] && continue
    ((tested++)) || true

    # ── Test 1: 404 page reflection ──
    notfound_url="${base_url}/${CANARY}"
    body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$notfound_url" 2>/dev/null || true)
    if [ -n "$body" ] && echo "$body" | grep -q "$CANARY"; then
        # Check if Content-Type is HTML
        headers=$(curl -sk -D- -o /dev/null --max-time 8 "${HUNT_UA_CURL[@]}" "$notfound_url" 2>/dev/null || true)
        content_type=$(echo "$headers" | grep -i '^Content-Type:' | head -1)

        if echo "$content_type" | grep -qi 'text/html'; then
            # Now test with HTML payload
            html_url="${base_url}/${HTML_ENCODED}"
            html_body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$html_url" 2>/dev/null || true)

            if echo "$html_body" | grep -q "<h1>${CANARY}</h1>"; then
                ((found++)) || true
                echo "[P4:CONTENT_SPOOF:HTML_RENDERED] ${base_url}/INJECT | 404 page renders injected HTML | Content-Type: text/html" >> "$findings_file"
            else
                echo "[P5:CONTENT_SPOOF:TEXT_REFLECTED] ${base_url}/INJECT | 404 page reflects text (HTML escaped)" >> "$findings_file"
            fi
        fi
    fi

    # ── Test 2: Search/query parameter reflection ──
    for param in "q" "search" "query" "s" "keyword" "term" "error" "message" "msg"; do
        search_url="${base_url}/?${param}=${HTML_ENCODED}"
        body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$search_url" 2>/dev/null || true)
        [ -z "$body" ] && continue

        if echo "$body" | grep -q "<h1>${CANARY}</h1>"; then
            ((found++)) || true

            # Check CSP
            headers=$(curl -sk -D- -o /dev/null --max-time 8 "${HUNT_UA_CURL[@]}" "$search_url" 2>/dev/null || true)
            csp=$(echo "$headers" | grep -i '^Content-Security-Policy:' | head -1)
            csp_note=""
            if [ -n "$csp" ]; then
                csp_note="CSP_PRESENT"
            else
                csp_note="NO_CSP"
            fi

            echo "[P4:CONTENT_SPOOF:HTML_RENDERED] ${search_url} | param=${param} renders HTML | ${csp_note}" >> "$findings_file"
            break  # One param per base URL is enough
        elif echo "$body" | grep -q "$CANARY"; then
            # Text reflected but HTML escaped
            echo "[P5:CONTENT_SPOOF:TEXT_REFLECTED] ${search_url} | param=${param} reflects text (escaped)" >> "$findings_file"
            break
        fi
    done

    # ── Test 3: Error message parameter reflection ──
    for path in "error" "404" "not-found" "message"; do
        for param in "error" "message" "msg" "reason" "detail"; do
            err_url="${base_url}/${path}?${param}=${HTML_ENCODED}"
            body=$(curl -sk --max-time 10 "${HUNT_UA_CURL[@]}" "$err_url" 2>/dev/null || true)
            [ -z "$body" ] && continue

            if echo "$body" | grep -q "<h1>${CANARY}</h1>"; then
                ((found++)) || true
                echo "[P4:CONTENT_SPOOF:HTML_RENDERED] ${err_url} | error page renders HTML" >> "$findings_file"
                break 2
            fi
        done
    done

    [ $((tested % 5)) -eq 0 ] && info "Tested ${tested}/${base_count} base URLs (${found} found)..."
done < "$base_urls"

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
log "Tested: ${tested} base URLs"
log "Content spoofing findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "Content spoofing found:"
    grep "HTML_RENDERED" "$findings_file" || true
fi
