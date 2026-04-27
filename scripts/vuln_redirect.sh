#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  vuln_redirect.sh — Open Redirect Hunting                   ║
# ║  Parameter extraction + redirect probing                    ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="vuln_redirect.sh"
SCRIPT_DESC="Open Redirect Scanning"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Hunt for open redirect vulnerabilities."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with URLs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "REDIRECT" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

> "${OUT_DIR}/redirect_findings.txt"

# ── Redirect parameter extraction + probing ──
# Prefer parameterized URLs over base URL list for parameter scanning
if [ -s "${OUT_DIR}/parameterized_urls.txt" ]; then
    urls_input="${OUT_DIR}/parameterized_urls.txt"
elif [ -s "${OUT_DIR}/all_urls.txt" ]; then
    urls_input="${OUT_DIR}/all_urls.txt"
else
    urls_input="${URLS_FILE:-}"
fi
if [ -n "${urls_input:-}" ] && [ -f "$urls_input" ]; then
    info "Checking for redirect-prone parameters..."

    # Common redirect parameter names
    grep -iP '(redirect=|url=|next=|rurl=|dest=|destination=|redir=|redirect_uri=|redirect_url=|return=|return_to=|returnTo=|go=|goto=|target=|link=|linkurl=|logout=|out=|checkout_url=|continue=|view=|image_url=|r=|callback=|forward=)' \
        "$urls_input" 2>/dev/null | sort -u > "${OUT_DIR}/redirect_candidates.txt" || true

    candidate_count=$(count_lines "${OUT_DIR}/redirect_candidates.txt")
    if [ "$candidate_count" -gt 0 ]; then
        log "Redirect candidate URLs: ${candidate_count}"

        info "Testing top redirect candidates..."
        head -30 "${OUT_DIR}/redirect_candidates.txt" | while IFS= read -r url; do
            # Replace redirect param value with external domain
            test_url=$(echo "$url" | sed -E 's/(redirect|url|next|dest|redir|return|goto|callback|forward|continue)=[^&]*/\1=https:\/\/evil.com/')
            # Check if it actually redirects
            location=$(curl -sk -o /dev/null -w "%{redirect_url}" --max-time 5 -L --max-redirs 1 "$test_url" 2>/dev/null || echo "")
            if echo "$location" | grep -qi "evil.com"; then
                echo "OPEN_REDIRECT ${test_url} -> ${location}" >> "${OUT_DIR}/redirect_findings.txt"
            fi
        done
    else
        warn "No redirect-prone parameters found"
    fi
else
    warn "No URL file available for redirect parameter scanning"
fi

sort -u -o "${OUT_DIR}/redirect_findings.txt" "${OUT_DIR}/redirect_findings.txt"
log "Total redirect findings: $(count_lines "${OUT_DIR}/redirect_findings.txt")"
log "Redirect results: ${OUT_DIR}/redirect_findings.txt"
