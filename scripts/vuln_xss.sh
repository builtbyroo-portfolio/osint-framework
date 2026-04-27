#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  vuln_xss.sh — XSS Hunting                                  ║
# ║  Dalfox + FormPoison                                          ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="vuln_xss.sh"
SCRIPT_DESC="XSS Vulnerability Scanning"
MAX_PARAMS="${MAX_PARAMS:-150}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Hunt for XSS vulnerabilities using dalfox, FormPoison, XSSRocket."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs (parameterized preferred)"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "XSS" "$SCRIPT_DESC"

# Determine input URLs (prefer parameterized)
param_urls=""
if [ -f "${OUT_DIR}/parameterized_urls.txt" ] && [ -s "${OUT_DIR}/parameterized_urls.txt" ]; then
    param_urls="${OUT_DIR}/parameterized_urls.txt"
elif [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    grep '=' "$URLS_FILE" 2>/dev/null | sort -u > "${OUT_DIR}/parameterized_urls.txt"
    param_urls="${OUT_DIR}/parameterized_urls.txt"
fi

param_count=0
[ -n "$param_urls" ] && [ -f "$param_urls" ] && param_count=$(count_lines "$param_urls")

# Check for WAF evasion flag
waf_flag=""
[ -f "${OUT_DIR}/.waf_evasion" ] && waf_flag="--waf-evasion"

> "${OUT_DIR}/xss_findings.txt"

# ── Dalfox ──
if [ "$param_count" -gt 0 ]; then
    info "Running dalfox on ${param_count} parameterized URLs (max ${MAX_PARAMS})..."
    head -"${MAX_PARAMS}" "$param_urls" | dalfox pipe \
        --silence --no-color --skip-bav ${waf_flag} \
        "${HUNT_UA_DALFOX[@]}" \
        -w "${THREADS}" \
        -o "${OUT_DIR}/dalfox_xss.txt" 2>/dev/null || true
    log "Dalfox XSS findings: $(count_lines "${OUT_DIR}/dalfox_xss.txt")"

    # Add dalfox findings to consolidated output
    cat "${OUT_DIR}/dalfox_xss.txt" >> "${OUT_DIR}/xss_findings.txt" 2>/dev/null || true
else
    warn "No parameterized URLs found — skipping dalfox"
fi

# ── FormPoison (BHEH) ──
if check_bheh "FormPoison/formpoison.py"; then
    urls_input="${URLS_FILE:-${OUT_DIR}/urls.txt}"
    if [ -f "$urls_input" ]; then
        info "Running FormPoison (form-focused injection testing)..."
        mkdir -p "${OUT_DIR}/formpoison"
        while IFS= read -r url; do
            host=$(echo "$url" | sed 's|https\?://||;s|/.*||;s|:|-|g')
            python3 "${BHEH_DIR}/FormPoison/formpoison.py" "$url" \
                2>/dev/null > "${OUT_DIR}/formpoison/${host}.txt" || true
        done < <(head -15 "$urls_input")

        fp_count=$(cat "${OUT_DIR}"/formpoison/*.txt 2>/dev/null | grep -ci "vuln\|inject\|xss\|sqli" || echo 0)
        log "FormPoison: ${fp_count} potential injection points"

        if [ "$fp_count" -gt 0 ]; then
            echo "# --- FormPoison findings ---" >> "${OUT_DIR}/xss_findings.txt"
            grep -hi "vuln\|inject\|xss\|sqli" "${OUT_DIR}"/formpoison/*.txt \
                >> "${OUT_DIR}/xss_findings.txt" 2>/dev/null || true
        fi
    fi
else
    warn "FormPoison not installed — skipping form injection testing"
fi

# ── Deduplicate ──
sort -u -o "${OUT_DIR}/xss_findings.txt" "${OUT_DIR}/xss_findings.txt"
log "Total XSS findings: $(count_lines "${OUT_DIR}/xss_findings.txt")"
log "XSS results: ${OUT_DIR}/xss_findings.txt"
