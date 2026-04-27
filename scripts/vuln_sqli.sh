#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  vuln_sqli.sh — SQL Injection Hunting                        ║
# ║  SQLMutant (primary) + ghauri fallback + sqlmap backend      ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="vuln_sqli.sh"
SCRIPT_DESC="SQL Injection Scanning"
MAX_SQLI_TARGETS="${MAX_SQLI_TARGETS:-20}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Hunt for SQL injection vulnerabilities."
    echo "  SQLMutant (BHEH) is primary, ghauri as fallback."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with parameterized URLs"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "SQLi" "$SCRIPT_DESC"

# Determine parameterized URLs
param_urls=""
if [ -f "${OUT_DIR}/parameterized_urls.txt" ] && [ -s "${OUT_DIR}/parameterized_urls.txt" ]; then
    param_urls="${OUT_DIR}/parameterized_urls.txt"
elif [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    grep '=' "$URLS_FILE" 2>/dev/null | sort -u > "${OUT_DIR}/parameterized_urls.txt"
    param_urls="${OUT_DIR}/parameterized_urls.txt"
fi

param_count=0
[ -n "$param_urls" ] && [ -f "$param_urls" ] && param_count=$(count_lines "$param_urls")

> "${OUT_DIR}/sqli_findings.txt"
mkdir -p "${OUT_DIR}/sqli"

used_sqlmutant=0

# ── SQLMutant (BHEH — primary) ──
if check_bheh "SQLMutant/SQLMutant.sh"; then
    info "Running SQLMutant (wayback→httpx→arjun→sqlmap pipeline)..."
    target="${DOMAIN:-}"
    if [ -z "$target" ] && [ -f "${param_urls:-}" ]; then
        target=$(head -1 "$param_urls" | sed 's|https\?://||;s|/.*||')
    fi

    if [ -n "$target" ]; then
        echo "$target" | bash "${BHEH_DIR}/SQLMutant/SQLMutant.sh" \
            > "${OUT_DIR}/sqlmutant_raw.txt" 2>/dev/null || true

        if [ -s "${OUT_DIR}/sqlmutant_raw.txt" ]; then
            sed 's/\x1b\[[0-9;]*m//g' "${OUT_DIR}/sqlmutant_raw.txt" | \
                grep -iP '(sqli|inject|vulnerable|payload|parameter|sqlmap)' \
                > "${OUT_DIR}/sqlmutant_findings.txt" 2>/dev/null || true
            cat "${OUT_DIR}/sqlmutant_findings.txt" >> "${OUT_DIR}/sqli_findings.txt" 2>/dev/null || true
            log "SQLMutant: $(count_lines "${OUT_DIR}/sqlmutant_findings.txt") findings"
            used_sqlmutant=1
        else
            warn "SQLMutant produced no output"
        fi
    fi
else
    warn "SQLMutant not installed"
fi

# ── Ghauri fallback (if SQLMutant didn't run or had no results) ──
if [ "$used_sqlmutant" -eq 0 ] && check_tool ghauri 2>/dev/null && [ "$param_count" -gt 0 ]; then
    info "Running ghauri (SQL injection, first ${MAX_SQLI_TARGETS} URLs)..."
    head -"${MAX_SQLI_TARGETS}" "$param_urls" | while read -r url; do
        hash=$(echo "$url" | md5sum | cut -c1-8)
        ghauri -u "$url" --batch --level 1 --risk 1 \
            --output-dir "${OUT_DIR}/sqli/${hash}" 2>/dev/null || true
    done

    ghauri_count=$(find "${OUT_DIR}/sqli" -name "*.txt" -size +0 2>/dev/null | wc -l || echo 0)
    log "Ghauri: ${ghauri_count} result files"

    # Consolidate ghauri findings
    find "${OUT_DIR}/sqli" -name "*.txt" -size +0 -exec grep -li "injectable\|vulnerable\|payload" {} \; 2>/dev/null | \
        while read -r f; do
            grep -i "injectable\|vulnerable\|payload" "$f" >> "${OUT_DIR}/sqli_findings.txt" 2>/dev/null || true
        done
elif [ "$used_sqlmutant" -eq 0 ] && [ "$param_count" -eq 0 ]; then
    warn "No parameterized URLs and no SQLMutant — skipping SQLi"
fi

# ── Deduplicate ──
sort -u -o "${OUT_DIR}/sqli_findings.txt" "${OUT_DIR}/sqli_findings.txt"
log "Total SQLi findings: $(count_lines "${OUT_DIR}/sqli_findings.txt")"
log "SQLi results: ${OUT_DIR}/sqli_findings.txt"
