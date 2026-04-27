#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  jwt_attack.sh — JWT Token Extraction & Attack Wrapper       ║
# ║  Extracts JWTs from hunt data, feeds to jwt_analyze.py       ║
# ║  VRT: Authentication Bypass (P1-P2)                          ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="jwt_attack.sh"
SCRIPT_DESC="JWT Token Extraction & Attack"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Extract JWTs from JS files, URLs, and responses, then analyze"
    echo "  for alg:none, weak HMAC secrets, RS256->HS256 confusion, etc."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan for JWTs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --dry-run              Show extracted JWTs without attacking"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"

DRY_RUN=false
PASSTHROUGH_ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        DRY_RUN=true
    else
        PASSTHROUGH_ARGS+=("$arg")
    fi
done
parse_common_args "${PASSTHROUGH_ARGS[@]}"

phase_header "JWT" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/jwt_findings.txt"
jwt_tokens_file="${OUT_DIR}/extracted_jwts.txt"
jwt_context_file="${OUT_DIR}/jwt_context.txt"
> "$findings_file"
> "$jwt_tokens_file"
> "$jwt_context_file"

# ── JWT extraction regex ──
# Matches: eyJ<base64>.<base64>.<base64> (3-part JWTs)
JWT_REGEX='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'

# ── Extract JWTs from JS files ──
extract_from_js() {
    local js_dir="${OUT_DIR}/js_downloads"
    local js_list="${OUT_DIR}/js_files.txt"

    if [ -d "$js_dir" ] && [ "$(ls -A "$js_dir" 2>/dev/null)" ]; then
        info "Scanning downloaded JS files for JWTs..."
        local js_count=0
        for jsfile in "$js_dir"/*; do
            [ -f "$jsfile" ] || continue
            while IFS= read -r token; do
                echo "$token" >> "$jwt_tokens_file"
                echo "JS_FILE:$(basename "$jsfile"):${token}" >> "$jwt_context_file"
                ((js_count++)) || true
            done < <(grep -oP "$JWT_REGEX" "$jsfile" 2>/dev/null || true)
        done
        log "Extracted ${js_count} JWT(s) from JS files"
    elif [ -f "$js_list" ]; then
        info "Scanning JS URLs for JWTs (inline extraction)..."
        local js_count=0
        while IFS= read -r js_url; do
            [ -z "$js_url" ] && continue
            local body
            body=$(curl -sk --max-time 10 "$js_url" 2>/dev/null || true)
            [ -z "$body" ] && continue
            while IFS= read -r token; do
                echo "$token" >> "$jwt_tokens_file"
                echo "JS_URL:${js_url}:${token}" >> "$jwt_context_file"
                ((js_count++)) || true
            done < <(echo "$body" | grep -oP "$JWT_REGEX" || true)
        done < <(head -100 "$js_list")
        log "Extracted ${js_count} JWT(s) from JS URLs"
    fi
}

# ── Extract JWTs from URL parameters ──
extract_from_urls() {
    local urls_file="${URLS_FILE:-${OUT_DIR}/all_urls.txt}"
    [ ! -f "$urls_file" ] && return

    info "Scanning URLs for JWT parameters..."
    local url_count=0
    while IFS= read -r token; do
        echo "$token" >> "$jwt_tokens_file"
        echo "URL_PARAM:${token}" >> "$jwt_context_file"
        ((url_count++)) || true
    done < <(grep -oP "$JWT_REGEX" "$urls_file" 2>/dev/null || true)
    log "Extracted ${url_count} JWT(s) from URL parameters"
}

# ── Extract JWTs from response files ──
extract_from_responses() {
    local resp_dir="${OUT_DIR}/responses"
    [ ! -d "$resp_dir" ] && return

    info "Scanning response files for JWTs..."
    local resp_count=0
    for rfile in "$resp_dir"/*; do
        [ -f "$rfile" ] || continue
        while IFS= read -r token; do
            echo "$token" >> "$jwt_tokens_file"
            echo "RESPONSE:$(basename "$rfile"):${token}" >> "$jwt_context_file"
            ((resp_count++)) || true
        done < <(grep -oP "$JWT_REGEX" "$rfile" 2>/dev/null || true)
    done
    log "Extracted ${resp_count} JWT(s) from response files"
}

# ── Extract JWTs from nuclei/secrets findings ──
extract_from_findings() {
    info "Scanning existing findings for JWTs..."
    local find_count=0
    for ff in secrets_findings.txt nuclei_findings.txt misc_findings.txt; do
        local fpath="${OUT_DIR}/${ff}"
        [ ! -f "$fpath" ] && continue
        while IFS= read -r token; do
            echo "$token" >> "$jwt_tokens_file"
            echo "FINDING:${ff}:${token}" >> "$jwt_context_file"
            ((find_count++)) || true
        done < <(grep -oP "$JWT_REGEX" "$fpath" 2>/dev/null || true)
    done
    log "Extracted ${find_count} JWT(s) from finding files"
}

# ── Main extraction ──
extract_from_js
extract_from_urls
extract_from_responses
extract_from_findings

# Deduplicate tokens
if [ -s "$jwt_tokens_file" ]; then
    sort -u "$jwt_tokens_file" -o "$jwt_tokens_file"
fi

total=$(count_lines "$jwt_tokens_file")
log "Total unique JWTs extracted: ${total}"

if [ "$total" -eq 0 ]; then
    warn "No JWT tokens found — skipping analysis"
    exit 0
fi

if $DRY_RUN; then
    info "[DRY-RUN] Extracted JWTs:"
    cat "$jwt_tokens_file"
    info "[DRY-RUN] Context:"
    cat "$jwt_context_file"
    exit 0
fi

# ── Run Python analyzer ──
ANALYZER="${LIB_DIR}/scripts/jwt_analyze.py"
if [ ! -f "$ANALYZER" ]; then
    err "jwt_analyze.py not found at ${ANALYZER}"
    exit 1
fi

info "Running JWT analysis on ${total} token(s)..."
python3 "$ANALYZER" \
    -i "$jwt_tokens_file" \
    -o "$findings_file" \
    -t "$THREADS" \
    --context "$jwt_context_file" \
    || { err "jwt_analyze.py failed"; exit 1; }

# ── Optional: jwt_tool extended attacks ──
if check_tool jwt_tool 2>/dev/null; then
    info "Running jwt_tool for extended attacks..."
    while IFS= read -r token; do
        [ -z "$token" ] && continue
        jwt_tool "$token" -M at -t "https://example.com" \
            >> "${OUT_DIR}/jwt_tool_results.txt" 2>/dev/null || true
    done < <(head -10 "$jwt_tokens_file")
else
    info "jwt_tool not installed — skipping extended attacks (install: sudo pacman -S jwt-tool)"
fi

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "JWT analysis complete: ${total} tokens analyzed, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "JWT vulnerabilities found:"
    cat "$findings_file"
fi
