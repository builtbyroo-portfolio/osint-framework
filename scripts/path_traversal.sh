#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  path_traversal.sh — Path Traversal / LFI Scanner            ║
# ║  20+ encoding variants to bypass input filters               ║
# ║  VRT: Server-Side Injection > File Inclusion (P1)             ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="path_traversal.sh"
SCRIPT_DESC="Path Traversal / LFI Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test file-like parameters for path traversal using 20+"
    echo "  encoding variants (URL, double, overlong UTF-8, null byte,"
    echo "  Java semicolons, PHP wrappers, Windows backslashes)."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --dry-run              Show targets without testing"
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

phase_header "LFI" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/path_traversal_findings.txt"
targets_file="${OUT_DIR}/path_traversal_targets.txt"
> "$findings_file"
> "$targets_file"

# ── Extract URLs with file-like parameters ──
info "Identifying path traversal targets from parameterized URLs..."

urls_input="${URLS_FILE:-${OUT_DIR}/all_urls.txt}"
FILE_PARAMS='[?&](file|path|doc|template|page|include|dir|img|image|attachment|download|load|read|content|folder|src|source|filename|filepath|name)='

if [ -f "$urls_input" ]; then
    grep -iP "$FILE_PARAMS" "$urls_input" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/urls.txt" ]; then
    grep -iP "$FILE_PARAMS" "${OUT_DIR}/urls.txt" >> "$targets_file" 2>/dev/null || true
fi
if [ -f "${OUT_DIR}/parameterized_urls.txt" ]; then
    grep -iP "$FILE_PARAMS" "${OUT_DIR}/parameterized_urls.txt" >> "$targets_file" 2>/dev/null || true
fi

# Deduplicate by base URL + param name
if [ -s "$targets_file" ]; then
    awk -F'[?&]' '{
        base=$1; param="";
        for(i=2;i<=NF;i++){
            split($i,kv,"=");
            k=tolower(kv[1]);
            if(k~/^(file|path|doc|template|page|include|dir|img|image|attachment|download|load|read|content|folder|src|source|filename|filepath|name)$/)
                param=k
        }
        key=base"|"param;
        if(!seen[key]++){print}
    }' "$targets_file" > "${targets_file}.dedup"
    mv "${targets_file}.dedup" "$targets_file"
fi

total=$(count_lines "$targets_file")
log "Identified ${total} URL(s) with file-like parameters"

if [ "$total" -eq 0 ]; then
    warn "No file-like parameters found — skipping path traversal testing"
    exit 0
fi

if $DRY_RUN; then
    info "[DRY-RUN] Targets to test:"
    cat "$targets_file"
    exit 0
fi

# ── Run Python scanner ──
SCANNER="${LIB_DIR}/scripts/path_traversal.py"
if [ ! -f "$SCANNER" ]; then
    err "path_traversal.py not found at ${SCANNER}"
    exit 1
fi

EXTRA_ARGS=()
if [ -n "${HUNT_UA:-}" ]; then
    EXTRA_ARGS+=(--user-agent "$HUNT_UA")
fi

info "Running path traversal tests on ${total} URL(s)..."
python3 "$SCANNER" \
    -i "$targets_file" \
    -o "$findings_file" \
    -t "$THREADS" \
    "${EXTRA_ARGS[@]}" \
    || { err "path_traversal.py failed"; exit 1; }

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Path traversal scan complete: ${total} URLs tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Path traversal findings detected:"
    cat "$findings_file"
fi
