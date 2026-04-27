#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  nextjs_poison.sh — Next.js Internal Cache Poisoning Scanner ║
# ║  CVE-2024-46982: SSR→SSG cache poison on Next.js <14.2.10   ║
# ║  VRT: Server Security Misconfiguration > Cache Poison (P1)   ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="nextjs_poison.sh"
SCRIPT_DESC="Next.js Internal Cache Poisoning Scanner (CVE-2024-46982)"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Identify Next.js targets and test for internal cache poisoning"
    echo "  via __nextDataReq, x-now-route-matches, purpose:prefetch,"
    echo "  middleware bypass, RSC, and locale manipulation."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 10)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "NEXTJS_POISON" "$SCRIPT_DESC"

findings_file="${OUT_DIR}/nextjs_poison_findings.txt"
targets_file="${OUT_DIR}/nextjs_poison_targets.txt"
> "$findings_file"
> "$targets_file"

# ── Identify Next.js targets ──
info "Identifying Next.js targets..."

urls_input="${URLS_FILE:-${OUT_DIR}/urls.txt}"

if [ ! -f "$urls_input" ]; then
    err "Provide --urls or ensure ${OUT_DIR}/urls.txt exists"
    script_usage
    exit 1
fi

# Method 1: grep for _next/ references in URL list
grep -i '_next/' "$urls_input" 2>/dev/null \
    | sed -E 's|(https?://[^/]+).*|\1|' | sort -u >> "$targets_file" || true

# Method 2: probe each unique base URL for Next.js indicators
info "Probing base URLs for Next.js signatures (x-powered-by / __NEXT_DATA__)..."
sed -E 's|(https?://[^/]+).*|\1|' "$urls_input" | sort -u | while read -r base; do
    # Skip if already identified from _next/ grep
    grep -qxF "$base" "$targets_file" 2>/dev/null && continue
    # Check response headers + body
    resp_headers=$(curl -sk -D - -o /dev/null \
        -H "User-Agent: ${HUNT_UA:-noleak}" "$base" 2>/dev/null | head -30)
    if echo "$resp_headers" | grep -qi 'x-powered-by:.*Next\.js'; then
        echo "$base" >> "$targets_file"
        continue
    fi
    resp_body=$(curl -sk -H "User-Agent: ${HUNT_UA:-noleak}" "$base" 2>/dev/null | head -200)
    if echo "$resp_body" | grep -q '__NEXT_DATA__'; then
        echo "$base" >> "$targets_file"
    fi
done

# Deduplicate
sort -u -o "$targets_file" "$targets_file"
total=$(count_lines "$targets_file")
log "Identified ${total} Next.js target(s)"

if [ "$total" -eq 0 ]; then
    warn "No Next.js targets found — skipping cache poisoning tests"
    log "Next.js cache poisoning findings: 0"
    exit 0
fi

# ── Run Python scanner ──
SCANNER="${LIB_DIR}/scripts/nextjs_poison.py"
if [ ! -f "$SCANNER" ]; then
    err "nextjs_poison.py not found at ${SCANNER}"
    exit 1
fi

py_args=(
    -i "$targets_file"
    -o "$findings_file"
    -t "${THREADS}"
    --timeout 10
)

if [ -n "${HUNT_UA:-}" ]; then
    py_args+=(--user-agent "${HUNT_UA}")
fi

info "Running Next.js cache poison tests on ${total} target(s)..."
python3 "$SCANNER" "${py_args[@]}" \
    || { err "nextjs_poison.py failed"; exit 1; }

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Next.js cache poison scan complete: ${total} targets tested, ${finding_count} finding(s)"

if [ "$finding_count" -gt 0 ]; then
    warn "Next.js cache poisoning findings detected:"
    cat "$findings_file"
    log "Results: ${findings_file}"
fi
