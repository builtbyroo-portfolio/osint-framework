#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  h2c_smuggle.sh — HTTP/2 CONNECT & h2c Smuggling Scanner    ║
# ║  Detect h2c upgrade, CONNECT tunneling, proxy ACL bypass     ║
# ║  VRT: Server Security Misconfiguration > H2C Smuggling (P1)  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="h2c_smuggle.sh"
SCRIPT_DESC="HTTP/2 CONNECT & h2c Smuggling Scanner"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Detect h2c cleartext upgrade acceptance, CONNECT method"
    echo "  tunneling, and proxy ACL bypass via HTTP/2 smuggling."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with target URLs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 10)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "H2C_SMUGGLE" "$SCRIPT_DESC"

# ── Determine input ──
urls_input="${URLS_FILE:-${OUT_DIR}/live_hosts.txt}"

if [ ! -f "$urls_input" ]; then
    urls_input="${OUT_DIR}/urls.txt"
fi

if [ ! -f "$urls_input" ]; then
    err "Provide --urls or ensure ${OUT_DIR}/live_hosts.txt exists"
    script_usage
    exit 1
fi

# ── Extract unique base URLs ──
info "Extracting unique base URLs from input..."
all_targets="${OUT_DIR}/h2c_all_targets.txt"
proxy_targets="${OUT_DIR}/h2c_proxy_targets.txt"
> "$all_targets"
> "$proxy_targets"

while IFS= read -r url; do
    [[ -z "$url" || ! "$url" =~ ^https?:// ]] && continue
    echo "$url" | grep -oP '^https?://[^/]+'
done < "$urls_input" | sort -u > "$all_targets"

total=$(count_lines "$all_targets")
info "Unique base targets: ${total}"

if [ "$total" -eq 0 ]; then
    warn "No targets found — skipping h2c smuggling scan"
    exit 0
fi

# ── Identify proxy-fronted targets via response headers ──
info "Probing targets for reverse proxy indicators..."
proxy_count=0
while IFS= read -r base_url; do
    headers=$(curl -sk -o /dev/null -D - --max-time 5 \
        ${HUNT_UA_CURL[@]+"${HUNT_UA_CURL[@]}"} \
        "$base_url" 2>/dev/null | head -40)

    if echo "$headers" | grep -qiP \
        '(^via:\s|^x-forwarded-for:\s|^x-forwarded-host:\s|^x-varnish:\s|^cf-ray:\s|^server:\s*(nginx|haproxy|envoy|traefik|apache)\b)'; then
        echo "$base_url" >> "$proxy_targets"
        proxy_count=$((proxy_count + 1))
    fi
done < "$all_targets"

info "Proxy-fronted targets: ${proxy_count} / ${total}"
info "Testing ALL ${total} targets (h2c can work without obvious proxy headers)"

# ── Build python args ──
py_args=(
    -i "$all_targets"
    -o "${OUT_DIR}/h2c_findings.txt"
    -t "${THREADS}"
    --timeout 10
)

if [ -n "${HUNT_UA:-}" ]; then
    py_args+=(--user-agent "${HUNT_UA}")
fi

if [ -s "$proxy_targets" ]; then
    py_args+=(--proxy-targets "$proxy_targets")
fi

# ── Run Python scanner ──
SCANNER="${LIB_DIR}/scripts/h2c_smuggle.py"
if [ ! -f "$SCANNER" ]; then
    err "h2c_smuggle.py not found at ${SCANNER}"
    exit 1
fi

info "Running h2c smuggling scan on ${total} target(s)..."
python3 "$SCANNER" "${py_args[@]}"

findings_count=$(count_lines "${OUT_DIR}/h2c_findings.txt")
log "h2c smuggling scan complete: ${total} targets tested, ${findings_count} finding(s)"

if [ "$findings_count" -gt 0 ]; then
    warn "h2c smuggling findings detected:"
    cat "${OUT_DIR}/h2c_findings.txt"
    log "Results: ${OUT_DIR}/h2c_findings.txt"
fi
