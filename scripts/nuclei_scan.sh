#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  nuclei_scan.sh — Nuclei Vulnerability Scanning              ║
# ║  Standard nuclei + Nucleimonst3r hail-mary option            ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="nuclei_scan.sh"
SCRIPT_DESC="Nuclei Vulnerability Scanning"
HAILMARY="${HAILMARY:-0}"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Run nuclei scans against target URLs."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with URLs to scan"
    echo "  -d, --domain DOMAIN    Single target domain"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --hailmary             Enable Nucleimonst3r hail-mary mode (aggressive)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "NUCLEI" "$SCRIPT_DESC"

# Determine input
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    scan_list="$URLS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    echo "https://${DOMAIN}" > "${OUT_DIR}/_nuclei_targets.txt"
    scan_list="${OUT_DIR}/_nuclei_targets.txt"
else
    err "Provide --urls or --domain"
    script_usage
    exit 1
fi

if [ ! -d "${NUCLEI_TEMPLATES}" ]; then
    warn "Nuclei templates not found at ${NUCLEI_TEMPLATES}, updating..."
    nuclei -update-templates 2>/dev/null || true
fi

# ── Critical + High ──
info "Nuclei scan: critical + high severity..."
nuclei -l "$scan_list" -severity critical,high \
    "${HUNT_UA_ARGS[@]}" \
    -t "${NUCLEI_TEMPLATES}/" -c "${THREADS}" -silent \
    -o "${OUT_DIR}/nuclei_critical_high.txt" 2>/dev/null || true
log "Critical+High: $(count_lines "${OUT_DIR}/nuclei_critical_high.txt") findings"

# ── Medium ──
info "Nuclei scan: medium severity..."
nuclei -l "$scan_list" -severity medium \
    "${HUNT_UA_ARGS[@]}" \
    -t "${NUCLEI_TEMPLATES}/" -c "${THREADS}" -silent \
    -o "${OUT_DIR}/nuclei_medium.txt" 2>/dev/null || true
log "Medium: $(count_lines "${OUT_DIR}/nuclei_medium.txt") findings"

# ── Exposures + Misconfigs ──
info "Nuclei scan: exposures + misconfigs..."
nuclei -l "$scan_list" \
    "${HUNT_UA_ARGS[@]}" \
    -t "${NUCLEI_TEMPLATES}/http/exposures/" \
    -t "${NUCLEI_TEMPLATES}/http/misconfiguration/" \
    -t "${NUCLEI_TEMPLATES}/http/vulnerabilities/" \
    -c "${THREADS}" -silent \
    -o "${OUT_DIR}/nuclei_exposures.txt" 2>/dev/null || true
log "Exposures/Misconfigs: $(count_lines "${OUT_DIR}/nuclei_exposures.txt") findings"

# ── All URLs scan (if all_urls.txt exists) ──
if [ -f "${OUT_DIR}/all_urls.txt" ] && [ -s "${OUT_DIR}/all_urls.txt" ]; then
    info "Nuclei scan: all discovered URLs..."
    nuclei -l "${OUT_DIR}/all_urls.txt" -severity critical,high,medium \
        "${HUNT_UA_ARGS[@]}" \
        -t "${NUCLEI_TEMPLATES}/" -c "${THREADS}" -silent \
        -o "${OUT_DIR}/nuclei_all_urls.txt" 2>/dev/null || true
    log "All URLs scan: $(count_lines "${OUT_DIR}/nuclei_all_urls.txt") findings"
fi

# ── Subdomain Takeover ──
if [ -f "${OUT_DIR}/subdomains.txt" ] && [ -s "${OUT_DIR}/subdomains.txt" ]; then
    info "Nuclei scan: subdomain takeover (74 fingerprints)..."
    # Takeover templates check CNAME → service-specific error pages
    nuclei -l "${OUT_DIR}/subdomains.txt" \
        "${HUNT_UA_ARGS[@]}" \
        -t "${NUCLEI_TEMPLATES}/http/takeovers/" \
        -c "${THREADS}" -silent \
        -o "${OUT_DIR}/nuclei_takeover.txt" 2>/dev/null || true
    takeover_count=$(count_lines "${OUT_DIR}/nuclei_takeover.txt")
    log "Subdomain takeover: ${takeover_count} findings"
    if [ "$takeover_count" -gt 0 ]; then
        warn "SUBDOMAIN TAKEOVER DETECTED — high-value finding!"
        cat "${OUT_DIR}/nuclei_takeover.txt" >> "${OUT_DIR}/nuclei_findings.txt"
    fi
fi

# ── DNS Checks (dangling CNAME, zone transfer) ──
if [ -f "${OUT_DIR}/subdomains.txt" ] && [ -s "${OUT_DIR}/subdomains.txt" ]; then
    info "Nuclei scan: DNS checks (dangling CNAME, DMARC, etc.)..."
    nuclei -l "${OUT_DIR}/subdomains.txt" \
        "${HUNT_UA_ARGS[@]}" \
        -t "${NUCLEI_TEMPLATES}/dns/" \
        -c "${THREADS}" -silent \
        -o "${OUT_DIR}/nuclei_dns.txt" 2>/dev/null || true
    log "DNS checks: $(count_lines "${OUT_DIR}/nuclei_dns.txt") findings"
fi

# ── CORS Misconfiguration ──
info "Nuclei scan: CORS misconfiguration..."
nuclei -l "$scan_list" \
    "${HUNT_UA_ARGS[@]}" \
    -t "${NUCLEI_TEMPLATES}/http/vulnerabilities/generic/cors-misconfig.yaml" \
    -c "${THREADS}" -silent \
    -o "${OUT_DIR}/nuclei_cors.txt" 2>/dev/null || true
cors_count=$(count_lines "${OUT_DIR}/nuclei_cors.txt")
log "CORS misconfiguration: ${cors_count} findings"
if [ "$cors_count" -gt 0 ]; then
    cat "${OUT_DIR}/nuclei_cors.txt" >> "${OUT_DIR}/nuclei_findings.txt"
fi

# ── Technology-specific panels + misconfigs ──
info "Nuclei scan: exposed panels + default logins..."
nuclei -l "$scan_list" \
    "${HUNT_UA_ARGS[@]}" \
    -t "${NUCLEI_TEMPLATES}/http/exposed-panels/" \
    -t "${NUCLEI_TEMPLATES}/http/default-logins/" \
    -c "${THREADS}" -silent \
    -o "${OUT_DIR}/nuclei_panels.txt" 2>/dev/null || true
log "Exposed panels: $(count_lines "${OUT_DIR}/nuclei_panels.txt") findings"

# ── Custom Templates (high-value, hand-written for cashflow VRT) ──
CUSTOM_TEMPLATES="${NUCLEI_TEMPLATES}/custom"
if [ -d "$CUSTOM_TEMPLATES" ] && [ "$(find "$CUSTOM_TEMPLATES" -name '*.yaml' 2>/dev/null | wc -l)" -gt 0 ]; then
    info "Nuclei scan: custom templates (cashflow VRT)..."
    nuclei -l "$scan_list" \
        "${HUNT_UA_ARGS[@]}" \
        -t "$CUSTOM_TEMPLATES/" \
        -c "${THREADS}" -silent \
        -o "${OUT_DIR}/nuclei_custom.txt" 2>/dev/null || true
    custom_count=$(count_lines "${OUT_DIR}/nuclei_custom.txt")
    log "Custom template findings: ${custom_count}"
    if [ "$custom_count" -gt 0 ]; then
        warn "CUSTOM TEMPLATE HIT — high-confidence finding!"
    fi
fi

# ── GraphQL Security Audit (graphql-cop) ──
GRAPHQL_COP="${HOME}/tools/graphql-cop/graphql-cop.py"
if [ -f "$GRAPHQL_COP" ] && [ -s "$scan_list" ]; then
    info "Running graphql-cop on discovered GraphQL endpoints..."
    > "${OUT_DIR}/graphql_audit.txt"
    # Find GraphQL endpoints from URLs
    graphql_targets=$(grep -iP '(graphql|gql|api)' "$scan_list" 2>/dev/null | head -20)
    if [ -n "$graphql_targets" ]; then
        while read -r gql_url; do
            [ -z "$gql_url" ] && continue
            python3 "$GRAPHQL_COP" -t "$gql_url" 2>/dev/null >> "${OUT_DIR}/graphql_audit.txt" || true
        done <<< "$graphql_targets"
        gql_count=$(grep -c "FOUND" "${OUT_DIR}/graphql_audit.txt" 2>/dev/null || echo 0)
        log "GraphQL audit findings: ${gql_count}"
    fi
fi

# ── Consolidate ──
cat "${OUT_DIR}"/nuclei_critical_high.txt "${OUT_DIR}"/nuclei_medium.txt \
    "${OUT_DIR}"/nuclei_exposures.txt "${OUT_DIR}"/nuclei_all_urls.txt \
    2>/dev/null | sort -u > "${OUT_DIR}/nuclei_findings.txt"
log "Total nuclei findings: $(count_lines "${OUT_DIR}/nuclei_findings.txt")"

# ── Nucleimonst3r hail-mary (optional) ──
if [ "${HAILMARY}" -eq 1 ]; then
    if check_bheh "Nucleimonst3r/Nucleimonst3r.sh"; then
        info "Running Nucleimonst3r HAIL-MARY mode (aggressive, all templates)..."
        warn "This will take a long time — scanning with maximum template coverage"

        target_domain="${DOMAIN:-}"
        if [ -z "$target_domain" ] && [ -f "$scan_list" ]; then
            target_domain=$(head -1 "$scan_list" | sed 's|https\?://||;s|/.*||')
        fi

        if [ -n "$target_domain" ]; then
            echo "$target_domain" | bash "${BHEH_DIR}/Nucleimonst3r/Nucleimonst3r.sh" \
                > "${OUT_DIR}/nucleimonst3r_raw.txt" 2>/dev/null || true

            if [ -s "${OUT_DIR}/nucleimonst3r_raw.txt" ]; then
                # Strip ANSI codes and extract findings
                sed 's/\x1b\[[0-9;]*m//g' "${OUT_DIR}/nucleimonst3r_raw.txt" | \
                    grep -iP '\[(critical|high|medium|low|info)\]' \
                    >> "${OUT_DIR}/nuclei_findings.txt" 2>/dev/null || true
                log "Nucleimonst3r: added findings to nuclei_findings.txt"
            fi
        fi
    else
        warn "Nucleimonst3r not installed — skipping hail-mary"
    fi
fi

log "Nuclei results: ${OUT_DIR}/nuclei_findings.txt"
