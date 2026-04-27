#!/usr/bin/env bash
# supplement.sh — Bolt new pipeline tools onto completed old-pipeline hunts
# Runs: alterx → dnsx → xnLinkFinder → custom nuclei → graphql-cop
# Usage: ./supplement.sh <hunt_dir>
# Example: ./supplement.sh ./hunts/Comcast_Xfinity_20260304_220210

set -euo pipefail

HUNT_DIR="${1:?Usage: ./supplement.sh <hunt_dir>}"
HUNT_DIR="$(realpath "$HUNT_DIR")"

if [ ! -d "$HUNT_DIR" ]; then
    echo "[ERROR] Hunt directory not found: $HUNT_DIR"
    exit 1
fi

NUCLEI_CUSTOM="${HOME}/nuclei-templates/custom"
GRAPHQL_COP="${HOME}/tools/graphql-cop/graphql-cop.py"
THREADS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="${HUNT_DIR}/supplement_${TIMESTAMP}.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

log "Supplement pass started on: $HUNT_DIR"

# --- Phase 1: alterx subdomain permutation ---
if command -v alterx &>/dev/null && [ -s "${HUNT_DIR}/subdomains.txt" ]; then
    log "Phase 1/5: alterx (subdomain permutation)"
    cat "${HUNT_DIR}/subdomains.txt" | alterx -silent 2>/dev/null | sort -u > "${HUNT_DIR}/subdomains_permuted.txt"
    PERM_COUNT=$(wc -l < "${HUNT_DIR}/subdomains_permuted.txt")
    log "  Generated ${PERM_COUNT} permutations"
else
    log "Phase 1/5: SKIP (alterx not found or no subdomains.txt)"
fi

# --- Phase 2: dnsx resolve permutations + wildcard filter ---
if command -v dnsx &>/dev/null && [ -s "${HUNT_DIR}/subdomains_permuted.txt" ]; then
    log "Phase 2/5: dnsx (resolve permutations + wildcard filter)"
    cat "${HUNT_DIR}/subdomains.txt" "${HUNT_DIR}/subdomains_permuted.txt" 2>/dev/null | \
        sort -u | dnsx -silent -a -resp -wd -t ${THREADS} 2>/dev/null | \
        awk '{print $1}' | sort -u > "${HUNT_DIR}/subdomains_new.txt"
    NEW_COUNT=$(comm -13 <(sort "${HUNT_DIR}/subdomains.txt") <(sort "${HUNT_DIR}/subdomains_new.txt") | wc -l)
    log "  Resolved $(wc -l < "${HUNT_DIR}/subdomains_new.txt") total, ${NEW_COUNT} NEW subdomains"

    # Probe new subdomains with httpx
    if command -v httpx &>/dev/null && [ "$NEW_COUNT" -gt 0 ]; then
        log "  Probing new subdomains with httpx..."
        comm -13 <(sort "${HUNT_DIR}/subdomains.txt") <(sort "${HUNT_DIR}/subdomains_new.txt") | \
            httpx -silent -threads ${THREADS} -status-code -title -tech-detect -follow-redirects 2>/dev/null \
            > "${HUNT_DIR}/new_hosts_httpx.txt"
        log "  $(wc -l < "${HUNT_DIR}/new_hosts_httpx.txt") new live hosts found"

        # Add new URLs to urls.txt
        awk '{print $1}' "${HUNT_DIR}/new_hosts_httpx.txt" >> "${HUNT_DIR}/urls.txt"
        sort -u -o "${HUNT_DIR}/urls.txt" "${HUNT_DIR}/urls.txt"
    fi
else
    log "Phase 2/5: SKIP (dnsx not found or no permutations)"
fi

# --- Phase 3: xnLinkFinder JS endpoint extraction ---
if command -v xnLinkFinder &>/dev/null && [ -s "${HUNT_DIR}/js_files.txt" ]; then
    log "Phase 3/5: xnLinkFinder (JS endpoint + parameter extraction)"
    DOMAIN=$(head -1 "${HUNT_DIR}/subdomains.txt" 2>/dev/null | sed 's/^[^.]*\.//')
    head -100 "${HUNT_DIR}/js_files.txt" | xnLinkFinder -i - \
        -o "${HUNT_DIR}/js_endpoints.txt" \
        -op "${HUNT_DIR}/js_parameters.txt" \
        -sf "${DOMAIN}" \
        2>/dev/null || true
    EP_COUNT=$(wc -l < "${HUNT_DIR}/js_endpoints.txt" 2>/dev/null || echo 0)
    PARAM_COUNT=$(wc -l < "${HUNT_DIR}/js_parameters.txt" 2>/dev/null || echo 0)
    log "  Extracted ${EP_COUNT} endpoints, ${PARAM_COUNT} parameters"
else
    log "Phase 3/5: SKIP (xnLinkFinder not found or no js_files.txt)"
fi

# --- Phase 4: Custom nuclei templates ---
if command -v nuclei &>/dev/null && [ -d "$NUCLEI_CUSTOM" ] && [ -s "${HUNT_DIR}/urls.txt" ]; then
    TEMPLATE_COUNT=$(find "$NUCLEI_CUSTOM" -name '*.yaml' 2>/dev/null | wc -l)
    if [ "$TEMPLATE_COUNT" -gt 0 ]; then
        log "Phase 4/5: nuclei custom templates (${TEMPLATE_COUNT} templates)"
        nuclei -l "${HUNT_DIR}/urls.txt" -t "$NUCLEI_CUSTOM/" -c ${THREADS} -silent \
            -o "${HUNT_DIR}/nuclei_custom.txt" 2>/dev/null || true
        FINDING_COUNT=$(wc -l < "${HUNT_DIR}/nuclei_custom.txt" 2>/dev/null || echo 0)
        log "  Custom template findings: ${FINDING_COUNT}"
    else
        log "Phase 4/5: SKIP (no custom templates found)"
    fi
else
    log "Phase 4/5: SKIP (nuclei not found or no urls.txt)"
fi

# --- Phase 5: graphql-cop ---
if [ -f "$GRAPHQL_COP" ] && [ -s "${HUNT_DIR}/urls.txt" ]; then
    log "Phase 5/5: graphql-cop (GraphQL security audit)"
    GQL_TARGETS=$(grep -iP '(graphql|gql|api)' "${HUNT_DIR}/urls.txt" 2>/dev/null | head -20)
    if [ -n "$GQL_TARGETS" ]; then
        > "${HUNT_DIR}/graphql_cop_results.txt"
        while IFS= read -r url; do
            log "  Testing: $url"
            python3 "$GRAPHQL_COP" -t "$url" 2>/dev/null >> "${HUNT_DIR}/graphql_cop_results.txt" || true
            python3 "$GRAPHQL_COP" -t "${url}/graphql" 2>/dev/null >> "${HUNT_DIR}/graphql_cop_results.txt" || true
        done <<< "$GQL_TARGETS"
        GQL_COUNT=$(grep -c "FOUND" "${HUNT_DIR}/graphql_cop_results.txt" 2>/dev/null || echo 0)
        log "  GraphQL findings: ${GQL_COUNT}"
    else
        log "Phase 5/5: SKIP (no GraphQL-like URLs found)"
    fi
else
    log "Phase 5/5: SKIP (graphql-cop not found or no urls.txt)"
fi

log "Supplement pass complete. Results in: $HUNT_DIR"
log "New files: subdomains_permuted.txt, subdomains_new.txt, new_hosts_httpx.txt, js_endpoints.txt, js_parameters.txt, nuclei_custom.txt, graphql_cop_results.txt"
