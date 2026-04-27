#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_reverse_tabnab.sh — Reverse Tabnabbing Detection         ║
# ║  target="_blank" without rel="noopener" (Phase 6)            ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_reverse_tabnab.sh"
SCRIPT_DESC="Reverse Tabnabbing Detection"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Scan pages for <a target=\"_blank\"> links without"
    echo "  rel=\"noopener noreferrer\". Focus on UGC areas."
    echo "  Note: Modern browsers mitigate this (Chrome 88+, FF 79+)."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with surface URLs (from Phase 1)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "6" "$SCRIPT_DESC"

urls_input="${URLS_FILE:-${OUT_DIR}/surface_urls.txt}"
findings_file="${OUT_DIR}/tabnab_findings.txt"
> "$findings_file"

if [ ! -f "$urls_input" ] || [ ! -s "$urls_input" ]; then
    warn "No surface URLs found at ${urls_input} — skipping"
    exit 0
fi

total=$(count_lines "$urls_input")
log "Scanning ${total} URLs for reverse tabnabbing"

checked=0
found=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((checked++)) || true

    # Fetch page HTML
    body=$(curl -sk --max-time 12 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || true)
    [ -z "$body" ] && continue

    # Find all <a target="_blank"> links
    # Extract links that have target="_blank" but lack noopener
    vulnerable_links=$(echo "$body" | grep -oiP '<a\s[^>]*target\s*=\s*["\x27]_blank["\x27][^>]*>' | while IFS= read -r tag; do
        # Check if rel contains noopener
        if ! echo "$tag" | grep -qiP 'rel\s*=\s*["\x27][^"]*noopener'; then
            # Extract href
            href=$(echo "$tag" | grep -oP 'href\s*=\s*["\x27]\K[^"\x27]+' | head -1)
            if [ -n "$href" ]; then
                echo "$href"
            fi
        fi
    done)

    if [ -n "$vulnerable_links" ]; then
        link_count=$(echo "$vulnerable_links" | wc -l)

        # Check if these are external links (more impactful)
        page_domain=$(echo "$url" | grep -oP 'https?://[^/]+')
        external_count=0
        while IFS= read -r link; do
            if echo "$link" | grep -qP '^https?://' && ! echo "$link" | grep -qi "$page_domain"; then
                ((external_count++)) || true
            fi
        done <<< "$vulnerable_links"

        if [ "$external_count" -gt 0 ]; then
            ((found++)) || true
            echo "[P4:TABNAB:EXTERNAL] ${url} | ${external_count} external links without noopener | NOTE: mitigated in modern browsers" >> "$findings_file"
        elif [ "$link_count" -gt 0 ]; then
            # Internal links without noopener — lower risk
            echo "[P5:TABNAB:INTERNAL] ${url} | ${link_count} links without noopener (internal only)" >> "$findings_file"
        fi
    fi

    [ $((checked % 10)) -eq 0 ] && info "Scanned ${checked}/${total} pages (${found} vulnerable)..."
done < <(head -50 "$urls_input")

# ── Katana crawl for deeper link discovery ──
if check_tool "katana" 2>/dev/null && [ -s "$urls_input" ]; then
    info "Running Katana crawl for additional link discovery..."
    katana_out="${OUT_DIR}/katana_tabnab.txt"
    head -5 "$urls_input" | katana -silent -depth 2 -jc \
        "${HUNT_UA_ARGS[@]}" 2>/dev/null > "$katana_out" || true
    if [ -s "$katana_out" ]; then
        # Check crawled pages for tabnab
        while IFS= read -r crawled_url; do
            [ -z "$crawled_url" ] && continue
            body=$(curl -sk --max-time 8 "${HUNT_UA_CURL[@]}" "$crawled_url" 2>/dev/null || true)
            [ -z "$body" ] && continue

            if echo "$body" | grep -qiP '<a\s[^>]*target\s*=\s*["\x27]_blank["\x27]' && \
               ! echo "$body" | grep -qiP 'rel\s*=\s*["\x27][^"]*noopener'; then
                # Quick check — has at least one vulnerable link
                echo "[P4:TABNAB:CRAWLED] ${crawled_url} | target=_blank without noopener found" >> "$findings_file"
            fi
        done < <(head -20 "$katana_out")
    fi
fi

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
log "Scanned: ${checked} pages"
log "Reverse tabnabbing findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "Reverse tabnabbing found (note: modern browsers mitigate this):"
    grep "EXTERNAL" "$findings_file" || true
fi
