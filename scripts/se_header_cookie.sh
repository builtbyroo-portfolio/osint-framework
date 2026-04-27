#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_header_cookie.sh — Header/Cookie Security Audit          ║
# ║  Session cookie flags, HSTS, Referrer-Policy (Phase 10)      ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_header_cookie.sh"
SCRIPT_DESC="Header/Cookie Security Audit"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Audit session cookies (Secure, HttpOnly, SameSite)"
    echo "  and security headers (HSTS, Referrer-Policy)."
    echo "  NOTE: Standalone header findings = P5 per VRT."
    echo "  Tagged [DO_NOT_SUBMIT] unless chained with impact."
    echo ""
    echo "Options:"
    echo "  -u, --urls FILE        File with sensitive URLs (from Phase 1)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "10" "$SCRIPT_DESC"

urls_input="${URLS_FILE:-${OUT_DIR}/sensitive_urls.txt}"
findings_file="${OUT_DIR}/header_cookie_findings.txt"
detail_file="${OUT_DIR}/header_cookie_detail.txt"
> "$findings_file"
> "$detail_file"

# Fall back to surface_urls if sensitive_urls doesn't exist
if [ ! -s "$urls_input" ]; then
    urls_input="${OUT_DIR}/surface_urls.txt"
fi

if [ ! -f "$urls_input" ] || [ ! -s "$urls_input" ]; then
    warn "No URLs found at ${urls_input} — skipping header/cookie audit"
    exit 0
fi

total=$(count_lines "$urls_input")
log "Auditing ${total} URLs for header/cookie security"

checked=0
issues=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((checked++)) || true

    echo "── ${url} ──" >> "$detail_file"

    headers=$(curl -sk -D- -o /dev/null --max-time 10 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || true)
    [ -z "$headers" ] && continue

    url_issues=()

    # ── Cookie Analysis ──
    cookie_lines=$(echo "$headers" | grep -i '^Set-Cookie:' || true)
    if [ -n "$cookie_lines" ]; then
        echo "$cookie_lines" | while IFS= read -r cookie_line; do
            cookie_name=$(echo "$cookie_line" | sed 's/^Set-Cookie:\s*//i' | cut -d= -f1 | tr -d ' ')
            is_session=false

            # Identify session-like cookies
            if echo "$cookie_name" | grep -qiP '(session|sid|sess|auth|token|jwt|connect\.sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|_session|laravel_session)'; then
                is_session=true
            fi

            # Check Secure flag
            if ! echo "$cookie_line" | grep -qi 'Secure'; then
                if $is_session; then
                    echo "[P4:COOKIE:MISSING_SECURE] ${url} | session cookie '${cookie_name}' missing Secure flag" >> "$findings_file"
                    ((issues++)) || true
                else
                    echo "[DO_NOT_SUBMIT:COOKIE:MISSING_SECURE] ${url} | cookie '${cookie_name}' missing Secure flag" >> "$findings_file"
                fi
                echo "MISSING_SECURE: ${cookie_name}" >> "$detail_file"
            fi

            # Check HttpOnly flag
            if ! echo "$cookie_line" | grep -qi 'HttpOnly'; then
                if $is_session; then
                    echo "[P4:COOKIE:MISSING_HTTPONLY] ${url} | session cookie '${cookie_name}' missing HttpOnly flag" >> "$findings_file"
                    ((issues++)) || true
                else
                    echo "[DO_NOT_SUBMIT:COOKIE:MISSING_HTTPONLY] ${url} | cookie '${cookie_name}' missing HttpOnly flag" >> "$findings_file"
                fi
                echo "MISSING_HTTPONLY: ${cookie_name}" >> "$detail_file"
            fi

            # Check SameSite attribute
            if ! echo "$cookie_line" | grep -qi 'SameSite'; then
                if $is_session; then
                    echo "[P5:COOKIE:MISSING_SAMESITE] ${url} | session cookie '${cookie_name}' missing SameSite (browser defaults to Lax)" >> "$findings_file"
                fi
                echo "MISSING_SAMESITE: ${cookie_name}" >> "$detail_file"
            elif echo "$cookie_line" | grep -qi 'SameSite=None'; then
                if $is_session; then
                    echo "[P4:COOKIE:SAMESITE_NONE] ${url} | session cookie '${cookie_name}' SameSite=None (cross-site requests send cookie)" >> "$findings_file"
                    ((issues++)) || true
                fi
                echo "SAMESITE_NONE: ${cookie_name}" >> "$detail_file"
            fi
        done
    fi

    # ── HSTS (Strict-Transport-Security) ──
    hsts=$(echo "$headers" | grep -i '^Strict-Transport-Security:' | head -1 | tr -d '\r')
    if [ -z "$hsts" ]; then
        echo "[DO_NOT_SUBMIT:HEADER:NO_HSTS] ${url} | Missing Strict-Transport-Security header" >> "$findings_file"
        echo "MISSING_HSTS" >> "$detail_file"
    else
        echo "HSTS: ${hsts}" >> "$detail_file"
        # Check for preload
        if ! echo "$hsts" | grep -qi 'preload'; then
            echo "HSTS_NO_PRELOAD" >> "$detail_file"
        fi
        # Check max-age
        max_age=$(echo "$hsts" | grep -oP 'max-age=\K\d+')
        if [ -n "$max_age" ] && [ "$max_age" -lt 31536000 ]; then
            echo "HSTS_SHORT_MAXAGE: ${max_age}s (< 1 year)" >> "$detail_file"
        fi
    fi

    # ── Referrer-Policy ──
    referrer=$(echo "$headers" | grep -i '^Referrer-Policy:' | head -1 | tr -d '\r')
    if [ -z "$referrer" ]; then
        # Missing Referrer-Policy on auth pages = potential token leakage
        if echo "$url" | grep -qiP '(login|auth|oauth|token|session|password|reset)'; then
            echo "[P5:HEADER:NO_REFERRER_POLICY] ${url} | Missing Referrer-Policy on auth page (potential token leakage via Referer header)" >> "$findings_file"
        else
            echo "[DO_NOT_SUBMIT:HEADER:NO_REFERRER_POLICY] ${url} | Missing Referrer-Policy" >> "$findings_file"
        fi
        echo "MISSING_REFERRER_POLICY" >> "$detail_file"
    else
        echo "REFERRER_POLICY: ${referrer}" >> "$detail_file"
        # Check for unsafe policies
        if echo "$referrer" | grep -qiP '(unsafe-url|no-referrer-when-downgrade)'; then
            if echo "$url" | grep -qiP '(login|auth|oauth|token|session)'; then
                echo "[P5:HEADER:UNSAFE_REFERRER_POLICY] ${url} | Referrer-Policy: ${referrer} on auth page" >> "$findings_file"
            fi
        fi
    fi

    # ── X-Content-Type-Options ──
    xcto=$(echo "$headers" | grep -i '^X-Content-Type-Options:' | head -1)
    if [ -z "$xcto" ]; then
        echo "[DO_NOT_SUBMIT:HEADER:NO_XCTO] ${url} | Missing X-Content-Type-Options" >> "$findings_file"
        echo "MISSING_XCTO" >> "$detail_file"
    fi

    # ── Cache-Control on sensitive pages ──
    cache=$(echo "$headers" | grep -i '^Cache-Control:' | head -1 | tr -d '\r')
    if echo "$url" | grep -qiP '(login|auth|account|password|settings|payment|admin)'; then
        if [ -z "$cache" ] || ! echo "$cache" | grep -qi 'no-store'; then
            echo "[P5:HEADER:CACHEABLE_SENSITIVE] ${url} | Sensitive page may be cached (missing no-store)" >> "$findings_file"
            echo "CACHEABLE_SENSITIVE: ${cache:-MISSING}" >> "$detail_file"
        fi
    fi

    echo "" >> "$detail_file"

    [ $((checked % 10)) -eq 0 ] && info "Audited ${checked}/${total} URLs..."
done < "$urls_input"

# ── Nuclei security header templates ──
if check_tool "nuclei" 2>/dev/null && [ -s "$urls_input" ]; then
    info "Running nuclei security header templates..."
    nuclei_hdr="${OUT_DIR}/nuclei_headers.txt"
    nuclei -l "$urls_input" -tags headers,cookies -severity info,low -silent \
        "${HUNT_UA_ARGS[@]}" 2>/dev/null > "$nuclei_hdr" || true
    if [ -s "$nuclei_hdr" ]; then
        while IFS= read -r line; do
            echo "[DO_NOT_SUBMIT:NUCLEI] ${line}" >> "$findings_file"
        done < "$nuclei_hdr"
        log "Nuclei header findings: $(count_lines "$nuclei_hdr")"
    fi
fi

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
submit_count=$(grep -cv 'DO_NOT_SUBMIT' "$findings_file" 2>/dev/null || echo 0)
log "Audited: ${checked} URLs"
log "Total header/cookie findings: ${finding_count}"
log "Potentially submittable (session cookie issues): ${submit_count}"
if [ "$submit_count" -gt 0 ]; then
    warn "Session cookie security issues:"
    grep -v 'DO_NOT_SUBMIT' "$findings_file" | head -10 || true
fi
warn "Most header findings are P5 — only submit if chained with demonstrated impact"
log "Detailed analysis: ${detail_file}"
