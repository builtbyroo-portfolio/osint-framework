#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_csrf.sh — CSRF on Sensitive Actions                      ║
# ║  Missing CSRF tokens on sensitive forms + SameSite analysis  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_csrf.sh"
SCRIPT_DESC="CSRF on Sensitive Actions"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Check forms on sensitive pages for CSRF tokens."
    echo "  Analyze session cookies for SameSite attribute."
    echo "  Check Content-Type acceptance."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with sensitive URLs (from Phase 1)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "7" "$SCRIPT_DESC"

urls_input="${URLS_FILE:-${OUT_DIR}/sensitive_urls.txt}"
findings_file="${OUT_DIR}/csrf_findings.txt"
detail_file="${OUT_DIR}/csrf_detail.txt"
> "$findings_file"
> "$detail_file"

if [ ! -f "$urls_input" ] || [ ! -s "$urls_input" ]; then
    warn "No sensitive URLs found at ${urls_input} — skipping CSRF check"
    exit 0
fi

total=$(count_lines "$urls_input")
log "Checking ${total} sensitive URLs for CSRF protections"

# ── CSRF token patterns (hidden inputs, meta tags) ──
CSRF_PATTERNS='(csrf|_token|authenticity_token|xsrf|anti[-_]?forgery|__RequestVerificationToken|csrfmiddlewaretoken|_csrf_token|nonce|_wpnonce)'

checked=0
vulnerable=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    ((checked++)) || true

    echo "── ${url} ──" >> "$detail_file"

    # Fetch page with headers
    response_file=$(mktemp)
    header_file=$(mktemp)
    curl -sk -D "$header_file" -o "$response_file" --max-time 12 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || true

    if [ ! -s "$response_file" ]; then
        rm -f "$response_file" "$header_file"
        continue
    fi

    body=$(cat "$response_file")
    headers=$(cat "$header_file")

    # ── Check 1: Forms with CSRF tokens ──
    has_form=false
    has_csrf_token=false
    form_count=$(echo "$body" | grep -ciP '<form' || true)

    if [ "$form_count" -gt 0 ]; then
        has_form=true

        # Check for CSRF token in hidden inputs
        if echo "$body" | grep -qiP "type\s*=\s*[\"']hidden[\"'][^>]*name\s*=\s*[\"']${CSRF_PATTERNS}"; then
            has_csrf_token=true
        fi
        # Check reversed attribute order
        if echo "$body" | grep -qiP "name\s*=\s*[\"']${CSRF_PATTERNS}[^>]*type\s*=\s*[\"']hidden"; then
            has_csrf_token=true
        fi
        # Check meta tags for CSRF
        if echo "$body" | grep -qiP "<meta[^>]*name\s*=\s*[\"']${CSRF_PATTERNS}"; then
            has_csrf_token=true
        fi
        # Check for CSRF in JavaScript (common in SPAs)
        if echo "$body" | grep -qiP "(X-CSRF-Token|X-XSRF-TOKEN|csrf[_-]?token)\s*[=:]"; then
            has_csrf_token=true
        fi
    fi

    echo "FORMS: ${form_count}, CSRF_TOKEN: ${has_csrf_token}" >> "$detail_file"

    # ── Check 2: Session cookie SameSite attribute ──
    samesite="MISSING"
    cookie_lines=$(echo "$headers" | grep -i '^Set-Cookie:' || true)

    if [ -n "$cookie_lines" ]; then
        # Check session-like cookies
        session_cookie=$(echo "$cookie_lines" | grep -iP '(session|sid|sess|auth|token|jwt|connect\.sid)' | head -1)
        if [ -z "$session_cookie" ]; then
            session_cookie=$(echo "$cookie_lines" | head -1)
        fi

        if [ -n "$session_cookie" ]; then
            if echo "$session_cookie" | grep -qi 'SameSite=Strict'; then
                samesite="STRICT"
            elif echo "$session_cookie" | grep -qi 'SameSite=Lax'; then
                samesite="LAX"
            elif echo "$session_cookie" | grep -qi 'SameSite=None'; then
                samesite="NONE"
            else
                samesite="MISSING"
            fi
        fi
    fi

    echo "SAMESITE: ${samesite}" >> "$detail_file"

    # ── Check 3: Content-Type acceptance ──
    # If endpoint accepts application/x-www-form-urlencoded, CSRF via form is possible
    # JSON-only endpoints are harder to CSRF (no simple form submission)
    content_type_note=""
    if $has_form; then
        # Forms typically use urlencoded — CSRF via form is straightforward
        content_type_note="FORM_URLENCODED"
    fi

    # ── Check 4: Custom header requirements ──
    # If the app requires custom headers (X-Requested-With, etc.), CSRF is harder
    has_custom_header_check=false
    if echo "$body" | grep -qiP '(X-Requested-With|X-Custom-Header)'; then
        has_custom_header_check=true
    fi

    echo "CUSTOM_HEADER_CHECK: ${has_custom_header_check}" >> "$detail_file"

    # ── Classify vulnerability ──
    if $has_form && ! $has_csrf_token; then
        # Form without CSRF token
        csrf_protected=false

        # SameSite=Strict mitigates most CSRF
        if [ "$samesite" = "STRICT" ]; then
            echo "MITIGATED: SameSite=Strict on session cookie" >> "$detail_file"
            csrf_protected=true
        fi

        if ! $csrf_protected; then
            ((vulnerable++)) || true

            # Classify sensitivity of the action
            sensitivity="LOW"
            if echo "$url" | grep -qiP '(password|email|delete|transfer|payment|withdraw|settings/security)'; then
                sensitivity="HIGH"
            elif echo "$url" | grep -qiP '(account|profile|settings|preferences|2fa|mfa)'; then
                sensitivity="MEDIUM"
            fi

            severity="P4"
            if [ "$sensitivity" = "HIGH" ]; then
                severity="P2"
            elif [ "$sensitivity" = "MEDIUM" ]; then
                severity="P3"
            fi

            samesite_note=""
            if [ "$samesite" = "LAX" ]; then
                samesite_note=" SameSite=Lax (GET-based CSRF possible)"
            elif [ "$samesite" = "NONE" ]; then
                samesite_note=" SameSite=None (full CSRF possible)"
            elif [ "$samesite" = "MISSING" ]; then
                samesite_note=" SameSite=MISSING (browser defaults to Lax)"
            fi

            echo "[${severity}:CSRF:NO_TOKEN] ${url} | ${form_count} form(s) without CSRF token | sensitivity:${sensitivity}${samesite_note}" >> "$findings_file"
        fi
    fi

    echo "" >> "$detail_file"
    rm -f "$response_file" "$header_file"

    [ $((checked % 10)) -eq 0 ] && info "Checked ${checked}/${total} URLs (${vulnerable} vulnerable)..."
done < "$urls_input"

# ── Summary ──
sort -u -o "$findings_file" "$findings_file"
finding_count=$(count_lines "$findings_file")
log "Checked: ${checked} sensitive URLs"
log "CSRF findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "Missing CSRF protections:"
    grep -P '\[P[23]:' "$findings_file" || true
fi
log "Detailed analysis: ${detail_file}"
