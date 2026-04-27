#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  lib.sh — Shared functions for hunt.sh and scripts/          ║
# ║  Source this file, do not execute directly.                   ║
# ╚══════════════════════════════════════════════════════════════╝

# Guard against direct execution
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "lib.sh is a library — source it, don't execute it."
    echo "  source lib.sh"
    exit 1
fi

# ── Path Defaults ───────────────────────────────────────────────
HUNT_DIR="${HUNT_DIR:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")}"
BHEH_DIR="${BHEH_DIR:-${HUNT_DIR}/bheh_tools}"
SCRIPTS_DIR="${SCRIPTS_DIR:-${HUNT_DIR}/scripts}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-${HOME}/nuclei-templates}"
SECLISTS="${SECLISTS:-/usr/share/seclists}"
THREADS="${THREADS:-30}"
SUBMITTED_FILE="${SUBMITTED_FILE:-${HUNT_DIR}/submitted_findings.txt}"

# ── Custom User-Agent (for program compliance) ────────────────
# Set HUNT_UA env var to override User-Agent on all tools.
# Example: HUNT_UA="bugcrowd" ./hunt.sh ...
HUNT_UA="${HUNT_UA:-}"
HUNT_UA_ARGS=()
HUNT_UA_CURL=()
HUNT_UA_DALFOX=()
HUNT_UA_NIKTO=()
if [ -n "$HUNT_UA" ]; then
    HUNT_UA_ARGS=(-H "User-Agent: ${HUNT_UA}")       # httpx, nuclei, katana, ffuf, crlfuzz
    HUNT_UA_CURL=(--user-agent "${HUNT_UA}")           # curl
    HUNT_UA_DALFOX=(--user-agent "${HUNT_UA}")         # dalfox
    HUNT_UA_NIKTO=(-useragent "${HUNT_UA}")            # nikto
fi

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Logging ─────────────────────────────────────────────────────
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
phase_header() { echo -e "\n${BOLD}═══ PHASE $1: $2 ═══${NC}"; }

# ── Utility ─────────────────────────────────────────────────────
count_lines() { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "Missing: $1 (install with: sudo pacman -S $1)"
        return 1
    fi
    return 0
}

# Check for a BHEH tool by relative path under BHEH_DIR
# Usage: check_bheh "TerminatorZ/TerminatorZ.sh" && ...
check_bheh() {
    local relpath="$1"
    if [ -e "${BHEH_DIR}/${relpath}" ]; then
        return 0
    fi
    return 1
}

# Exit with error if required input file is missing or empty
# Usage: require_file "$urls_file" "URLs file"
require_file() {
    local filepath="$1" label="${2:-file}"
    if [ ! -f "$filepath" ]; then
        err "Required ${label} not found: ${filepath}"
        exit 1
    fi
    if [ ! -s "$filepath" ]; then
        warn "${label} is empty: ${filepath}"
    fi
}

# ── Common Argument Parser ──────────────────────────────────────
# Sets: DOMAIN, DOMAINS_FILE, URLS_FILE, OUT_DIR, THREADS, SCRIPT_NAME
# Usage: parse_common_args "$@"  (after setting SCRIPT_NAME and SCRIPT_DESC)
parse_common_args() {
    DOMAIN="${DOMAIN:-}"
    DOMAINS_FILE="${DOMAINS_FILE:-}"
    URLS_FILE="${URLS_FILE:-}"
    OUT_DIR="${OUT_DIR:-./out}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)   DOMAIN="$2"; shift 2 ;;
            --domains)     DOMAINS_FILE="$2"; shift 2 ;;
            -u|--urls)     URLS_FILE="$2"; shift 2 ;;
            -o|--out)      OUT_DIR="$2"; shift 2 ;;
            -t|--threads)  THREADS="$2"; shift 2 ;;
            --submitted)   SUBMITTED_FILE="$2"; shift 2 ;;
            --hailmary)    HAILMARY=1; shift ;;
            --platform)    PLATFORM="$2"; shift 2 ;;
            --keyword)     KEYWORD="$2"; shift 2 ;;
            -h|--help)     script_usage; exit 0 ;;
            *)             err "Unknown option: $1"; script_usage; exit 1 ;;
        esac
    done

    mkdir -p "$OUT_DIR"
}

# Default usage — override per-script by defining script_usage() before sourcing
if ! declare -f script_usage &>/dev/null; then
    script_usage() {
        echo "Usage: ${SCRIPT_NAME:-$(basename "$0")} [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  -d, --domain DOMAIN    Target domain"
        echo "  --domains FILE         File with domains (one per line)"
        echo "  -u, --urls FILE        File with URLs (one per line)"
        echo "  -o, --out DIR          Output directory (default: ./out)"
        echo "  -t, --threads N        Concurrency level (default: ${THREADS})"
        echo "  --submitted FILE       Submitted findings tracker"
        echo "  -h, --help             Show this help"
    }
fi

# ── Dedup / Submitted Findings Tracker ──────────────────────────
init_submitted() {
    if [ ! -f "$SUBMITTED_FILE" ]; then
        cat > "$SUBMITTED_FILE" << 'SUBEOF'
# submitted_findings.txt — Tracks already-reported findings to prevent duplicates
# Add one host/URL/pattern per line. Scripts will exclude matches from reports.
# Lines starting with # are comments. Matching is case-insensitive substring.
#
# Examples:
#   flashpaper.chime.com          # Excludes any finding on this host
#   research.pinterest.com/admin  # Excludes this specific path
#   CVE-2024-1234                 # Excludes a specific CVE by ID
SUBEOF
        log "Created submitted findings tracker: ${SUBMITTED_FILE}"
    fi
}

is_duplicate() {
    local line="$1"
    [ ! -f "$SUBMITTED_FILE" ] && return 1
    while IFS= read -r pattern; do
        [[ "$pattern" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${pattern// }" ]] && continue
        if echo "$line" | grep -qiF "$pattern"; then
            return 0
        fi
    done < "$SUBMITTED_FILE"
    return 1
}

filter_submitted() {
    local input_file="$1"
    local output_file="$2"
    [ ! -f "$input_file" ] && return
    [ ! -f "$SUBMITTED_FILE" ] && cp "$input_file" "$output_file" && return

    local total
    total=$(count_lines "$input_file")
    > "$output_file"
    local dupes=0
    while IFS= read -r line; do
        if is_duplicate "$line"; then
            ((dupes++)) || true
        else
            echo "$line" >> "$output_file"
        fi
    done < "$input_file"
    local kept
    kept=$(count_lines "$output_file")
    if [ "$dupes" -gt 0 ]; then
        warn "Dedup: removed ${dupes} previously-submitted findings (${kept}/${total} kept)"
    fi
}

mark_submitted() {
    local pattern="$1"
    local note="${2:-}"
    echo "${pattern}  # ${note} — submitted $(date +%Y-%m-%d)" >> "$SUBMITTED_FILE"
    log "Marked as submitted: ${pattern}"
}

list_submitted() {
    if [ ! -f "$SUBMITTED_FILE" ]; then
        warn "No submitted findings file found"
        return
    fi
    echo -e "${BOLD}── Previously Submitted Findings ──${NC}"
    grep -v '^[[:space:]]*#' "$SUBMITTED_FILE" | grep -v '^[[:space:]]*$' | while IFS= read -r line; do
        echo "  - ${line}"
    done
    local count
    count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$SUBMITTED_FILE" 2>/dev/null || echo 0)
    echo "  Total: ${count} patterns"
}

# ── Bugcrowd Universal Exclusion Filter ───────────────────────
# Based on Bugcrowd Standard Disclosure Terms + VRT P5 categories
# These findings are NEVER rewardable on ANY Bugcrowd program.

# Check if a finding line matches a universal Bugcrowd exclusion.
# Returns 0 (true) if the finding should be excluded, 1 (false) if OK.
is_standard_exclusion() {
    local line="$1"
    local lower
    lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')

    # P5: Version/banner disclosure without CVE exploitation
    if echo "$lower" | grep -qE '(banner|fingerprint|server.header|x-powered-by|version.disclos)' && \
       ! echo "$lower" | grep -qiE '(CVE-|exploit|rce|injection|bypass|data.access)'; then
        return 0
    fi

    # P5: Missing security headers (standalone)
    if echo "$lower" | grep -qE '(missing.*(hsts|strict-transport|x-frame|x-content-type|csp|content-security|referrer-policy|permissions-policy|x-xss-protection))' && \
       ! echo "$lower" | grep -qiE '(bypass|injection|exploit)'; then
        return 0
    fi

    # P5: Directory listing (non-sensitive)
    if echo "$lower" | grep -qE '(directory.listing|index.of)' && \
       ! echo "$lower" | grep -qiE '(password|secret|credential|key|token|backup|\.env|\.sql|\.bak)'; then
        return 0
    fi

    # P5: Missing cookie flags (standalone)
    if echo "$lower" | grep -qE '(missing.*(secure|httponly|samesite).*(flag|attribute|cookie))' && \
       ! echo "$lower" | grep -qiE '(session.hijack|fixation|theft)'; then
        return 0
    fi

    # P5: Username enumeration
    if echo "$lower" | grep -qE '(username.enum|user.enum|wp-json/wp/v2/users)' && \
       ! echo "$lower" | grep -qiE '(brute.force.success|credential.stuff|account.takeover)'; then
        return 0
    fi

    # P5: CAPTCHA issues
    if echo "$lower" | grep -qE '(missing.captcha|weak.captcha|captcha.bypass)' && \
       ! echo "$lower" | grep -qiE '(brute.force.success|account.takeover|rate.limit.bypass)'; then
        return 0
    fi

    # P5: Clickjacking on non-sensitive pages
    if echo "$lower" | grep -qE '(clickjack|x-frame-options|frameable)' && \
       ! echo "$lower" | grep -qiE '(login|account|settings|payment|admin|password|delete|transfer)'; then
        return 0
    fi

    # P5: CSRF on anonymous/logout
    if echo "$lower" | grep -qE '(csrf.*(logout|anonymous|unauthenticated|public.form))'; then
        return 0
    fi

    # P5: Known public files
    if echo "$lower" | grep -qE '(robots\.txt|sitemap\.xml|crossdomain\.xml|\.well-known|security\.txt)' && \
       ! echo "$lower" | grep -qiE '(secret|credential|password|disallow.*(admin|internal))'; then
        return 0
    fi

    # P5: GraphQL introspection alone
    if echo "$lower" | grep -qE '(graphql.*introspection|__schema|__type)' && \
       ! echo "$lower" | grep -qiE '(data.access|auth.bypass|sensitive.field|pii|mutation.exploit)'; then
        return 0
    fi

    # P5: Source maps on internal/infra tools
    if echo "$lower" | grep -qE '(\.js\.map|source.?map)' && \
       ! echo "$lower" | grep -qiE '(credential|secret|api.key|password|live_|private.key)'; then
        return 0
    fi

    # P5: SRI missing (standalone)
    if echo "$lower" | grep -qE '(subresource.integrity|sri.missing|integrity.attribute)'; then
        return 0
    fi

    # P5: CORS on write-only/ingest endpoints
    if echo "$lower" | grep -qE '(cors.*(ingest|collector|intake|hec|logging|beacon|track))'; then
        return 0
    fi

    # P5: EOL/outdated software without exploitation
    if echo "$lower" | grep -qE '(end.of.life|eol|outdated.*(software|version|component))' && \
       ! echo "$lower" | grep -qiE '(CVE-|exploit|rce|injection|data.access)'; then
        return 0
    fi

    # P5: Stack traces / error messages
    if echo "$lower" | grep -qE '(stack.trace|verbose.error|debug.mode|error.message.disclos)' && \
       ! echo "$lower" | grep -qiE '(credential|secret|password|api.key|token|database|internal.path)'; then
        return 0
    fi

    # P5: Login page without bypass (exposed portal but protected)
    if echo "$lower" | grep -qE '(login.page|admin.panel|management.console)' && \
       echo "$lower" | grep -qE '(401|403|redirect|protected|requires.auth)' && \
       ! echo "$lower" | grep -qiE '(bypass|default.cred|unauth.access)'; then
        return 0
    fi

    # P5: Vendor-default API documentation paths
    if echo "$lower" | grep -qE '(swagger|openapi|api.doc|wsdl.disclos)' && \
       ! echo "$lower" | grep -qiE '(unauth.data|sensitive|credential|internal.endpoint|undocumented)'; then
        return 0
    fi

    # P5: Unsafe HTTP methods without exploitation
    if echo "$lower" | grep -qE '(trace.method|options.method|unsafe.http.method)' && \
       ! echo "$lower" | grep -qiE '(xst|exploit|bypass)'; then
        return 0
    fi

    # P5: DNSSEC missing
    if echo "$lower" | grep -qE '(dnssec.missing|dnssec.not.configured)'; then
        return 0
    fi

    # P5: Self-XSS
    if echo "$lower" | grep -qE '(self-xss|self.xss|xss.*self)'; then
        return 0
    fi

    return 1
}

# Apply universal exclusion filter to a findings file.
# Adds [DO_NOT_SUBMIT:STANDARD_EXCLUSION] tag to matching lines.
# Usage: filter_standard_exclusions input_file output_file
filter_standard_exclusions() {
    local input_file="$1"
    local output_file="$2"
    [ ! -f "$input_file" ] && return

    local excluded=0
    > "$output_file"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Skip lines already tagged
        if echo "$line" | grep -q '^\[DO_NOT_SUBMIT'; then
            echo "$line" >> "$output_file"
            continue
        fi
        if is_standard_exclusion "$line"; then
            echo "[DO_NOT_SUBMIT:STANDARD_EXCLUSION] $line" >> "$output_file"
            ((excluded++)) || true
        else
            echo "$line" >> "$output_file"
        fi
    done < "$input_file"
    if [ "$excluded" -gt 0 ]; then
        warn "Standard exclusions: tagged ${excluded} findings as DO_NOT_SUBMIT (Bugcrowd universal P5)"
    fi
}

# Check if a URL/host is in the program's scope targets.
# Reads scope from $HUNT_DIR/scope_targets.txt (one target per line).
# Returns 0 if in scope, 1 if OOS.
is_in_scope() {
    local url="$1"
    local scope_file="${HUNT_DIR:-$OUT_DIR}/scope_targets.txt"
    [ ! -f "$scope_file" ] && return 0  # No scope file = skip check (backwards compat)

    local host
    host=$(echo "$url" | sed -E 's|^https?://||;s|/.*||;s|:[0-9]+$||')

    while IFS= read -r target; do
        [[ "$target" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${target// }" ]] && continue
        # Wildcard match: *.example.com matches sub.example.com
        if [[ "$target" == \** ]]; then
            local domain="${target#\*.}"
            if [[ "$host" == *"$domain" ]]; then
                return 0
            fi
        else
            # Exact match or subdomain match
            if [[ "$host" == "$target" ]] || [[ "$host" == *".$target" ]]; then
                return 0
            fi
        fi
    done < "$scope_file"
    return 1
}

# Tag OOS findings in a file.
# Usage: filter_oos_findings input_file output_file
filter_oos_findings() {
    local input_file="$1"
    local output_file="$2"
    local scope_file="${HUNT_DIR:-$OUT_DIR}/scope_targets.txt"
    [ ! -f "$input_file" ] && return
    [ ! -f "$scope_file" ] && cp "$input_file" "$output_file" && return

    local oos_count=0
    > "$output_file"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Extract URL from finding line
        local url
        url=$(echo "$line" | grep -oP 'https?://[^\s"<>]+' | head -1)
        if [ -n "$url" ] && ! is_in_scope "$url"; then
            echo "[DO_NOT_SUBMIT:OOS] $line" >> "$output_file"
            ((oos_count++)) || true
        else
            echo "$line" >> "$output_file"
        fi
    done < "$input_file"
    if [ "$oos_count" -gt 0 ]; then
        warn "Scope filter: tagged ${oos_count} findings as DO_NOT_SUBMIT:OOS (out of scope)"
    fi
}

# ── Impact Gate ──
# Runs impact_gate.py to filter findings matching known-rejected patterns.
# Based on 19 Bugcrowd rejections (2026-03). Use on any findings file.
# Usage: run_impact_gate input_file output_file [--strict]
run_impact_gate() {
    local input_file="$1" output_file="$2" strict="${3:-}"
    local gate_script="${HUNT_DIR:-$(dirname "$0")}/scripts/impact_gate.py"
    if [[ ! -f "$gate_script" ]]; then
        warn "impact_gate.py not found — rejection filter skipped (expected: ${gate_script})"
        [[ -f "$input_file" ]] && cp "$input_file" "$output_file"
        return 0
    fi
    [[ ! -f "$input_file" ]] && return 0

    local args=(--input "$input_file" --output "$output_file")
    [[ "$strict" == "--strict" ]] && args+=(--strict)

    python3 "$gate_script" "${args[@]}" 2>/dev/null
    local killed_file base="${output_file%.*}"
    local ext="${output_file##*.}"
    if [[ "$output_file" == *.json ]]; then
        killed_file="${base}.killed.json"
    elif [[ "$output_file" == *.txt ]]; then
        killed_file="${base}.killed.txt"
    else
        killed_file="${output_file}.killed"
    fi
    if [[ -f "$killed_file" ]]; then
        local kill_count
        kill_count=$(grep -c 'KILLED\|killed' "$killed_file" 2>/dev/null || echo 0)
        [[ "$kill_count" -gt 0 ]] && warn "Impact gate: killed ${kill_count} known-rejected patterns"
    fi
}
