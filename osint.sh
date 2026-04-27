#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  osint.sh v3.0  —  Interactive OSINT Investigation Framework
#  Output : ~/Desktop/{name}_investigation.zip
#  Import : Maltego  ·  Burp Suite  ·  recon-ng  ·  SpiderFoot
#
#  Pivot engine: after the initial pass, automatically extracts newly
#  discovered entities (emails, names, phones, IPs, domains) from tool
#  output and investigates them to the configured depth level.
# ═══════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DATE_HUMAN="$(date '+%Y-%m-%d %H:%M')"
DESKTOP="${HOME}/Desktop"
VERSION="4.0"

MAIGRET_BIN="/home/raze/.local/share/virtualenvs/operator_toolbox-X2A_8faL/bin/maigret"
SUBFINDER_BIN="${SCRIPT_DIR}/../subfinder"

# ── Load API keys from central key store ────────────────────────────────────
[[ -f "${HOME}/.config/osint/keys.env" ]] && source "${HOME}/.config/osint/keys.env"

# ── Optional API keys (set as env vars, skipped if absent) ──────────────────
# export WIGLE_API_KEY="..."           SSID geolocation
# export SHODAN_API_KEY="..."          IP intelligence (REST API)
# export HIBP_API_KEY="..."            Have I Been Pwned breach lookups
# export ABUSEIPDB_API_KEY="..."       IP abuse/reputation scoring
# export INTELX_API_KEY="..."          IntelligenceX breach metadata + leak search
# export VIEWDNS_API_KEY="..."         viewdns.info reverse IP/WHOIS/history
# export WHOISXML_API_KEY="..."        WHOIS history + reverse WHOIS by email/name
# export CRIMINALIP_API_KEY="..."      CriminalIP threat scoring + proxy/VPN detection
# export SECURITYTRAILS_API_KEY="..."  Passive DNS history + reverse WHOIS (50/month free)
# export GREYNOISE_API_KEY="..."       GreyNoise community IP classification (free tier)
# export GITHUB_TOKEN="..."            GitHub code search for email/domain leaks
# export HUNTER_API_KEY="..."          hunter.io domain→email discovery + email verification
# export NUMVERIFY_API_KEY="..."       numverify phone validation + carrier/line type lookup
# export URLSCAN_API_KEY="..."         urlscan.io domain/URL scan + tech fingerprint + screenshot

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'  Y='\033[1;33m'  G='\033[0;32m'  C='\033[0;36m'
B='\033[0;34m'  M='\033[0;35m'  W='\033[1;37m'  DIM='\033[2m'
BOLD='\033[1m'  RESET='\033[0m'

# ── Investigation state ─────────────────────────────────────────────────────
INVESTIGATION_NAME=""
CASE_NUMBER=""
INVESTIGATOR="${USER}"
TARGET_TYPE="mixed"
NOTES=""
MAX_DEPTH=1                   # default: investigate one level of discovered entities

declare -a EMAILS=()
declare -a PHONES=()
declare -a USERNAMES=()
declare -a FULLNAMES=()
declare -a DOMAINS=()
declare -a IPS=()
declare -a ADDRESSES=()
declare -a MACS=()
declare -a SSIDS=()

OUTDIR=""
SAFE_NAME=""

RUN_EMAIL=false   RUN_USERNAME=false  RUN_PHONE=false
RUN_DOMAIN=false  RUN_IP=false        RUN_NETWORK=false
RUN_ADDRESS=false RUN_FULLNAME=false

# ── Entity tracking — prevents re-investigating the same entity ─────────────
declare -A KNOWN=()   # key: "type:lc_value"  value: depth investigated at

mark_known() {
    local type="$1" value="${2,,}"
    KNOWN["${type}:${value}"]=1
}
is_known() {
    local type="$1" value="${2,,}"
    [[ -n "${KNOWN["${type}:${value}"]:-}" ]]
}

# ── Pivot state (repopulated each depth level) ──────────────────────────────
declare -a PIVOT_EMAILS=()
declare -a PIVOT_USERNAMES=()
declare -a PIVOT_DOMAINS=()
declare -a PIVOT_IPS=()
declare -a PIVOT_NAMES=()
declare -a PIVOT_PHONES=()


# ════════════════════════════════════════════════════════════════════════════
#  UI HELPERS
# ════════════════════════════════════════════════════════════════════════════

banner() {
    clear
    echo -e "${C}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║   ██████╗ ███████╗██╗███╗   ██╗████████╗               ║"
    echo "  ║  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝               ║"
    echo "  ║  ██║   ██║███████╗██║██╔██╗ ██║   ██║                  ║"
    echo "  ║  ██║   ██║╚════██║██║██║╚██╗██║   ██║                  ║"
    echo "  ║  ╚██████╔╝███████║██║██║ ╚████║   ██║                  ║"
    echo "  ║   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝                  ║"
    echo "  ║                                                          ║"
    echo "  ║   Investigation Framework  v${VERSION}  [pivot engine]         ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

section() {
    echo
    echo -e "${C}${BOLD}  ┌──────────────────────────────────────────────────────┐${RESET}"
    printf  "${C}${BOLD}  │  %-52s│${RESET}\n" "  ◈  $1"
    echo -e "${C}${BOLD}  └──────────────────────────────────────────────────────┘${RESET}"
}

log()  { echo "[$(date +%H:%M:%S)] $*" >> "${OUTDIR}/timeline.log" 2>/dev/null || true; }
info() { echo -e "  ${C}ℹ${RESET}  $*"; }
ok()   { echo -e "  ${G}✓${RESET}  $*"; }
warn() { echo -e "  ${Y}⚠${RESET}  $*"; }
step() { echo -e "\n  ${M}▶${RESET}  ${BOLD}$1${RESET}  ${DIM}${2:-}${RESET}"; }
pivot_found() { echo -e "  ${Y}◎${RESET}  ${BOLD}$1${RESET}  ${DIM}→ queued for depth $2${RESET}"; }

has_tool() { command -v "$1" &>/dev/null; }

# ── IntelligenceX search helper (2-step: submit → poll result) ───────────────
# Usage: intelx_search "term" outfile.json
intelx_search() {
    local term="$1" outfile="$2"
    local key="${INTELX_API_KEY:-}"
    [[ -z "$key" ]] && return 0

    local search_id
    search_id="$(curl -s --max-time 15 -X POST "https://free.intelx.io/intelligent/search" \
        -H "x-key: ${key}" -H "Content-Type: application/json" \
        -d "{\"term\":\"${term}\",\"maxresults\":20,\"media\":0,\"sort\":4,\"terminate\":[]}" \
        2>/dev/null | jq -r '.id // empty' 2>/dev/null)"

    [[ -z "$search_id" ]] && return 0

    sleep 3  # allow indexer to populate results

    curl -s --max-time 15 \
        "https://free.intelx.io/intelligent/search/result?id=${search_id}&limit=20&offset=0" \
        -H "x-key: ${key}" 2>/dev/null \
        | jq '{total: (.records | length), results: [.records[]? | {bucket: .bucket, date: .date, name: .name, size: .size, storageid: .storageid}]}' \
        2>/dev/null > "$outfile" || true
}

offer_install() {
    local pkg="$1" cmd="${2:-$1}"
    if ! has_tool "$cmd"; then
        printf "\n  ${Y}⚠${RESET}  ${BOLD}%s${RESET} not installed. Install via pacman? [y/N] " "$pkg"
        read -r ans
        if [[ "${ans,,}" == "y" ]]; then
            sudo pacman -S --noconfirm "$pkg" 2>&1 | grep -E "^(installing|error)" || true
            has_tool "$cmd" && ok "Installed $pkg" || warn "Install failed — $pkg phases will be skipped"
        else
            warn "$pkg not installed — those phases will be skipped"
        fi
    fi
}

collect() {
    local -n _arr=$1
    local label="$2"
    local hint="$3"
    local added=0

    echo
    printf "  ${W}${BOLD}%-24s${RESET}  ${DIM}e.g. %s${RESET}\n" "$label" "$hint"
    printf "  ${DIM}  One per line or comma-separated. Blank line to continue.${RESET}\n"

    while IFS= read -r -p "  $(printf "${C}→ ${RESET}")" raw; do
        [[ -z "$raw" ]] && break
        while IFS=',' read -ra parts; do
            for p in "${parts[@]}"; do
                p="${p#"${p%%[![:space:]]*}"}"
                p="${p%"${p##*[![:space:]]}"}"
                [[ -n "$p" ]] && _arr+=("$p") && added=$(( added + 1 ))
            done
        done <<< "$raw"
    done

    if (( added > 0 )); then
        printf "  ${G}✓  %d %s recorded${RESET}\n" "$added" "$label"
    else
        printf "  ${DIM}     skipped${RESET}\n"
    fi
}


# ════════════════════════════════════════════════════════════════════════════
#  DATA ENTRY
# ════════════════════════════════════════════════════════════════════════════

enter_data() {
    # Parse --depth flag before interactive prompts
    for arg in "$@"; do
        case "$arg" in
            --depth=*) MAX_DEPTH="${arg#*=}" ;;
        esac
    done

    banner

    section "INVESTIGATION METADATA"

    printf "\n  ${W}${BOLD}Investigation name${RESET}  ${DIM}(e.g. BestUSALeads, JohnDoe, AcmeCorp)${RESET}\n"
    printf "  ${C}→ ${RESET}"; read -r INVESTIGATION_NAME
    [[ -z "$INVESTIGATION_NAME" ]] && { echo -e "  ${R}✗  Name required.${RESET}"; exit 1; }

    printf "\n  ${W}${BOLD}Case / reference number${RESET}  ${DIM}(optional)${RESET}\n"
    printf "  ${C}→ ${RESET}"; read -r CASE_NUMBER

    printf "\n  ${W}${BOLD}Investigator${RESET}  ${DIM}(default: ${USER})${RESET}\n"
    printf "  ${C}→ ${RESET}"; read -r inp; [[ -n "$inp" ]] && INVESTIGATOR="$inp"

    echo
    echo -e "  ${W}${BOLD}Target type${RESET}"
    echo -e "  ${DIM}  1) Person    2) Organization    3) Domain / IP    4) Mixed (default)${RESET}"
    printf "  ${C}→ ${RESET}"; read -r t
    case "$t" in
        1) TARGET_TYPE="person" ;;       2) TARGET_TYPE="organization" ;;
        3) TARGET_TYPE="domain/ip" ;;    *) TARGET_TYPE="mixed" ;;
    esac

    echo
    echo -e "  ${W}${BOLD}Pivot depth${RESET}  ${DIM}(how many levels deep to follow discovered entities)${RESET}"
    echo -e "  ${DIM}  0 = seed data only${RESET}"
    echo -e "  ${DIM}  1 = investigate entities found in initial scan  (default)${RESET}"
    echo -e "  ${DIM}  2 = also investigate what depth-1 finds${RESET}"
    printf "  ${C}→ ${RESET}"; read -r d_input
    [[ "$d_input" =~ ^[0-9]+$ ]] && MAX_DEPTH="$d_input"

    section "SEED DATA  —  What do you already know?"
    echo -e "  ${DIM}  Fill in whatever you have. Every field is optional.${RESET}"

    collect EMAILS    "Email addresses"     "jane@example.com, info@corp.org"
    collect PHONES    "Phone numbers"       "8645909905, 2125550100"
    collect USERNAMES "Usernames / handles" "janed_99, JaneDoe, jane.doe"
    collect FULLNAMES "Full names"          "Jane Doe, John A. Smith"
    collect DOMAINS   "Domains / websites"  "example.com, shop.example.com"
    collect IPS       "IP addresses"        "104.21.44.220, 192.168.1.1"
    collect ADDRESSES "Physical addresses"  "123 Main St, Springfield, IL 62701  ← FULL address on ONE line"
    collect MACS      "MAC addresses"       "00:1A:2B:3C:4D:5E"
    collect SSIDS     "Wi-Fi SSIDs"         "CoffeeShop_Guest, CorpNet-5G"

    echo
    printf "  ${W}${BOLD}Additional notes${RESET}  ${DIM}(one line, optional)${RESET}\n"
    printf "  ${C}→ ${RESET}"; read -r NOTES
}


# ════════════════════════════════════════════════════════════════════════════
#  REVIEW SCREEN
# ════════════════════════════════════════════════════════════════════════════

review() {
    _row() {
        local label="$1"; shift
        local arr=("$@")
        local val count=${#arr[@]}
        if   (( count == 0 ));  then val="—"
        elif (( count <= 2 ));  then val="${arr[*]}"
        else val="${arr[0]}, ${arr[1]} … (+$((count-2)) more)"
        fi
        printf "${C}${BOLD}  │${RESET}  ${W}%-20s${RESET}  %-29s ${C}${BOLD}│${RESET}\n" \
            "${label} (${count})" "${val:0:29}"
    }

    clear
    echo
    echo -e "${C}${BOLD}  ┌────────────────────────────────────────────────────────┐${RESET}"
    printf  "${C}${BOLD}  │  %-54s│${RESET}\n" " INVESTIGATION: ${INVESTIGATION_NAME^^}"
    [[ -n "$CASE_NUMBER" ]] && \
    printf  "${C}${BOLD}  │  %-54s│${RESET}\n" " Case: ${CASE_NUMBER}"
    printf  "${C}${BOLD}  │  %-54s│${RESET}\n" " Investigator: ${INVESTIGATOR}  |  ${DATE_HUMAN}"
    printf  "${C}${BOLD}  │  %-54s│${RESET}\n" " Target type: ${TARGET_TYPE}  |  Pivot depth: ${MAX_DEPTH}"
    echo -e "${C}${BOLD}  ├────────────────────────────────────────────────────────┤${RESET}"
    _row "Emails"       "${EMAILS[@]+"${EMAILS[@]}"}"
    _row "Phones"       "${PHONES[@]+"${PHONES[@]}"}"
    _row "Usernames"    "${USERNAMES[@]+"${USERNAMES[@]}"}"
    _row "Full names"   "${FULLNAMES[@]+"${FULLNAMES[@]}"}"
    _row "Domains"      "${DOMAINS[@]+"${DOMAINS[@]}"}"
    _row "IP addresses" "${IPS[@]+"${IPS[@]}"}"
    _row "Addresses"    "${ADDRESSES[@]+"${ADDRESSES[@]}"}"
    _row "MACs"         "${MACS[@]+"${MACS[@]}"}"
    _row "SSIDs"        "${SSIDS[@]+"${SSIDS[@]}"}"
    echo -e "${C}${BOLD}  └────────────────────────────────────────────────────────┘${RESET}"

    echo
    printf "  ${W}${BOLD}Begin investigation? [Y/n]${RESET} "
    read -r confirm
    [[ "${confirm,,}" == "n" ]] && echo "  Aborted." && exit 0
}


# ════════════════════════════════════════════════════════════════════════════
#  DIRECTORY SETUP
# ════════════════════════════════════════════════════════════════════════════

setup_dirs() {
    SAFE_NAME="$(echo "$INVESTIGATION_NAME" | tr '[:upper:]' '[:lower:]' \
                 | tr ' ' '_' | tr -cd 'a-z0-9_-')"
    OUTDIR="${HOME}/Documents/${SAFE_NAME}_investigation_${TIMESTAMP}"

    mkdir -p "${OUTDIR}"/{seed,email_osint,username_osint,phone_osint,\
domain_osint/{whois,dns,subdomains,harvester,certs,urls},\
ip_osint/{whois,reverse_dns,asn,nmap},\
network_osint,address_osint,pivot,maltego,burp,recon_ng,spiderfoot,raw}

    local f="${OUTDIR}/seed"
    (IFS=$'\n'; [[ ${#EMAILS[@]}    -gt 0 ]] && printf '%s\n' "${EMAILS[@]}"    > "${f}/emails.txt")
    (IFS=$'\n'; [[ ${#PHONES[@]}    -gt 0 ]] && printf '%s\n' "${PHONES[@]}"    > "${f}/phones.txt")
    (IFS=$'\n'; [[ ${#USERNAMES[@]} -gt 0 ]] && printf '%s\n' "${USERNAMES[@]}" > "${f}/usernames.txt")
    (IFS=$'\n'; [[ ${#FULLNAMES[@]} -gt 0 ]] && printf '%s\n' "${FULLNAMES[@]}" > "${f}/fullnames.txt")
    (IFS=$'\n'; [[ ${#DOMAINS[@]}   -gt 0 ]] && printf '%s\n' "${DOMAINS[@]}"   > "${f}/domains.txt")
    (IFS=$'\n'; [[ ${#IPS[@]}       -gt 0 ]] && printf '%s\n' "${IPS[@]}"       > "${f}/ip_addresses.txt")
    (IFS=$'\n'; [[ ${#ADDRESSES[@]} -gt 0 ]] && printf '%s\n' "${ADDRESSES[@]}" > "${f}/physical_addresses.txt")
    (IFS=$'\n'; [[ ${#MACS[@]}      -gt 0 ]] && printf '%s\n' "${MACS[@]}"      > "${f}/mac_addresses.txt")
    (IFS=$'\n'; [[ ${#SSIDS[@]}     -gt 0 ]] && printf '%s\n' "${SSIDS[@]}"     > "${f}/ssids.txt")
    [[ -n "$NOTES" ]] && echo "$NOTES" > "${f}/notes.txt"

    log "Investigation started: ${INVESTIGATION_NAME}  |  depth: ${MAX_DEPTH}"
    log "Investigator: ${INVESTIGATOR}  |  Case: ${CASE_NUMBER:-none}"
}

select_phases() {
    (( ${#EMAILS[@]}    > 0 )) && RUN_EMAIL=true
    (( ${#USERNAMES[@]} > 0 )) && RUN_USERNAME=true
    (( ${#PHONES[@]}    > 0 )) && RUN_PHONE=true
    (( ${#FULLNAMES[@]} > 0 )) && RUN_FULLNAME=true
    (( ${#DOMAINS[@]}   > 0 )) && RUN_DOMAIN=true
    (( ${#IPS[@]}       > 0 )) && RUN_IP=true
    (( ${#MACS[@]} > 0 || ${#SSIDS[@]} > 0 )) && RUN_NETWORK=true
    (( ${#ADDRESSES[@]} > 0 )) && RUN_ADDRESS=true
}

# Mark all seed entities as known at depth 0
mark_seed_known() {
    for e in "${EMAILS[@]+"${EMAILS[@]}"}";    do mark_known email    "$e"; done
    for p in "${PHONES[@]+"${PHONES[@]}"}";    do mark_known phone    "$p"; done
    for u in "${USERNAMES[@]+"${USERNAMES[@]}"}"; do mark_known username "$u"; done
    for n in "${FULLNAMES[@]+"${FULLNAMES[@]}"}"; do mark_known name     "$n"; done
    for d in "${DOMAINS[@]+"${DOMAINS[@]}"}";  do mark_known domain   "$d"; done
    for i in "${IPS[@]+"${IPS[@]}"}";          do mark_known ip       "$i"; done
    for a in "${ADDRESSES[@]+"${ADDRESSES[@]}"}"; do mark_known address  "$a"; done
    for m in "${MACS[@]+"${MACS[@]}"}";        do mark_known mac      "$m"; done
    for s in "${SSIDS[@]+"${SSIDS[@]}"}";      do mark_known ssid     "$s"; done
}


# ════════════════════════════════════════════════════════════════════════════
#  ATOMIC INVESTIGATION FUNCTIONS
#  Each function investigates a single entity and writes output to $outdir.
#  Used by both the main phases and the pivot engine.
# ════════════════════════════════════════════════════════════════════════════

investigate_email() {
    local email="$1" outdir="$2"
    local safe_e="${email//[@.]/_}"
    local domain="${email#*@}"

    if has_tool holehe; then
        holehe "$email" --only-used --no-color 2>/dev/null \
            > "${outdir}/holehe_${safe_e}.txt" || true
        local hits
        hits="$(grep -c '^\[+\]' "${outdir}/holehe_${safe_e}.txt" 2>/dev/null || echo 0)"
        ok "holehe: ${hits} services  [${email}]"
    fi

    {
        echo "=== MX ==="; dig +short MX "$domain" 2>/dev/null || true
        echo "=== A ===";  dig +short A  "$domain" 2>/dev/null || true
        echo "=== TXT ==="; dig +short TXT "$domain" 2>/dev/null || true
    } > "${outdir}/dns_${safe_e}.txt"

    whois "$domain" 2>/dev/null > "${outdir}/whois_${safe_e}.txt" || true

    if python3 -m theHarvester --help &>/dev/null 2>&1; then
        python3 -m theHarvester -d "$domain" -b all \
            -f "${outdir}/harvester_${safe_e}" 2>/dev/null \
            > "${outdir}/harvester_${safe_e}.txt" || true
        ok "theHarvester → harvester_${safe_e}.txt  [${domain}]"
    fi

    # emailrep.io — reputation, fraud signal, known profiles (no key for basic)
    curl -s --max-time 10 "https://emailrep.io/${email}" \
        -H "User-Agent: osint.sh/${VERSION}" 2>/dev/null \
        | jq '{reputation: .reputation, suspicious: .suspicious, references: .references, details: {blacklisted: .details.blacklisted, malicious_activity: .details.malicious_activity, credentials_leaked: .details.credentials_leaked, profiles: .details.profiles, last_seen: .details.last_seen, days_since_domain_creation: .details.days_since_domain_creation}}' \
        2>/dev/null > "${outdir}/emailrep_${safe_e}.json" || true
    local erep_rep
    erep_rep="$(jq -r '.reputation // "unknown"' "${outdir}/emailrep_${safe_e}.json" 2>/dev/null || echo 'unknown')"
    local erep_sus
    erep_sus="$(jq -r '.suspicious // "?"' "${outdir}/emailrep_${safe_e}.json" 2>/dev/null || echo '?')"
    ok "emailrep.io: reputation=${erep_rep} suspicious=${erep_sus}  [${email}]"

    # hunter.io email verifier — SMTP deliverability + disposable/webmail classification
    local hunter_key="${HUNTER_API_KEY:-}"
    if [[ -n "$hunter_key" ]]; then
        curl -s --max-time 15 \
            "https://api.hunter.io/v2/email-verifier?email=${email}&api_key=${hunter_key}" \
            2>/dev/null | jq '{result: .data.result, score: .data.score, disposable: .data.disposable, webmail: .data.webmail, accept_all: .data.accept_all, smtp_server: .data.smtp_server, smtp_check: .data.smtp_check}' \
            2>/dev/null > "${outdir}/hunter_verify_${safe_e}.json" || true
        local h_result
        h_result="$(jq -r '.result // "unknown"' "${outdir}/hunter_verify_${safe_e}.json" 2>/dev/null || echo 'unknown')"
        local h_score
        h_score="$(jq -r '.score // "?"' "${outdir}/hunter_verify_${safe_e}.json" 2>/dev/null || echo '?')"
        ok "hunter.io: result=${h_result} score=${h_score}  [${email}]"
    fi

    # viewdns.info reverse WHOIS by email — finds all domains registered with this email
    local vdns_key="${VIEWDNS_API_KEY:-}"
    if [[ -n "$vdns_key" ]]; then
        curl -s --max-time 15 \
            "https://api.viewdns.info/reversewhois/?q=${email}&apikey=${vdns_key}&output=json" \
            2>/dev/null | jq '.' 2>/dev/null \
            > "${outdir}/viewdns_reversewhois_${safe_e}.json" || true
        local vdns_count
        vdns_count="$(jq '.query.count // 0' "${outdir}/viewdns_reversewhois_${safe_e}.json" 2>/dev/null || echo 0)"
        ok "viewdns.info reverse WHOIS: ${vdns_count} domains  [${email}]"
    fi

    # WhoisXML reverse WHOIS by email
    local wxl_key="${WHOISXML_API_KEY:-}"
    if [[ -n "$wxl_key" ]]; then
        curl -s --max-time 15 \
            "https://reverse-whois.whoisxmlapi.com/api/v2" \
            -H "Content-Type: application/json" \
            -d "{\"apiKey\":\"${wxl_key}\",\"searchType\":\"current\",\"basicSearchTerms\":{\"include\":[\"${email}\"]}}" \
            2>/dev/null | jq '{domainCount: .domainsCount, domains: .domainsList}' 2>/dev/null \
            > "${outdir}/whoisxml_reversewhois_${safe_e}.json" || true
        local wxl_count
        wxl_count="$(jq '.domainCount // 0' "${outdir}/whoisxml_reversewhois_${safe_e}.json" 2>/dev/null || echo 0)"
        ok "WhoisXML reverse WHOIS: ${wxl_count} domains  [${email}]"
    fi

    # GitHub code search — find email in public repos/configs
    local gh_token="${GITHUB_TOKEN:-}"
    if [[ -n "$gh_token" ]]; then
        curl -s --max-time 15 \
            "https://api.github.com/search/code?q=${email}+in:file&per_page=10" \
            -H "Authorization: token ${gh_token}" \
            -H "Accept: application/vnd.github.v3+json" 2>/dev/null \
            | jq '{total_count: .total_count, items: [.items[]? | {repo: .repository.full_name, path: .path, url: .html_url}]}' \
            2>/dev/null > "${outdir}/github_${safe_e}.json" || true
        local gh_count
        gh_count="$(jq '.total_count // 0' "${outdir}/github_${safe_e}.json" 2>/dev/null || echo 0)"
        ok "GitHub code search: ${gh_count} hits  [${email}]"
    fi

    # GHunt — Google account OSINT (profile, maps, calendar, photos)
    if has_tool ghunt; then
        ghunt email "$email" --json "${outdir}/ghunt_${safe_e}.json" 2>/dev/null || true
        local gname
        gname="$(jq -r '.name // "not found"' "${outdir}/ghunt_${safe_e}.json" 2>/dev/null || echo 'not found')"
        ok "GHunt: name=${gname}  [${email}]"
    fi

    # Stage 3: breach data + IntelX
    investigate_email_breach "$email" "$outdir"
}

investigate_username() {
    local uname="$1" outdir="$2"

    if [[ -x "$MAIGRET_BIN" ]]; then
        mkdir -p "${outdir}/maigret_${uname}"
        # Note: site names with spaces must be quoted individually — maigret parses comma-separated list
        local _maigret_sites="Twitter,Instagram,TikTok,Facebook,LinkedIn,YouTube,Reddit,GitHub,Discord,Twitch,Snapchat,Pinterest,Nextdoor,Telegram,BeReal,Mastodon,Bluesky,MySpace,Spotify,Pandora,Lastfm,Flickr,Quora,Medium,Tumblr,Yelp,Patreon,Bitbucket,GitLab,SourceForge,StackOverflow,HackerNews,Vimeo,DeviantArt,Letterboxd,Goodreads,Wattpad,Roblox,ProductHunt,Dribbble,Behance,Etsy,Kickstarter"
        "$MAIGRET_BIN" "$uname" \
            --folderoutput "${outdir}/maigret_${uname}" \
            --sites "$_maigret_sites" \
            --timeout 10 2>/dev/null || true
        ok "maigret done  [${uname}] (USA mainstream only)"
    fi

    if [[ -f /usr/share/whatsmyname/whats_my_name.py ]]; then
        python3 /usr/share/whatsmyname/whats_my_name.py \
            -u "$uname" \
            -o "${outdir}/whatsmyname_${uname}.txt" \
            -t 30 2>/dev/null || true
        local wmn_hits
        wmn_hits="$(wc -l < "${outdir}/whatsmyname_${uname}.txt" 2>/dev/null || echo 0)"
        ok "whatsmyname: ${wmn_hits} profiles  [${uname}]"
    fi
}

investigate_phone() {
    local phone="$1" outdir="$2"
    local safe_p="${phone//[^0-9]/_}"

    if has_tool phoneinfoga; then
        phoneinfoga scan -n "$phone" 2>/dev/null \
            > "${outdir}/phoneinfoga_${safe_p}.txt" || true
        ok "phoneinfoga done  [${phone}]"
    fi

    # numverify — carrier, line type (mobile/landline/voip), country, location
    # Auto-prepend +1 for bare 10-digit North American numbers
    local numv_key="${NUMVERIFY_API_KEY:-}"
    if [[ -n "$numv_key" ]]; then
        local numv_phone="$phone"
        [[ "$numv_phone" =~ ^[0-9]{10}$ ]] && numv_phone="+1${numv_phone}"
        curl -s --max-time 10 \
            "https://apilayer.net/api/validate?access_key=${numv_key}&number=${numv_phone}&format=1" \
            2>/dev/null | jq '{valid: .valid, number: .number, local_format: .local_format, international_format: .international_format, country: .country_name, location: .location, carrier: .carrier, line_type: .line_type}' \
            2>/dev/null > "${outdir}/carrier_${safe_p}.json" || true
        local carrier
        carrier="$(jq -r '.carrier // "unknown"' "${outdir}/carrier_${safe_p}.json" 2>/dev/null || echo 'unknown')"
        local line_type
        line_type="$(jq -r '.line_type // "unknown"' "${outdir}/carrier_${safe_p}.json" 2>/dev/null || echo 'unknown')"
        ok "numverify: carrier=${carrier} type=${line_type}  [${phone}]"
    else
        warn "NUMVERIFY_API_KEY not set — carrier lookup skipped  [${phone}]"
    fi
}

investigate_domain() {
    local domain="$1" outdir="$2"
    local safe_d="${domain//[^a-zA-Z0-9_-]/_}"

    whois "$domain" 2>/dev/null > "${outdir}/whois/${safe_d}.txt" || true
    ok "WHOIS done  [${domain}]"

    {
        for rtype in A AAAA MX NS TXT CNAME SOA; do
            echo "=== ${rtype} ==="
            dig +short "$rtype" "$domain" 2>/dev/null || true
        done
    } > "${outdir}/dns/${safe_d}_records.txt"

    curl -s --max-time 15 "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null | sort -u \
        > "${outdir}/certs/${safe_d}_ct.txt" || true

    local sf="$SUBFINDER_BIN"
    has_tool subfinder && sf="subfinder"
    if [[ -x "$sf" ]] || has_tool subfinder; then
        ${sf} -d "$domain" -silent 2>/dev/null \
            > "${outdir}/subdomains/${safe_d}_subfinder.txt" || true
    fi

    if python3 -c "import theHarvester" 2>/dev/null; then
        mkdir -p "${outdir}/harvester"
        python3 -m theHarvester -d "$domain" -b all \
            -f "${outdir}/harvester/${safe_d}" 2>/dev/null \
            > "${outdir}/harvester/${safe_d}.txt" || true
        ok "theHarvester done  [${domain}]"
    fi

    if has_tool gau; then
        mkdir -p "${outdir}/urls"
        gau "$domain" 2>/dev/null | head -1000 \
            > "${outdir}/urls/${safe_d}_gau.txt" || true
    fi

    nmap -T3 --top-ports 100 -sV --script=http-title,ssl-cert \
        "$domain" 2>/dev/null > "${outdir}/${safe_d}_nmap.txt" || true
    ok "nmap done  [${domain}]"

    cat "${outdir}/subdomains/${safe_d}_subfinder.txt" \
        "${outdir}/certs/${safe_d}_ct.txt" 2>/dev/null \
        | sort -u > "${outdir}/subdomains/${safe_d}_all.txt" || true

    # HackerTarget hostsearch — all subdomains + IPs for this domain (free, no key)
    mkdir -p "${outdir}/passive"
    curl -s --max-time 15 \
        "https://api.hackertarget.com/hostsearch/?q=${domain}" 2>/dev/null \
        > "${outdir}/passive/${safe_d}_hostsearch.txt" || true
    local ht_count
    ht_count="$(grep -vc '^$\|error\|API count' "${outdir}/passive/${safe_d}_hostsearch.txt" 2>/dev/null || echo 0)"
    ok "HackerTarget hostsearch: ${ht_count} hosts  [${domain}]"
    sleep 1

    # HackerTarget reverse NS — all domains sharing each nameserver of this domain
    local ns_list
    ns_list="$(dig +short NS "$domain" 2>/dev/null | head -4)"
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        local safe_ns="${ns//[^a-zA-Z0-9_-]/_}"
        curl -s --max-time 20 \
            "https://api.hackertarget.com/reverseiplookup/?q=${ns}" 2>/dev/null \
            > "${outdir}/passive/${safe_d}_ns_${safe_ns}_customers.txt" || true
        local ns_count
        ns_count="$(grep -vc '^$\|error\|API count\|no record' "${outdir}/passive/${safe_d}_ns_${safe_ns}_customers.txt" 2>/dev/null || echo 0)"
        ok "HackerTarget reverse NS (${ns}): ${ns_count} customer domains"
        sleep 1
    done <<< "$ns_list"

    # WHOIS history (viewdns.info) — owner changes, historical contacts
    local vdns_key="${VIEWDNS_API_KEY:-}"
    if [[ -n "$vdns_key" ]]; then
        curl -s --max-time 15 \
            "https://api.viewdns.info/whoishistory/?domain=${domain}&apikey=${vdns_key}&output=json" \
            2>/dev/null | jq '.' 2>/dev/null \
            > "${outdir}/passive/${safe_d}_viewdns_whoishistory.json" || true
        ok "viewdns.info WHOIS history done  [${domain}]"
    fi

    # WhoisXML WHOIS + history
    local wxl_key="${WHOISXML_API_KEY:-}"
    if [[ -n "$wxl_key" ]]; then
        curl -s --max-time 15 \
            "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${wxl_key}&domainName=${domain}&outputFormat=JSON" \
            2>/dev/null | jq '.' 2>/dev/null \
            > "${outdir}/passive/${safe_d}_whoisxml.json" || true
        curl -s --max-time 15 \
            "https://whois-history.whoisxmlapi.com/api/v1?apiKey=${wxl_key}&domainName=${domain}&outputFormat=JSON" \
            2>/dev/null | jq '{records: [.records[]? | {createdDate: .createdDate, updatedDate: .updatedDate, registrantName: .registrantContact.name, registrantEmail: .registrantContact.email, registrantOrg: .registrantContact.organization}]}' \
            2>/dev/null > "${outdir}/passive/${safe_d}_whoisxml_history.json" || true
        ok "WhoisXML WHOIS + history done  [${domain}]"
    fi

    # SecurityTrails DNS history — shows when A records changed (tracks IP hops)
    local st_key="${SECURITYTRAILS_API_KEY:-}"
    if [[ -n "$st_key" ]]; then
        curl -s --max-time 15 \
            "https://api.securitytrails.com/v1/history/${domain}/dns/a" \
            -H "APIKEY: ${st_key}" 2>/dev/null \
            | jq '{pages: .pages, records: [.records[]? | {first_seen: .first_seen, last_seen: .last_seen, values: [.values[]?.ip]}]}' \
            2>/dev/null > "${outdir}/passive/${safe_d}_st_dns_history.json" || true
        ok "SecurityTrails DNS history done  [${domain}]"
    fi

    # hunter.io domain search — all public emails for this domain + org pattern
    local hunter_key="${HUNTER_API_KEY:-}"
    if [[ -n "$hunter_key" ]]; then
        curl -s --max-time 15 \
            "https://api.hunter.io/v2/domain-search?domain=${domain}&limit=100&api_key=${hunter_key}" \
            2>/dev/null | jq '{organization: .data.organization, pattern: .data.pattern, total_emails: .meta.total, emails: [.data.emails[]? | {email: .value, type: .type, confidence: .confidence, first_name: .first_name, last_name: .last_name, position: .position, linkedin: .linkedin}]}' \
            2>/dev/null > "${outdir}/passive/${safe_d}_hunter.json" || true
        local h_total
        h_total="$(jq '.total_emails // 0' "${outdir}/passive/${safe_d}_hunter.json" 2>/dev/null || echo 0)"
        local h_pattern
        h_pattern="$(jq -r '.pattern // "unknown"' "${outdir}/passive/${safe_d}_hunter.json" 2>/dev/null || echo 'unknown')"
        ok "hunter.io: ${h_total} email(s) found, pattern=${h_pattern}  [${domain}]"
    fi

    # urlscan.io — search existing scans for this domain (tech stack, IPs, redirects)
    local urlscan_key="${URLSCAN_API_KEY:-}"
    if [[ -n "$urlscan_key" ]]; then
        # Search existing scan history first (no credit cost)
        curl -s --max-time 15 \
            "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10" \
            -H "API-Key: ${urlscan_key}" 2>/dev/null \
            | jq '{total: .total, results: [.results[]? | {url: .page.url, ip: .page.ip, country: .page.country, server: .page.server, date: .task.time, screenshot: .screenshot, uuid: .task.uuid}]}' \
            2>/dev/null > "${outdir}/passive/${safe_d}_urlscan_history.json" || true
        local us_total
        us_total="$(jq '.total // 0' "${outdir}/passive/${safe_d}_urlscan_history.json" 2>/dev/null || echo 0)"
        ok "urlscan.io history: ${us_total} existing scan(s)  [${domain}]"

        # Submit a fresh scan (unlisted visibility — not public)
        local scan_resp
        scan_resp="$(curl -s --max-time 15 -X POST "https://urlscan.io/api/v1/scan/" \
            -H "API-Key: ${urlscan_key}" -H "Content-Type: application/json" \
            -d "{\"url\":\"https://${domain}\",\"visibility\":\"unlisted\"}" 2>/dev/null)"
        local scan_uuid
        scan_uuid="$(echo "$scan_resp" | jq -r '.uuid // empty' 2>/dev/null)"
        if [[ -n "$scan_uuid" ]]; then
            echo "$scan_uuid" > "${outdir}/passive/${safe_d}_urlscan_uuid.txt"
            ok "urlscan.io scan submitted (uuid=${scan_uuid}) — retrieve result in ~30s"
            sleep 35
            curl -s --max-time 15 \
                "https://urlscan.io/api/v1/result/${scan_uuid}/" \
                -H "API-Key: ${urlscan_key}" 2>/dev/null \
                | jq '{url: .page.url, ip: .page.ip, country: .page.country, server: .page.server, asn: .page.asn, asnname: .page.asnname, technologies: [.meta.processors.wappa.data[]?.app], certificates: [.lists.certificates[]? | {subject: .subjectName, issuer: .issuer, validTo: .validTo}], ips: .lists.ips, hashes: .lists.hashes[0:5], screenshot: .screenshot}' \
                2>/dev/null > "${outdir}/passive/${safe_d}_urlscan_result.json" || true
            local us_server
            us_server="$(jq -r '.server // "unknown"' "${outdir}/passive/${safe_d}_urlscan_result.json" 2>/dev/null || echo 'unknown')"
            local us_techs
            us_techs="$(jq -r '[.technologies[]?] | join(", ")' "${outdir}/passive/${safe_d}_urlscan_result.json" 2>/dev/null || echo 'none detected')"
            ok "urlscan.io result: server=${us_server} tech=[${us_techs}]  [${domain}]"
        fi
    fi

    # Wayback Machine CDX — free, no key, shows historical snapshots + status codes
    curl -s --max-time 15 \
        "https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=json&limit=20&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&filter=statuscode:200" \
        2>/dev/null | jq '[.[] | select(.[0] != "timestamp") | {timestamp: .[0], url: .[1], status: .[2], type: .[3]}]' \
        2>/dev/null > "${outdir}/passive/${safe_d}_wayback.json" || true
    local wb_count
    wb_count="$(jq 'length' "${outdir}/passive/${safe_d}_wayback.json" 2>/dev/null || echo 0)"
    ok "Wayback CDX: ${wb_count} snapshots  [${domain}]"

    # IntelX — breach/leak metadata for this domain
    if [[ -n "${INTELX_API_KEY:-}" ]]; then
        intelx_search "$domain" "${outdir}/passive/${safe_d}_intelx.json"
        local ix_total
        ix_total="$(jq '.total // 0' "${outdir}/passive/${safe_d}_intelx.json" 2>/dev/null || echo 0)"
        ok "IntelX: ${ix_total} result(s)  [${domain}]"
        sleep 1
    fi

    # GitHub code search — find domain in public repos (config leaks, secrets)
    local gh_token="${GITHUB_TOKEN:-}"
    if [[ -n "$gh_token" ]]; then
        curl -s --max-time 15 \
            "https://api.github.com/search/code?q=${domain}+in:file&per_page=10" \
            -H "Authorization: token ${gh_token}" \
            -H "Accept: application/vnd.github.v3+json" 2>/dev/null \
            | jq '{total_count: .total_count, items: [.items[]? | {repo: .repository.full_name, path: .path, url: .html_url}]}' \
            2>/dev/null > "${outdir}/passive/${safe_d}_github.json" || true
        local gh_count
        gh_count="$(jq '.total_count // 0' "${outdir}/passive/${safe_d}_github.json" 2>/dev/null || echo 0)"
        ok "GitHub code search: ${gh_count} hits  [${domain}]"
    fi
}

# Lighter domain scan for pivot passes (no nmap, no gau, no theHarvester)
investigate_domain_light() {
    local domain="$1" outdir="$2"
    local safe_d="${domain//[^a-zA-Z0-9_-]/_}"

    whois "$domain" 2>/dev/null > "${outdir}/whois/${safe_d}.txt" || true

    {
        for rtype in A MX NS TXT; do
            echo "=== ${rtype} ==="
            dig +short "$rtype" "$domain" 2>/dev/null || true
        done
    } > "${outdir}/dns/${safe_d}_records.txt"

    curl -s --max-time 10 "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null | sort -u \
        > "${outdir}/certs/${safe_d}_ct.txt" || true

    local sf="$SUBFINDER_BIN"
    has_tool subfinder && sf="subfinder"
    if [[ -x "$sf" ]] || has_tool subfinder; then
        ${sf} -d "$domain" -silent 2>/dev/null \
            > "${outdir}/subdomains/${safe_d}_subfinder.txt" || true
    fi

    cat "${outdir}/subdomains/${safe_d}_subfinder.txt" \
        "${outdir}/certs/${safe_d}_ct.txt" 2>/dev/null \
        | sort -u > "${outdir}/subdomains/${safe_d}_all.txt" || true

    # HackerTarget hostsearch + reverse NS (free — key pivot for infrastructure mapping)
    mkdir -p "${outdir}/passive"
    curl -s --max-time 15 \
        "https://api.hackertarget.com/hostsearch/?q=${domain}" 2>/dev/null \
        > "${outdir}/passive/${safe_d}_hostsearch.txt" || true
    sleep 1
    local ns_list
    ns_list="$(dig +short NS "$domain" 2>/dev/null | head -4)"
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        local safe_ns="${ns//[^a-zA-Z0-9_-]/_}"
        curl -s --max-time 20 \
            "https://api.hackertarget.com/reverseiplookup/?q=${ns}" 2>/dev/null \
            > "${outdir}/passive/${safe_d}_ns_${safe_ns}_customers.txt" || true
        sleep 1
    done <<< "$ns_list"

    # Wayback CDX at pivot depth
    curl -s --max-time 15 \
        "https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=json&limit=10&fl=timestamp,original,statuscode&collapse=urlkey&filter=statuscode:200" \
        2>/dev/null | jq '[.[] | select(.[0] != "timestamp") | {timestamp: .[0], url: .[1], status: .[2]}]' \
        2>/dev/null > "${outdir}/passive/${safe_d}_wayback.json" || true

    # IntelX search at pivot depth
    if [[ -n "${INTELX_API_KEY:-}" ]]; then
        intelx_search "$domain" "${outdir}/passive/${safe_d}_intelx.json"
        sleep 1
    fi

    ok "Light domain scan done  [${domain}]"
}

investigate_ip() {
    local ip="$1" outdir="$2"
    local safe_i="${ip//./_}"

    whois "$ip" 2>/dev/null > "${outdir}/whois/${safe_i}.txt" || true
    dig +short -x "$ip" 2>/dev/null > "${outdir}/reverse_dns/${safe_i}_rdns.txt" || true

    curl -s --max-time 8 "https://ipinfo.io/${ip}/json" 2>/dev/null \
        | jq '.' 2>/dev/null > "${outdir}/asn/${safe_i}_ipinfo.json" || true
    ok "ASN/geo done  [${ip}]"

    nmap -T3 --top-ports 1000 -sV --script=http-title,ssl-cert,banner \
        "$ip" 2>/dev/null > "${outdir}/nmap/${safe_i}_nmap.txt" || true
    ok "nmap done  [${ip}]"

    if has_tool shodan; then
        local key
        key="$(shodan info 2>/dev/null | grep 'API Key' | awk '{print $NF}')" || true
        if [[ -n "$key" ]]; then
            shodan host "$ip" 2>/dev/null > "${outdir}/nmap/${safe_i}_shodan.txt" || true
        fi
    fi

    # Stage 3: passive DNS + reputation
    investigate_ip_passive "$ip" "$outdir"
}

# Lighter IP scan for pivot passes (no nmap)
investigate_ip_light() {
    local ip="$1" outdir="$2"
    local safe_i="${ip//./_}"

    whois "$ip" 2>/dev/null > "${outdir}/whois/${safe_i}.txt" || true
    dig +short -x "$ip" 2>/dev/null > "${outdir}/reverse_dns/${safe_i}_rdns.txt" || true
    curl -s --max-time 8 "https://ipinfo.io/${ip}/json" 2>/dev/null \
        | jq '.' 2>/dev/null > "${outdir}/asn/${safe_i}_ipinfo.json" || true
    investigate_ip_passive "$ip" "$outdir"
    ok "IP light scan done  [${ip}]"
}

# ── Stage 3: Passive DNS / reputation lookups for IPs ───────────────────────
investigate_ip_passive() {
    local ip="$1" outdir="$2"
    local safe_i="${ip//./_}"
    local d="${outdir}/passive"
    mkdir -p "$d"

    # HackerTarget reverse IP — free, no key needed
    curl -s --max-time 10 \
        "https://api.hackertarget.com/reverseiplookup/?q=${ip}" 2>/dev/null \
        > "${d}/${safe_i}_reverseip.txt" || true
    local count
    count="$(grep -vc '^$\|error\|API count\|no record' "${d}/${safe_i}_reverseip.txt" 2>/dev/null || echo 0)"
    ok "Passive DNS (HackerTarget): ${count} domains  [${ip}]"
    sleep 1

    # Shodan REST API — ports, banners, vuln tags, hostnames (passive — no scan)
    local shodan_key="${SHODAN_API_KEY:-}"
    if [[ -n "$shodan_key" ]]; then
        curl -s --max-time 15 \
            "https://api.shodan.io/shodan/host/${ip}?key=${shodan_key}" 2>/dev/null \
            | jq '{org: .org, isp: .isp, country: .country_name, city: .city, asn: .asn, ports: .ports, hostnames: .hostnames, domains: .domains, tags: .tags, vulns: (.vulns // {} | keys), last_update: .last_update}' \
            2>/dev/null > "${d}/${safe_i}_shodan.json" || true
        local shodan_ports
        shodan_ports="$(jq '.ports | join(",")' "${d}/${safe_i}_shodan.json" 2>/dev/null || echo 'n/a')"
        local shodan_vulns
        shodan_vulns="$(jq '.vulns | length' "${d}/${safe_i}_shodan.json" 2>/dev/null || echo 0)"
        ok "Shodan: ports=[${shodan_ports}] vulns=${shodan_vulns}  [${ip}]"
    else
        warn "SHODAN_API_KEY not set — Shodan REST skipped  [${ip}]"
    fi

    # CriminalIP — threat score, proxy/VPN detection, abuse record
    local criminalip_key="${CRIMINALIP_API_KEY:-}"
    if [[ -n "$criminalip_key" ]]; then
        curl -s --max-time 15 \
            "https://api.criminalip.io/v1/asset/ip/report?ip=${ip}" \
            -H "x-api-key: ${criminalip_key}" 2>/dev/null \
            | jq '{score: .ip_scoring, is_vpn: .is_vpn, is_proxy: .is_proxy, is_tor: .is_tor, is_hosting: .is_hosting, country: .country, abuse_record_count: (.abuse_record.count // 0), tags: [.tags[]?.name]}' \
            2>/dev/null > "${d}/${safe_i}_criminalip.json" || true
        local cip_score
        cip_score="$(jq -r '.score // "unknown"' "${d}/${safe_i}_criminalip.json" 2>/dev/null || echo 'unknown')"
        local cip_proxy
        cip_proxy="$(jq -r 'if .is_vpn or .is_proxy or .is_tor then "VPN/PROXY/TOR" else "clean" end' "${d}/${safe_i}_criminalip.json" 2>/dev/null || echo 'unknown')"
        ok "CriminalIP: score=${cip_score} anonymizer=${cip_proxy}  [${ip}]"
    else
        warn "CRIMINALIP_API_KEY not set — CriminalIP skipped  [${ip}]"
    fi

    # GreyNoise — classify as scanner/noise/malicious vs targeted (free community tier)
    local gn_key="${GREYNOISE_API_KEY:-}"
    if [[ -n "$gn_key" ]]; then
        curl -s --max-time 10 \
            "https://api.greynoise.io/v3/community/${ip}" \
            -H "key: ${gn_key}" 2>/dev/null \
            | jq '{classification: .classification, name: .name, last_seen: .last_seen, noise: .noise, riot: .riot, message: .message}' \
            2>/dev/null > "${d}/${safe_i}_greynoise.json" || true
        local gn_class
        gn_class="$(jq -r '.classification // .message // "unknown"' "${d}/${safe_i}_greynoise.json" 2>/dev/null || echo 'unknown')"
        ok "GreyNoise: classification=${gn_class}  [${ip}]"
    else
        # GreyNoise community endpoint — works without key, limited response
        local gn_url="${GREYNOISE_COMMUNITY_URL:-https://api.greynoise.io/v3/community}"
        curl -s --max-time 10 "${gn_url}/${ip}" 2>/dev/null \
            | jq '{riot: .riot, classification: .classification, message: .message}' 2>/dev/null \
            > "${d}/${safe_i}_greynoise.json" || true
        ok "GreyNoise community  [${ip}]"
    fi

    # SecurityTrails nearby IPs — passive DNS, other IPs in same subnet
    local st_key="${SECURITYTRAILS_API_KEY:-}"
    if [[ -n "$st_key" ]]; then
        curl -s --max-time 15 \
            "https://api.securitytrails.com/v1/ips/nearby/${ip}" \
            -H "APIKEY: ${st_key}" 2>/dev/null \
            | jq '{blocks: [.blocks[]? | {cidr: .cidr, hostnames: .hostnames[0:5]}]}' \
            2>/dev/null > "${d}/${safe_i}_st_nearby.json" || true
        ok "SecurityTrails nearby IPs done  [${ip}]"
    fi

    # RIPE stat abuse contact finder — auto-resolve correct abuse@ for EU/global IPs
    curl -s --max-time 10 \
        "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${ip}" 2>/dev/null \
        | jq '{abuse_contacts: .data.abuse_contacts, anti_abuse_contacts: .data.anti_abuse_contacts}' \
        2>/dev/null > "${d}/${safe_i}_ripe_abuse.json" || true
    local ripe_contact
    ripe_contact="$(jq -r '.abuse_contacts[0] // "not found"' "${d}/${safe_i}_ripe_abuse.json" 2>/dev/null || echo 'not found')"
    ok "RIPE abuse contact: ${ripe_contact}  [${ip}]"

    # AbuseIPDB reputation (if API key set)
    local abuse_key="${ABUSEIPDB_API_KEY:-}"
    if [[ -n "$abuse_key" ]]; then
        curl -s --max-time 10 \
            "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose" \
            -H "Key: ${abuse_key}" -H "Accept: application/json" 2>/dev/null \
            | jq '{abuseConfidenceScore: .data.abuseConfidenceScore, totalReports: .data.totalReports, isp: .data.isp, usageType: .data.usageType, domain: .data.domain, countryCode: .data.countryCode, isWhitelisted: .data.isWhitelisted}' \
            2>/dev/null > "${d}/${safe_i}_abuseipdb.json" || true
        local abuse_score
        abuse_score="$(jq '.abuseConfidenceScore // 0' "${d}/${safe_i}_abuseipdb.json" 2>/dev/null || echo 0)"
        ok "AbuseIPDB: confidence=${abuse_score}%  [${ip}]"
    fi

    # urlscan.io — search all scans that loaded from this IP (shows what sites it served)
    local urlscan_key="${URLSCAN_API_KEY:-}"
    if [[ -n "$urlscan_key" ]]; then
        curl -s --max-time 15 \
            "https://urlscan.io/api/v1/search/?q=ip:${ip}&size=20" \
            -H "API-Key: ${urlscan_key}" 2>/dev/null \
            | jq '{total: .total, sites: [.results[]? | {url: .page.url, domain: .page.domain, date: .task.time, country: .page.country}] | unique_by(.domain)}' \
            2>/dev/null > "${d}/${safe_i}_urlscan.json" || true
        local us_total
        us_total="$(jq '.total // 0' "${d}/${safe_i}_urlscan.json" 2>/dev/null || echo 0)"
        ok "urlscan.io: ${us_total} scan(s) from this IP  [${ip}]"
    fi

    # IntelX — leak/paste/breach mentions of this IP
    if [[ -n "${INTELX_API_KEY:-}" ]]; then
        intelx_search "$ip" "${d}/${safe_i}_intelx.json"
        local ix_total
        ix_total="$(jq '.total // 0' "${d}/${safe_i}_intelx.json" 2>/dev/null || echo 0)"
        ok "IntelX: ${ix_total} result(s)  [${ip}]"
        sleep 1
    fi

    # Manual lookup reference file — open these in a browser for deeper passive recon
    {
        echo "=== Passive / Historical Lookups for ${ip} ==="
        echo ""
        echo "[ Passive DNS — historically hosted domains ]"
        echo "  ViewDNS Reverse IP   : https://viewdns.info/reverseip/?host=${ip}"
        echo "  SecurityTrails       : https://securitytrails.com/list/ip/${ip}"
        echo "  RiskIQ (Defender)    : https://community.riskiq.com/search/${ip}"
        echo ""
        echo "[ Threat Intelligence ]"
        echo "  Shodan               : https://www.shodan.io/host/${ip}"
        echo "  Censys               : https://search.censys.io/hosts/${ip}"
        echo "  GreyNoise            : https://viz.greynoise.io/ip/${ip}"
        echo "  VirusTotal           : https://www.virustotal.com/gui/ip-address/${ip}"
        echo "  AbuseIPDB            : https://www.abuseipdb.com/check/${ip}"
        echo "  ThreatFox            : https://threatfox.abuse.ch/browse.php?search=ioc%3A${ip}"
        echo ""
        echo "[ Geolocation / ISP ]"
        echo "  IPinfo               : https://ipinfo.io/${ip}"
        echo "  ip-api               : http://ip-api.com/json/${ip}"
        echo "  MaxMind              : https://www.maxmind.com/en/geoip-demo"
    } > "${d}/${safe_i}_manual_lookups.txt"
}

# ── Stage 3: Breach / leak data for emails ──────────────────────────────────
investigate_email_breach() {
    local email="$1" outdir="$2"
    local safe_e="${email//[@.]/_}"
    local d="${outdir}/breach"
    mkdir -p "$d"

    # Initialize hashes file on first call
    local hash_file="${OUTDIR}/found_hashes.txt"
    if [[ ! -f "$hash_file" ]]; then
        printf '# Found credential hashes/passwords — %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" > "$hash_file"
        printf '# Format: source_breach  |  account  |  hash:<value>  or  plain:<value>\n\n' >> "$hash_file"
    fi

    # HIBP breach check (requires HIBP_API_KEY)
    local hibp_key="${HIBP_API_KEY:-}"
    if [[ -n "$hibp_key" ]]; then
        local result
        result="$(curl -s --max-time 10 \
            "https://haveibeenpwned.com/api/v3/breachedaccount/${email}?truncateResponse=false" \
            -H "hibp-api-key: ${hibp_key}" \
            -H "User-Agent: OSINT-Investigation-Framework/${VERSION}" 2>/dev/null)"
        echo "$result" | jq '.' 2>/dev/null > "${d}/hibp_${safe_e}.json" || true
        local breach_count
        breach_count="$(echo "$result" | jq 'length // 0' 2>/dev/null || echo 0)"
        ok "HIBP: ${breach_count} breach(es)  [${email}]"
    else
        warn "HIBP_API_KEY not set — breach check skipped  [${email}]"
    fi

    # IntelligenceX — breach metadata, infostealer logs, paste sites (free: 50 searches/2d)
    if [[ -n "${INTELX_API_KEY:-}" ]]; then
        intelx_search "$email" "${d}/intelx_${safe_e}.json"
        local ix_total
        ix_total="$(jq '.total // 0' "${d}/intelx_${safe_e}.json" 2>/dev/null || echo 0)"
        ok "IntelX: ${ix_total} result(s) — bucket/filename metadata  [${email}]"
        sleep 1
    else
        warn "INTELX_API_KEY not set — IntelX search skipped  [${email}]"
    fi

    # SecurityTrails reverse WHOIS by email — all domains ever registered with this email
    local st_key="${SECURITYTRAILS_API_KEY:-}"
    if [[ -n "$st_key" ]]; then
        curl -s --max-time 15 -X POST \
            "https://api.securitytrails.com/v1/domains/list?include_ips=false&page=1" \
            -H "APIKEY: ${st_key}" -H "Content-Type: application/json" \
            -d "{\"filter\":{\"whois_email\":\"${email}\"}}" 2>/dev/null \
            | jq '{total: .meta.total_pages, domains: [.records[]?.hostname]}' 2>/dev/null \
            > "${d}/securitytrails_reversewhois_${safe_e}.json" || true
        local st_count
        st_count="$(jq '.domains | length' "${d}/securitytrails_reversewhois_${safe_e}.json" 2>/dev/null || echo 0)"
        ok "SecurityTrails reverse WHOIS: ${st_count} domain(s)  [${email}]"
    fi

    # DeHashed — leaked credential search (email + password hashes)
    # v2 API: POST to /v2/search, auth via x-api-key header
    local dh_key="${DEHASHED_API_KEY:-}"
    if [[ -n "$dh_key" ]]; then
        curl -s --max-time 15 \
            "https://api.dehashed.com/v2/search" \
            -X POST \
            -H "x-api-key: ${dh_key}" \
            -H "Content-Type: application/json" \
            -d "{\"query\":\"email:\\\"${email}\\\"\",\"page\":1,\"size\":10}" \
            2>/dev/null \
            | jq '{total: .total, entries: [.entries[]? | {email: .email, username: .username, password: .password, hashed_password: .hashed_password, database_name: .database_name}]}' \
            2>/dev/null > "${d}/dehashed_${safe_e}.json" || true
        local dh_count
        dh_count="$(jq '.total // 0' "${d}/dehashed_${safe_e}.json" 2>/dev/null || echo 0)"
        ok "DeHashed: ${dh_count} credential(s) found  [${email}]"

        # Extract any hashes/passwords into the job-level hashes file
        local hash_file="${OUTDIR}/found_hashes.txt"
        jq -r '
          .entries[]? |
          select((.hashed_password // "" | length > 0) or (.password // "" | length > 0)) |
          [ (.database_name // "unknown"),
            (.email // ""),
            (if (.hashed_password // "" | length > 0) then "hash:" + .hashed_password
             else "plain:" + .password end)
          ] | join("\t")
        ' "${d}/dehashed_${safe_e}.json" 2>/dev/null \
        | while IFS=$'\t' read -r source acct value; do
            echo "${source}  |  ${acct}  |  ${value}" >> "$hash_file"
          done
    fi

    # Manual breach/leak lookup reference file
    {
        echo "=== Breach / Leak Lookups for ${email} ==="
        echo ""
        echo "[ Automated (set HIBP_API_KEY for auto-check) ]"
        echo "  HaveIBeenPwned  : https://haveibeenpwned.com/account/${email}"
        echo ""
        echo "[ Manual (paid / requires account) ]"
        echo "  DeHashed        : https://dehashed.com/search?query=${email}"
        echo "  IntelligenceX   : https://intelx.io/?s=${email}"
        echo "  Snusbase        : https://snusbase.com (search: ${email})"
        echo "  LeakCheck       : https://leakcheck.io (search: ${email})"
        echo "  GhostProject    : https://ghostproject.fr (search: ${email})"
        echo ""
        echo "[ Paste Sites (check for leaked data) ]"
        echo "  PasteHunter     : https://pastehunter.com"
        echo "  Google dork     : site:pastebin.com \"${email}\""
    } > "${d}/manual_breach_${safe_e}.txt"
}

# ── Stage 3: Person / identity investigation ────────────────────────────────
investigate_person() {
    local name="$1" outdir="$2"
    local safe_n="${name// /_}"
    local fn="${name%% *}"
    local ln="${name##* }"
    local encoded_name
    encoded_name="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${name}'))" \
                   2>/dev/null || echo "${name// /+}")"
    local d="${outdir}/person_osint"
    mkdir -p "$d"

    # viewdns.info reverse WHOIS by name — domains registered under this person's name
    local vdns_key="${VIEWDNS_API_KEY:-}"
    if [[ -n "$vdns_key" ]]; then
        curl -s --max-time 15 \
            "https://api.viewdns.info/reversewhois/?q=${encoded_name}&apikey=${vdns_key}&output=json" \
            2>/dev/null | jq '.' 2>/dev/null \
            > "${d}/${safe_n}_viewdns_reversewhois.json" || true
        local vdns_count
        vdns_count="$(jq '.query.count // 0' "${d}/${safe_n}_viewdns_reversewhois.json" 2>/dev/null || echo 0)"
        ok "viewdns.info reverse WHOIS (name): ${vdns_count} domains  [${name}]"
    fi

    # WhoisXML reverse WHOIS by name
    local wxl_key="${WHOISXML_API_KEY:-}"
    if [[ -n "$wxl_key" ]]; then
        curl -s --max-time 15 \
            "https://reverse-whois.whoisxmlapi.com/api/v2" \
            -H "Content-Type: application/json" \
            -d "{\"apiKey\":\"${wxl_key}\",\"searchType\":\"current\",\"basicSearchTerms\":{\"include\":[\"${name}\"]}}" \
            2>/dev/null | jq '{domainCount: .domainsCount, domains: .domainsList}' 2>/dev/null \
            > "${d}/${safe_n}_whoisxml_reversewhois.json" || true
        local wxl_count
        wxl_count="$(jq '.domainCount // 0' "${d}/${safe_n}_whoisxml_reversewhois.json" 2>/dev/null || echo 0)"
        ok "WhoisXML reverse WHOIS (name): ${wxl_count} domains  [${name}]"
    fi

    # IntelX — search by full name (finds mentions in breach/paste/dark web data)
    if [[ -n "${INTELX_API_KEY:-}" ]]; then
        intelx_search "$name" "${d}/${safe_n}_intelx.json"
        local ix_total
        ix_total="$(jq '.total // 0' "${d}/${safe_n}_intelx.json" 2>/dev/null || echo 0)"
        ok "IntelX: ${ix_total} result(s)  [${name}]"
        sleep 1
    fi

    # hunter.io email finder — given name + each known domain, find likely email address
    local hunter_key="${HUNTER_API_KEY:-}"
    if [[ -n "$hunter_key" ]] && (( ${#DOMAINS[@]} > 0 )); then
        mkdir -p "${d}/hunter_emailfinder"
        for dom in "${DOMAINS[@]}"; do
            local safe_dom="${dom//[^a-zA-Z0-9_-]/_}"
            curl -s --max-time 15 \
                "https://api.hunter.io/v2/email-finder?domain=${dom}&first_name=${fn}&last_name=${ln}&api_key=${hunter_key}" \
                2>/dev/null | jq '{email: .data.email, score: .data.score, position: .data.position, linkedin: .data.linkedin_url}' \
                2>/dev/null > "${d}/hunter_emailfinder/${safe_n}_at_${safe_dom}.json" || true
            local h_email
            h_email="$(jq -r '.email // "not found"' "${d}/hunter_emailfinder/${safe_n}_at_${safe_dom}.json" 2>/dev/null || echo 'not found')"
            ok "hunter.io email finder: ${h_email}  [${name} @ ${dom}]"
        done
    fi

    # Generate pre-built people-search and social links for manual follow-up
    {
        echo "=== Person Investigation — ${name} ==="
        echo ""
        echo "[ Public Records / People Finders ]"
        echo "  WhitePages        : https://www.whitepages.com/name/${encoded_name}"
        echo "  FastPeopleSearch  : https://www.fastpeoplesearch.com/name/${encoded_name}"
        echo "  Spokeo            : https://www.spokeo.com/${encoded_name}"
        echo "  BeenVerified      : https://www.beenverified.com/people/${encoded_name}"
        echo "  Intelius          : https://www.intelius.com/people/${encoded_name}"
        echo "  TruthFinder       : https://www.truthfinder.com/people-search/?firstName=${fn}&lastName=${ln}"
        echo "  PeopleFinder      : https://www.peoplefinder.com/search/?fname=${fn}&lname=${ln}"
        echo ""
        echo "[ Social Media ]"
        echo "  LinkedIn          : https://www.linkedin.com/search/results/people/?keywords=${encoded_name}"
        echo "  Facebook          : https://www.facebook.com/search/people/?q=${encoded_name}"
        echo "  Twitter/X         : https://twitter.com/search?q=%22${encoded_name}%22&f=user"
        echo "  Instagram         : https://www.instagram.com/explore/search/keyword/?q=${encoded_name}"
        echo "  TikTok            : https://www.tiktok.com/search?q=${encoded_name}"
        echo ""
        echo "[ Search Engine Dorks ]"
        echo "  Google            : https://www.google.com/search?q=%22${encoded_name}%22"
        echo "  Bing              : https://www.bing.com/search?q=%22${encoded_name}%22"
        echo "  DuckDuckGo        : https://duckduckgo.com/?q=%22${encoded_name}%22"
        echo "  Google (+ phone)  : https://www.google.com/search?q=%22${encoded_name}%22+phone"
        echo "  Google (+ address): https://www.google.com/search?q=%22${encoded_name}%22+address"
        echo ""
        echo "[ Professional / Corporate ]"
        echo "  ZoomInfo          : https://www.zoominfo.com/person/${encoded_name}"
        echo "  Hunter.io         : https://hunter.io (search by domain)"
        echo "  RocketReach       : https://rocketreach.co/search?name=${encoded_name}"
        echo ""
        echo "[ Court / Legal Records ]"
        echo "  CourtListener     : https://www.courtlistener.com/?q=%22${encoded_name}%22&type=p"
        echo "  Judyrecords       : https://www.judyrecords.com/search?q=${encoded_name}"
        echo "  PACER             : https://www.pacer.gov (federal court — requires account)"
        echo ""
        echo "[ Voter / Property Records ]"
        echo "  VoterRecords      : https://www.voterrecords.com/search?search[name]=${encoded_name}"
        echo "  PropertyShark     : https://www.propertyshark.com (county property records)"
        echo ""
        echo "[ Image Search (if photo obtained) ]"
        echo "  Google Images     : https://images.google.com (upload photo)"
        echo "  TinEye            : https://tineye.com"
        echo "  PimEyes           : https://pimeyes.com (facial recognition)"
        echo "  Yandex Images     : https://yandex.com/images"
    } > "${d}/${safe_n}_search_links.txt"
    ok "Person search links saved  [${name}]"
    log "[person] ${name}"
}


# ════════════════════════════════════════════════════════════════════════════
#  MAIN PHASES  (seed data, depth 0)
# ════════════════════════════════════════════════════════════════════════════

phase_email() {
    section "PHASE: EMAIL OSINT  (depth 0)"
    for email in "${EMAILS[@]}"; do
        step "$email"; log "Email: $email"
        investigate_email "$email" "${OUTDIR}/email_osint"
    done
}

phase_username() {
    section "PHASE: USERNAME OSINT  (depth 0)"
    # offer_install sherlock sherlock  # DISABLED: sherlock false positives
    for uname in "${USERNAMES[@]}"; do
        step "$uname"; log "Username: $uname"
        investigate_username "$uname" "${OUTDIR}/username_osint"
    done
}

phase_phone() {
    section "PHASE: PHONE OSINT  (depth 0)"
    offer_install phoneinfoga phoneinfoga
    for phone in "${PHONES[@]}"; do
        step "$phone"; log "Phone: $phone"
        investigate_phone "$phone" "${OUTDIR}/phone_osint"
    done
}

phase_fullname() {
    section "PHASE: PERSON OSINT  (depth 0)"
    mkdir -p "${OUTDIR}/person_osint"
    for name in "${FULLNAMES[@]}"; do
        step "$name"; log "Person: $name"
        investigate_person "$name" "${OUTDIR}"
    done
}

phase_domain() {
    section "PHASE: DOMAIN OSINT  (depth 0)"
    for domain in "${DOMAINS[@]}"; do
        step "$domain"; log "Domain: $domain"
        investigate_domain "$domain" "${OUTDIR}/domain_osint"
    done
}

phase_ip() {
    section "PHASE: IP OSINT  (depth 0)"
    for ip in "${IPS[@]}"; do
        step "$ip"; log "IP: $ip"
        investigate_ip "$ip" "${OUTDIR}/ip_osint"
    done
}

phase_network() {
    section "PHASE: NETWORK OSINT  (MAC / SSID)"
    local d="${OUTDIR}/network_osint"

    for mac in "${MACS[@]+"${MACS[@]}"}"; do
        step "$mac"; log "MAC: $mac"
        local oui="${mac:0:8}"
        local vendor
        vendor="$(curl -s --max-time 8 "https://api.macvendors.com/${oui}" 2>/dev/null \
                  || echo 'unknown')"
        echo "${mac}  →  ${vendor}" >> "${d}/mac_vendors.txt"
        ok "Vendor: ${vendor}  [${mac}]"
        sleep 1
    done

    if (( ${#SSIDS[@]} > 0 )); then
        nmcli -f SSID,BSSID,FREQ,SIGNAL dev wifi list 2>/dev/null \
            > "${d}/local_wifi_scan.txt" || true
        ok "Local Wi-Fi scan → local_wifi_scan.txt"
        for ssid in "${SSIDS[@]}"; do
            grep -i "$ssid" "${d}/local_wifi_scan.txt" 2>/dev/null \
                >> "${d}/ssid_matches.txt" || true
        done
        local wigle_key="${WIGLE_API_KEY:-}"
        if [[ -n "$wigle_key" ]]; then
            for ssid in "${SSIDS[@]}"; do
                curl -s --max-time 10 \
                    "https://api.wigle.net/api/v2/network/search?ssid=${ssid}" \
                    -u "${wigle_key}:" 2>/dev/null \
                    | jq '.results[0:5]' 2>/dev/null \
                    > "${d}/wigle_${ssid// /_}.json" || true
            done
        else
            warn "WIGLE_API_KEY not set — Wigle lookups skipped"
        fi
    fi
}

phase_address() {
    section "PHASE: ADDRESS / GEO OSINT"
    local out="${OUTDIR}/address_osint/geocoded.txt"
    > "$out"

    for addr in "${ADDRESSES[@]}"; do
        step "$addr"; log "Address: $addr"
        local encoded
        encoded="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${addr}'))" \
                   2>/dev/null || echo "${addr// /+}")"
        local result
        result="$(curl -s --max-time 10 \
            "https://nominatim.openstreetmap.org/search?q=${encoded}&format=json&limit=1&addressdetails=1" \
            -H "User-Agent: OSINT-Investigation/1.0" 2>/dev/null || echo '[]')"
        local lat lon display
        lat="$(echo "$result" | jq -r '.[0].lat // "unknown"' 2>/dev/null || echo 'unknown')"
        lon="$(echo "$result" | jq -r '.[0].lon // "unknown"' 2>/dev/null || echo 'unknown')"
        display="$(echo "$result" | jq -r '.[0].display_name // "not found"' 2>/dev/null || echo 'not found')"
        {
            echo "Input   : $addr"
            echo "Display : $display"
            echo "Lat/Lon : ${lat}, ${lon}"
            echo "Maps    : https://maps.google.com/?q=${lat},${lon}"
            echo "---"
        } >> "$out"
        ok "Geocoded: ${lat}, ${lon}  [${addr:0:40}]"
    done
}


# ════════════════════════════════════════════════════════════════════════════
#  PIVOT ENGINE
# ════════════════════════════════════════════════════════════════════════════

# Scans all output files under $search_dir and populates PIVOT_* arrays
# with entities that haven't been investigated yet.
extract_new_entities() {
    local search_dir="$1"

    PIVOT_EMAILS=()
    PIVOT_USERNAMES=()
    PIVOT_DOMAINS=()
    PIVOT_IPS=()
    PIVOT_NAMES=()
    PIVOT_PHONES=()

    # ── Emails ──────────────────────────────────────────────────────────────
    # Skip generic prefixes and known infrastructure/registrar domains
    local _infra_domains='@microsoft\.|@markmonitor\.|@verisign\.|@networksolutions\.|@godaddy\.|@namecheap\.|@iana\.|@icann\.|@ripe\.|@arin\.|@apnic\.|@yahoo-inc\.|@yahooinc\.|@oath\.|@google\.|@amazon\.|@cloudflare\.|@akamai\.|@whoisguard\.|@domaincontrol\.|@registrar-servers\.|@cscdbs\.|@cscinfo\.'
    local _infra_prefix='noreply|no-reply|donotreply|abuse|domains|hostmaster|postmaster|webmaster|registrar|registry|whoisrequest|custserv|rir-noc|rir-tech|ioc|iphostmaster|msndcc|msnhst|pracsin|someshch|secure|admin|help|info|sales|billing|support|contact'
    while IFS= read -r val; do
        val="${val,,}"
        [[ -z "$val" ]] && continue
        [[ "$val" =~ example\.com|@sentry\.|@amplitude\.|@test\. ]] && continue
        [[ "$val" =~ $_infra_prefix ]] && continue
        [[ "$val" =~ $_infra_domains ]] && continue
        is_known email "$val" || PIVOT_EMAILS+=("$val")
    done < <(grep -rhoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
             "$search_dir" 2>/dev/null | sort -u) || true

    # ── IPs from DNS A records, nmap output, and ASN/ipinfo results ─────────────
    while IFS= read -r val; do
        [[ -z "$val" ]] && continue
        [[ "$val" =~ ^10\.|^192\.168\.|^127\.|^0\.|^169\.254\.|^255\. ]] && continue
        [[ "$val" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && continue
        is_known ip "$val" || PIVOT_IPS+=("$val")
    done < <(grep -rhoE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
             "${search_dir}"/{email_osint,domain_osint/dns} 2>/dev/null \
             | sort -u
             grep -rhoE 'Nmap scan report for .+ \(([0-9]{1,3}\.){3}[0-9]{1,3}\)' \
             "${search_dir}" 2>/dev/null \
             | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
             jq -r '.ip // empty' "${search_dir}"/domain_osint/passive/*_urlscan_result.json \
             2>/dev/null | sort -u) || true

    # ── Subdomains from crt.sh / subfinder output + SSL cert SANs ───────────
    while IFS= read -r val; do
        val="${val,,}"
        [[ -z "$val" || "$val" == "." ]] && continue
        [[ "$val" =~ ^\*\. ]] && val="${val:2}"
        [[ "$val" =~ \. ]] || continue
        is_known domain "$val" || PIVOT_DOMAINS+=("$val")
    done < <(
        find "${search_dir}" -name "*_all.txt" -path "*/subdomains/*" \
            -exec cat {} \; 2>/dev/null | grep -v '^#'
        # SSL cert SANs from nmap output (Subject Alternative Name: DNS:...)
        grep -rhoE 'DNS:[a-zA-Z0-9*._-]+' "${search_dir}" 2>/dev/null \
            | sed 's/DNS://' | grep -v '^\*$'
        # SANs from urlscan cert data
        jq -r '.certificates[]?.subject // empty' \
            "${search_dir}"/domain_osint/passive/*_urlscan_result.json 2>/dev/null
    ) | sort -u || true

    # ── Names from WHOIS registrant fields ───────────────────────────────────
    while IFS= read -r val; do
        val="$(echo "$val" | xargs 2>/dev/null || echo "$val")"
        [[ -z "$val" ]] && continue
        is_known name "$val" || PIVOT_NAMES+=("$val")
    done < <(grep -rhi \
             -e 'Registrant Name:' -e 'Admin Name:' -e 'Tech Name:' \
             "${search_dir}" 2>/dev/null \
             | sed 's/.*:[[:space:]]*//' \
             | grep -vEi 'REDACTED|Privacy|Withheld|Ltd|LLC|Corp|Inc|GmbH|N\/A|Administrator|Hostmaster|Registrant|Registrar|Registry|Domain|Technical|Abuse|Whois|^[[:space:]]*$' \
             | grep -E '^[A-Z][a-z]+ [A-Z]' \
             | sort -u) || true

    # ── Phones from WHOIS ────────────────────────────────────────────────────
    while IFS= read -r val; do
        val="$(echo "$val" | xargs 2>/dev/null || echo "$val")"
        [[ -z "$val" ]] && continue
        is_known phone "$val" || PIVOT_PHONES+=("$val")
    done < <(grep -rhi -e 'Registrant Phone:' -e 'Admin Phone:' \
             "${search_dir}" 2>/dev/null \
             | sed 's/.*:[[:space:]]*//' \
             | grep -vEi 'REDACTED|Privacy|Withheld|^[[:space:]]*$' \
             | grep -E '^\+?[0-9]' \
             | sort -u) || true

    # ── Username candidates derived from discovered emails ────────────────────
    for email in "${PIVOT_EMAILS[@]+"${PIVOT_EMAILS[@]}"}"; do
        local local_part="${email%@*}"
        # Skip generic/infrastructure usernames
        [[ "$local_part" =~ abuse|noreply|no.reply|support|contact|admin|help|info|sales|billing|domains|hostmaster|postmaster|webmaster|registrar|registry|whoisrequest|custserv|rir|ioc|iphostmaster|msndcc|msnhst|pracsin|secure ]] && continue
        # Generate common username variations
        local v_plain="${local_part//[._-]/}"           # johndoe
        local v_dot="${local_part//[_-]/.}"             # john.doe
        local v_under="${local_part//[.-]/_}"           # john_doe
        for v in "$local_part" "$v_plain" "$v_dot" "$v_under"; do
            [[ ${#v} -gt 3 ]] && ! is_known username "$v" && PIVOT_USERNAMES+=("$v")
        done
    done

    # ── Username candidates derived from discovered names ─────────────────────
    for name in "${PIVOT_NAMES[@]+"${PIVOT_NAMES[@]}"}"; do
        local fn="${name%% *}"; fn="${fn,,}"
        local ln="${name##* }"; ln="${ln,,}"
        [[ "$fn" == "$ln" ]] && continue  # single-word name, skip
        for v in "${fn}.${ln}" "${fn}${ln}" "${fn}_${ln}" "${fn:0:1}${ln}"; do
            [[ ${#v} -gt 3 ]] && ! is_known username "$v" && PIVOT_USERNAMES+=("$v")
        done
    done

    # Deduplicate PIVOT_USERNAMES
    if (( ${#PIVOT_USERNAMES[@]} > 0 )); then
        local _uniq=()
        declare -A _seen=()
        for u in "${PIVOT_USERNAMES[@]}"; do
            [[ -z "${_seen[$u]:-}" ]] && _uniq+=("$u") && _seen[$u]=1
        done
        PIVOT_USERNAMES=("${_uniq[@]+"${_uniq[@]}"}")
    fi
}

show_pivot_discovery() {
    local depth="$1"
    local total=$(( ${#PIVOT_EMAILS[@]} + ${#PIVOT_USERNAMES[@]} + ${#PIVOT_DOMAINS[@]} \
                  + ${#PIVOT_IPS[@]} + ${#PIVOT_NAMES[@]} + ${#PIVOT_PHONES[@]} ))

    echo
    echo -e "  ${Y}${BOLD}  ┌─── PIVOT DISCOVERY  (depth ${depth}) ─────────────────────┐${RESET}"
    printf  "  ${Y}${BOLD}  │  %-52s│${RESET}\n" "  ${total} new entities found from depth $((depth-1)) output"
    echo -e "  ${Y}${BOLD}  ├──────────────────────────────────────────────────────┤${RESET}"
    (( ${#PIVOT_EMAILS[@]}    > 0 )) && \
        printf "  ${Y}${BOLD}  │${RESET}  ${W}Emails (%d)   ${DIM}%s${RESET}\n" \
        "${#PIVOT_EMAILS[@]}" "${PIVOT_EMAILS[*]:0:60}"
    (( ${#PIVOT_USERNAMES[@]} > 0 )) && \
        printf "  ${Y}${BOLD}  │${RESET}  ${W}Usernames (%d)${DIM}%s${RESET}\n" \
        "${#PIVOT_USERNAMES[@]}" "${PIVOT_USERNAMES[*]:0:60}"
    (( ${#PIVOT_PHONES[@]}    > 0 )) && \
        printf "  ${Y}${BOLD}  │${RESET}  ${W}Phones (%d)   ${DIM}%s${RESET}\n" \
        "${#PIVOT_PHONES[@]}" "${PIVOT_PHONES[*]:0:60}"
    (( ${#PIVOT_DOMAINS[@]}   > 0 )) && \
        printf "  ${Y}${BOLD}  │${RESET}  ${W}Domains (%d)  ${DIM}%s${RESET}\n" \
        "${#PIVOT_DOMAINS[@]}" "${PIVOT_DOMAINS[*]:0:60}"
    (( ${#PIVOT_IPS[@]}       > 0 )) && \
        printf "  ${Y}${BOLD}  │${RESET}  ${W}IPs (%d)      ${DIM}%s${RESET}\n" \
        "${#PIVOT_IPS[@]}" "${PIVOT_IPS[*]:0:60}"
    (( ${#PIVOT_NAMES[@]}     > 0 )) && \
        printf "  ${Y}${BOLD}  │${RESET}  ${W}Names (%d)    ${DIM}%s${RESET}\n" \
        "${#PIVOT_NAMES[@]}" "${PIVOT_NAMES[*]:0:60}"
    echo -e "  ${Y}${BOLD}  └──────────────────────────────────────────────────────┘${RESET}"
}

run_pivot_pass() {
    local depth="$1"
    local d="${OUTDIR}/pivot/depth_${depth}"

    mkdir -p "${d}"/{email_osint,username_osint,phone_osint,\
domain_osint/{whois,dns,subdomains,certs},\
ip_osint/{whois,reverse_dns,asn}}

    # Save discovered entities list for this depth
    {
        echo "# Entities discovered at pivot depth ${depth}"
        echo "# $(date)"
        (( ${#PIVOT_EMAILS[@]}    > 0 )) && printf 'email: %s\n'    "${PIVOT_EMAILS[@]}"
        (( ${#PIVOT_USERNAMES[@]} > 0 )) && printf 'username: %s\n' "${PIVOT_USERNAMES[@]}"
        (( ${#PIVOT_PHONES[@]}    > 0 )) && printf 'phone: %s\n'    "${PIVOT_PHONES[@]}"
        (( ${#PIVOT_DOMAINS[@]}   > 0 )) && printf 'domain: %s\n'   "${PIVOT_DOMAINS[@]}"
        (( ${#PIVOT_IPS[@]}       > 0 )) && printf 'ip: %s\n'       "${PIVOT_IPS[@]}"
        (( ${#PIVOT_NAMES[@]}     > 0 )) && printf 'name: %s\n'     "${PIVOT_NAMES[@]}"
    } > "${d}/discovered_entities.txt"

    # ── Emails ──────────────────────────────────────────────────────────────
    if (( ${#PIVOT_EMAILS[@]} > 0 )); then
        section "PIVOT depth ${depth}  —  EMAILS  (${#PIVOT_EMAILS[@]})"
        for email in "${PIVOT_EMAILS[@]}"; do
            step "$email" "discovered"
            log "[depth=${depth}] Email pivot: $email"
            investigate_email "$email" "${d}/email_osint"
            mark_known email "$email"
        done
    fi

    # ── Usernames ────────────────────────────────────────────────────────────
    # DISABLED sherlock guard — investigate_username still runs maigret
    if (( ${#PIVOT_USERNAMES[@]} > 0 )); then
        section "PIVOT depth ${depth}  —  USERNAMES  (${#PIVOT_USERNAMES[@]})"
        for uname in "${PIVOT_USERNAMES[@]}"; do
            step "$uname" "derived from discovered entities"
            log "[depth=${depth}] Username pivot: $uname"
            investigate_username "$uname" "${d}/username_osint"
            mark_known username "$uname"
        done
    fi

    # ── Phones ───────────────────────────────────────────────────────────────
    if (( ${#PIVOT_PHONES[@]} > 0 )); then
        section "PIVOT depth ${depth}  —  PHONES  (${#PIVOT_PHONES[@]})"
        mkdir -p "${d}/phone_osint"
        for phone in "${PIVOT_PHONES[@]}"; do
            step "$phone" "discovered from WHOIS"
            log "[depth=${depth}] Phone pivot: $phone"
            investigate_phone "$phone" "${d}/phone_osint"
            mark_known phone "$phone"
        done
    fi

    # ── Domains (light scan — no nmap/gau/theHarvester at pivot depth) ────────
    if (( ${#PIVOT_DOMAINS[@]} > 0 )); then
        section "PIVOT depth ${depth}  —  DOMAINS  (${#PIVOT_DOMAINS[@]})"
        for domain in "${PIVOT_DOMAINS[@]}"; do
            step "$domain" "discovered"
            log "[depth=${depth}] Domain pivot: $domain"
            investigate_domain_light "$domain" "${d}/domain_osint"
            mark_known domain "$domain"
        done
    fi

    # ── IPs (light scan — no nmap at pivot depth) ─────────────────────────────
    if (( ${#PIVOT_IPS[@]} > 0 )); then
        section "PIVOT depth ${depth}  —  IPs  (${#PIVOT_IPS[@]})"
        for ip in "${PIVOT_IPS[@]}"; do
            step "$ip" "discovered from DNS"
            log "[depth=${depth}] IP pivot: $ip"
            investigate_ip_light "$ip" "${d}/ip_osint"
            mark_known ip "$ip"
        done
    fi

    # ── Names: full person investigation + derive username candidates ───────────
    if (( ${#PIVOT_NAMES[@]} > 0 )); then
        section "PIVOT depth ${depth}  —  PERSONS  (${#PIVOT_NAMES[@]})"
        mkdir -p "${d}/person_osint"
        log "[depth=${depth}] Discovered names: ${PIVOT_NAMES[*]}"
        for name in "${PIVOT_NAMES[@]}"; do
            step "$name" "discovered from WHOIS"
            log "[depth=${depth}] Person pivot: $name"
            investigate_person "$name" "$d"
            mark_known name "$name"
        done
    fi
}


# ════════════════════════════════════════════════════════════════════════════
#  OUTPUT GENERATORS
# ════════════════════════════════════════════════════════════════════════════

gen_maltego() {
    local f="${OUTDIR}/maltego/entities.csv"
    {
        echo "Entity Type,Value,Source,Depth"

        # Seed data
        for e in "${EMAILS[@]+"${EMAILS[@]}"}";    do echo "maltego.EmailAddress,${e},seed,0"; done
        for p in "${PHONES[@]+"${PHONES[@]}"}";    do echo "maltego.PhoneNumber,${p},seed,0"; done
        for u in "${USERNAMES[@]+"${USERNAMES[@]}"}"; do echo "maltego.Alias,${u},seed,0"; done
        for n in "${FULLNAMES[@]+"${FULLNAMES[@]}"}"; do echo "maltego.Person,${n},seed,0"; done
        for d in "${DOMAINS[@]+"${DOMAINS[@]}"}";  do echo "maltego.Domain,${d},seed,0"; done
        for i in "${IPS[@]+"${IPS[@]}"}";          do echo "maltego.IPv4Address,${i},seed,0"; done
        for m in "${MACS[@]+"${MACS[@]}"}";        do echo "maltego.MACAddress,${m},seed,0"; done
        for s in "${SSIDS[@]+"${SSIDS[@]}"}";      do echo "maltego.SSID,${s},seed,0"; done
        for a in "${ADDRESSES[@]+"${ADDRESSES[@]}"}"; do echo "maltego.Location,${a},seed,0"; done

        # Depth-0 discovered subdomains
        while IFS= read -r sub; do
            [[ -n "$sub" ]] && echo "maltego.DNSName,${sub},subfinder/crt.sh,0"
        done < <(find "${OUTDIR}/domain_osint" -name "*_all.txt" \
                 -exec cat {} \; 2>/dev/null | sort -u) || true

        # Depth-0 harvested emails
        while IFS= read -r em; do
            [[ "$em" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && \
                echo "maltego.EmailAddress,${em},theHarvester,0"
        done < <(grep -rhoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
                 "${OUTDIR}/domain_osint/harvester" 2>/dev/null | sort -u) || true

        # Depth-0 sherlock profiles — DISABLED (sherlock false positives)
        # while IFS= read -r line; do
        #     [[ "$line" =~ ^\[\+\] ]] && \
        #         echo "maltego.URL,$(echo "$line" | awk '{print $NF}'),sherlock,0"
        # done < <(cat "${OUTDIR}"/username_osint/sherlock_*.txt 2>/dev/null) || true

        # Pivot depths
        local depth
        for depth in $(seq 1 "$MAX_DEPTH"); do
            local pd="${OUTDIR}/pivot/depth_${depth}"
            [[ -d "$pd" ]] || continue

            # Emails from pivot
            while IFS= read -r em; do
                [[ "$em" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && \
                    echo "maltego.EmailAddress,${em},pivot,${depth}"
            done < <(grep -rhoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
                     "${pd}" 2>/dev/null | sort -u) || true

            # Subdomains from pivot
            while IFS= read -r sub; do
                [[ -n "$sub" ]] && echo "maltego.DNSName,${sub},pivot,${depth}"
            done < <(find "${pd}" -name "*_all.txt" -exec cat {} \; 2>/dev/null | sort -u) || true

            # Sherlock profiles from pivot — DISABLED (sherlock false positives)
            # while IFS= read -r line; do
            #     [[ "$line" =~ ^\[\+\] ]] && \
            #         echo "maltego.URL,$(echo "$line" | awk '{print $NF}'),pivot-sherlock,${depth}"
            # done < <(cat "${pd}"/username_osint/sherlock_*.txt 2>/dev/null) || true

            # Names discovered
            if [[ -f "${pd}/discovered_entities.txt" ]]; then
                grep '^name:' "${pd}/discovered_entities.txt" 2>/dev/null \
                    | sed 's/^name: //' \
                    | while IFS= read -r n; do
                        echo "maltego.Person,${n},pivot-whois,${depth}"
                    done || true
            fi
        done

    } | sort -u > "$f"

    local count
    count="$(wc -l < "$f")"
    ok "Maltego CSV: $((count-1)) entities → maltego/entities.csv"

    cat > "${OUTDIR}/maltego/import_guide.txt" << 'EOF'
MALTEGO IMPORT GUIDE
====================
1. Open Maltego → Investigate → "Import Entities from CSV"
2. Select: maltego/entities.csv
3. Map columns:
     Column 1 "Entity Type" → Type
     Column 2 "Value"       → Value/Name property
     Column 4 "Depth"       → (optional note property)
4. Click Import

Entity types: EmailAddress · PhoneNumber · Alias · Person · Domain
              DNSName · IPv4Address · MACAddress · SSID · Location · URL
EOF
}

gen_burp() {
    local d="${OUTDIR}/burp"
    local -a targets=()

    for dom in "${DOMAINS[@]+"${DOMAINS[@]}"}"; do targets+=("$dom"); done
    for ip  in "${IPS[@]+"${IPS[@]}"}";         do targets+=("$ip");  done

    # Add all discovered subdomains (all depths)
    while IFS= read -r sub; do
        [[ -n "$sub" ]] && targets+=("$sub")
    done < <(find "${OUTDIR}" -name "*_all.txt" -path "*/subdomains/*" \
             -exec cat {} \; 2>/dev/null | sort -u) || true

    {
        echo '{'
        echo '  "target": {'
        echo '    "scope": {'
        echo '      "advanced_mode": false,'
        echo '      "exclude": [],'
        echo '      "include": ['
        local first=true
        for t in "${targets[@]}"; do
            local escaped
            escaped="$(echo "$t" | sed 's/\./\\\\./g')"
            [[ "$first" == "true" ]] && first=false || echo ','
            printf '        {"enabled": true, "file": "", "host": "%s", "port": "", "protocol": "any"}' \
                "$escaped"
        done
        echo
        echo '      ]'
        echo '    }'
        echo '  }'
        echo '}'
    } > "${d}/scope.json"

    printf '%s\n' "${targets[@]+"${targets[@]}"}" > "${d}/target_list.txt"
    ok "Burp Suite scope → burp/scope.json  (${#targets[@]} targets)"

    cat > "${d}/import_guide.txt" << 'EOF'
BURP SUITE IMPORT GUIDE
========================
Method A: Burp → Project options → Scope → Load → select scope.json
Method B: Burp → Target → Scope → Include → paste from target_list.txt
EOF
}

gen_recon_ng() {
    local f="${OUTDIR}/recon_ng/workspace.rc"
    {
        echo "# recon-ng workspace — ${INVESTIGATION_NAME}"
        echo "# Run: recon-ng -r ${f}"
        echo ""
        echo "workspaces create ${SAFE_NAME}"
        echo ""
        for name in "${FULLNAMES[@]+"${FULLNAMES[@]}"}"; do
            local fn="${name%% *}" ln="${name#* }"
            echo "db insert contacts first_name=\"${fn}\" last_name=\"${ln}\""
        done
        for e in "${EMAILS[@]+"${EMAILS[@]}"}"; do
            echo "db insert contacts email=\"${e}\""
        done
        for d in "${DOMAINS[@]+"${DOMAINS[@]}"}"; do
            echo "db insert domains domain=\"${d}\""
        done
        for ip in "${IPS[@]+"${IPS[@]}"}"; do
            echo "db insert hosts ip_address=\"${ip}\""
        done
        while IFS= read -r sub; do
            [[ -n "$sub" ]] && echo "db insert hosts host=\"${sub}\""
        done < <(find "${OUTDIR}" -name "*_all.txt" -path "*/subdomains/*" \
                 -exec cat {} \; 2>/dev/null | sort -u) || true
        for u in "${USERNAMES[@]+"${USERNAMES[@]}"}"; do
            echo "db insert profiles username=\"${u}\""
        done
        for a in "${ADDRESSES[@]+"${ADDRESSES[@]}"}"; do
            echo "db insert locations street_address=\"${a}\""
        done
        # Pivot-discovered names
        find "${OUTDIR}/pivot" -name "discovered_entities.txt" 2>/dev/null \
            | xargs grep '^name:' 2>/dev/null \
            | sed 's/.*name: //' \
            | while IFS= read -r n; do
                fn="${n%% *}"; ln="${n#* }"
                echo "db insert contacts first_name=\"${fn}\" last_name=\"${ln}\""
            done || true
        echo ""
        echo "show contacts"
        echo "show domains"
        echo "show hosts"
    } > "$f"
    ok "recon-ng workspace → recon_ng/workspace.rc"
}

gen_spiderfoot() {
    local f="${OUTDIR}/spiderfoot/targets.txt"
    {
        echo "# SpiderFoot targets — ${INVESTIGATION_NAME}"
        for d in "${DOMAINS[@]+"${DOMAINS[@]}"}";  do echo "$d"; done
        for i in "${IPS[@]+"${IPS[@]}"}";          do echo "$i"; done
        for e in "${EMAILS[@]+"${EMAILS[@]}"}";    do echo "$e"; done
        for u in "${USERNAMES[@]+"${USERNAMES[@]}"}"; do echo "$u"; done
        for n in "${FULLNAMES[@]+"${FULLNAMES[@]}"}"; do echo "$n"; done
    } > "$f"
    ok "SpiderFoot targets → spiderfoot/targets.txt"
}

gen_summary() {
    local f="${OUTDIR}/summary.md"
    local sub_count
    sub_count="$(find "${OUTDIR}" -name "*_all.txt" -path "*/subdomains/*" \
                 -exec cat {} \; 2>/dev/null | sort -u | grep -c . 2>/dev/null || echo 0)"

    {
        echo "# OSINT Investigation Summary"
        echo ""
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| Investigation | ${INVESTIGATION_NAME} |"
        [[ -n "$CASE_NUMBER" ]] && echo "| Case # | ${CASE_NUMBER} |"
        echo "| Investigator | ${INVESTIGATOR} |"
        echo "| Date | ${DATE_HUMAN} |"
        echo "| Target type | ${TARGET_TYPE} |"
        echo "| Pivot depth | ${MAX_DEPTH} |"
        echo ""
        echo "## Seed Data"
        echo ""
        echo "| Category | Count | Values |"
        echo "|----------|-------|--------|"
        _srow() {
            local lbl="$1"; shift; local arr=("$@")
            local cnt=${#arr[@]}; local val="—"
            (( cnt > 0 )) && val="${arr[*]}"
            echo "| $lbl | $cnt | ${val:0:80} |"
        }
        _srow "Emails"     "${EMAILS[@]+"${EMAILS[@]}"}"
        _srow "Phones"     "${PHONES[@]+"${PHONES[@]}"}"
        _srow "Usernames"  "${USERNAMES[@]+"${USERNAMES[@]}"}"
        _srow "Full names" "${FULLNAMES[@]+"${FULLNAMES[@]}"}"
        _srow "Domains"    "${DOMAINS[@]+"${DOMAINS[@]}"}"
        _srow "IPs"        "${IPS[@]+"${IPS[@]}"}"
        _srow "Addresses"  "${ADDRESSES[@]+"${ADDRESSES[@]}"}"
        _srow "MACs"       "${MACS[@]+"${MACS[@]}"}"
        _srow "SSIDs"      "${SSIDS[@]+"${SSIDS[@]}"}"

        echo ""
        echo "## Discovery"
        echo ""
        echo "| Source | Result |"
        echo "|--------|--------|"
        echo "| Subdomains (all depths) | ${sub_count} |"
        echo "| holehe service registrations | see email_osint/ + pivot/ |"
        echo "| username profiles (maigret) | see username_osint/ + pivot/ |"
        echo "| nmap (depth 0 only) | see domain_osint/ + ip_osint/ |"

        # API integration results
        echo ""
        echo "## API Intelligence"
        echo ""
        echo "| API | Coverage | Files |"
        echo "|-----|----------|-------|"

        local ix_files
        ix_files="$(find "$OUTDIR" -name "*_intelx.json" 2>/dev/null | wc -l | tr -d ' ')"
        local ix_total_hits=0
        while IFS= read -r f; do
            local h; h="$(jq '.total // 0' "$f" 2>/dev/null || echo 0)"
            ix_total_hits=$(( ix_total_hits + h ))
        done < <(find "$OUTDIR" -name "*_intelx.json" 2>/dev/null)
        echo "| IntelligenceX | ${ix_files} searches, ${ix_total_hits} total results | \`*_intelx.json\` |"

        local shodan_files
        shodan_files="$(find "$OUTDIR" -name "*_shodan.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| Shodan | ${shodan_files} IPs | \`*_shodan.json\` |"

        local cip_files
        cip_files="$(find "$OUTDIR" -name "*_criminalip.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| CriminalIP | ${cip_files} IPs | \`*_criminalip.json\` |"

        local gn_files
        gn_files="$(find "$OUTDIR" -name "*_greynoise.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| GreyNoise | ${gn_files} IPs | \`*_greynoise.json\` |"

        local ripe_files
        ripe_files="$(find "$OUTDIR" -name "*_ripe_abuse.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| RIPE abuse contacts | ${ripe_files} IPs | \`*_ripe_abuse.json\` |"

        local ht_files
        ht_files="$(find "$OUTDIR" -name "*_hostsearch.txt" -o -name "*_customers.txt" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| HackerTarget (rev NS/IP) | ${ht_files} lookups | \`*_hostsearch.txt\`, \`*_customers.txt\` |"

        local erep_files
        erep_files="$(find "$OUTDIR" -name "emailrep_*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| emailrep.io | ${erep_files} emails | \`emailrep_*.json\` |"

        local vdns_files
        vdns_files="$(find "$OUTDIR" -name "*viewdns*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| viewdns.info | ${vdns_files} lookups | \`*viewdns*.json\` |"

        local wxl_files
        wxl_files="$(find "$OUTDIR" -name "*whoisxml*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| WhoisXML | ${wxl_files} lookups | \`*whoisxml*.json\` |"

        local st_files
        st_files="$(find "$OUTDIR" -name "*securitytrails*.json" -o -name "*_st_*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| SecurityTrails | ${st_files} lookups | \`*st_*.json\` |"

        local gh_files
        gh_files="$(find "$OUTDIR" -name "github_*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| GitHub code search | ${gh_files} searches | \`github_*.json\` |"

        local hunter_files
        hunter_files="$(find "$OUTDIR" -name "*_hunter*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| hunter.io | ${hunter_files} lookups (domain email lists + verify + finder) | \`*_hunter*.json\` |"

        local urlscan_files
        urlscan_files="$(find "$OUTDIR" -name "*_urlscan*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| urlscan.io | ${urlscan_files} lookups (history search + live scan) | \`*_urlscan*.json\` |"

        local numv_files
        numv_files="$(find "$OUTDIR" -name "carrier_*.json" 2>/dev/null | wc -l | tr -d ' ')"
        echo "| numverify | ${numv_files} phone lookups | \`carrier_*.json\` |"

        # Pivot summary per depth
        for depth in $(seq 1 "$MAX_DEPTH"); do
            local pd="${OUTDIR}/pivot/depth_${depth}"
            [[ -f "${pd}/discovered_entities.txt" ]] || continue
            echo ""
            echo "### Pivot Depth ${depth}"
            echo "\`\`\`"
            cat "${pd}/discovered_entities.txt"
            echo "\`\`\`"
        done

        [[ -n "$NOTES" ]] && echo "" && echo "## Notes" && echo "" && echo "$NOTES"

        echo ""
        echo "## File Tree"
        echo "\`\`\`"
        find "$OUTDIR" -type f | sort | sed "s|${OUTDIR}/||"
        echo "\`\`\`"
    } > "$f"
    ok "Summary → summary.md"
}

gen_readme() {
    cat > "${OUTDIR}/README.txt" << EOF
══════════════════════════════════════════════════════════════
  OSINT INVESTIGATION DOSSIER  v4.0
  ${INVESTIGATION_NAME}
  Generated : ${DATE_HUMAN}
  Investigator: ${INVESTIGATOR}
  Pivot depth : ${MAX_DEPTH}
══════════════════════════════════════════════════════════════

DIRECTORY STRUCTURE
───────────────────
  seed/               Original seed data entered at start
  email_osint/        depth-0: holehe, emailrep.io, DNS, WHOIS, theHarvester
    breach/             HIBP, IntelX, SecurityTrails reverse WHOIS
    emailrep_*.json     Fraud/reputation signal
    viewdns_*.json      Domains registered with this email
    whoisxml_*.json     WhoisXML reverse WHOIS
    github_*.json       GitHub code search hits
  username_osint/     depth-0: maigret
  phone_osint/        depth-0: phoneinfoga, carrier lookup
  domain_osint/       depth-0: WHOIS, DNS, subfinder, crt.sh, gau, nmap
    passive/            HackerTarget hostsearch + reverse NS, IntelX, viewdns history
                        WhoisXML history, SecurityTrails DNS history, GitHub
  ip_osint/           depth-0: WHOIS, rDNS, ASN/geo, nmap
    passive/            Shodan, CriminalIP, GreyNoise, RIPE abuse, AbuseIPDB
                        SecurityTrails nearby, IntelX, HackerTarget reverse IP
  network_osint/      MAC vendors, SSID scan, Wigle
  address_osint/      Nominatim geocoding, map links
  person_osint/       viewdns/WhoisXML reverse WHOIS by name, IntelX, social links
  pivot/
    depth_N/          Entities discovered and investigated at depth N
      discovered_entities.txt  — what triggered this depth
      email_osint/
      username_osint/
      domain_osint/   (WHOIS, DNS, subfinder, crt.sh, HackerTarget, IntelX)
      ip_osint/       (WHOIS, rDNS, ASN/geo, Shodan, CriminalIP, GreyNoise)
  maltego/            entities.csv with all depths tagged
  burp/               scope.json + target_list.txt
  recon_ng/           workspace.rc (includes pivot-discovered entities)
  spiderfoot/         targets.txt
  summary.md          Full summary + API intelligence table
  timeline.log        Timestamped activity across all depths

TOOL IMPORT
───────────
  Maltego   → Investigate → Import Entities from CSV → maltego/entities.csv
  Burp      → Project options → Scope → Load → burp/scope.json
  recon-ng  → recon-ng -r recon_ng/workspace.rc
  SpiderFoot → New Scan → paste targets from spiderfoot/targets.txt

PIVOT ENGINE NOTES
──────────────────
  Depth 0: seed data only (what you entered)
  Depth 1: emails/usernames/domains/IPs discovered from depth-0 output
           (WHOIS registrant contacts, harvested emails, subdomains, DNS IPs)
  Depth N: continues recursively, skipping already-investigated entities
  Pivot depth scans are lighter: no nmap, no gau, no theHarvester
  Username candidates are derived from emails and names automatically
EOF
    ok "README → README.txt"
}


# ════════════════════════════════════════════════════════════════════════════
#  REFERENCE LINKS  —  Pre-filled manual investigation URLs (OSINT Framework)
# ════════════════════════════════════════════════════════════════════════════

gen_reference_links() {
    local f="${OUTDIR}/reference_links.md"
    local name_q="" name_first="" name_last="" phone_clean="" email1=""

    # Pull seed data for URL construction
    [[ ${#FULLNAMES[@]} -gt 0 ]] && name_q="${FULLNAMES[0]// /+}" \
        && name_first="${FULLNAMES[0]%% *}" \
        && name_last="${FULLNAMES[0]##* }"
    [[ ${#PHONES[@]} -gt 0 ]] && phone_clean="${PHONES[0]//[^0-9]/}"
    [[ ${#EMAILS[@]} -gt 0 ]] && email1="${EMAILS[0]}"

    {
    echo "# Investigation Reference Links"
    echo "> Generated: ${DATE_HUMAN} | Target: ${INVESTIGATION_NAME}"
    echo "> Pre-filled with seed data. Click to investigate manually."
    echo ""

    echo "## 👤 People Search Engines"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$name_q" ]] && {
        echo "| ThatsThem | https://thatsthem.com/name/${name_q} | Name + address + phone |"
        echo "| PeekYou | https://www.peekyou.com/${name_first,,}_${name_last,,} | Social + web presence |"
        echo "| IDCrawl | https://www.idcrawl.com/${name_q} | Aggregated profiles |"
        echo "| Webmii | https://webmii.com/people?n=${name_q} | Web mentions |"
        echo "| Spokeo | https://www.spokeo.com/search?q=${name_q} | Address history + relatives |"
        echo "| BeenVerified | https://www.beenverified.com/people-search/?firstName=${name_first}&lastName=${name_last} | Full background |"
        echo "| Intelius | https://www.intelius.com/people-search/results?FirstName=${name_first}&LastName=${name_last} | Background check |"
        echo "| FamilyTreeNow | https://www.familytreenow.com/search/genealogy/results?firstname=${name_first}&lastname=${name_last} | Family + address history |"
        echo "| usa-people-search | https://www.usa-people-search.com/people/${name_first}-${name_last} | USA records |"
        echo "| Snitch.name | https://snitch.name/${name_q} | Aggregator |"
        echo "| Lullar | https://com.lullar.com/search?q=${name_q} | Multi-site |"
        echo "| AnyWho | https://www.anywho.com/whitepages/people/${name_first}+${name_last} | Whitepages data |"
        echo "| Yasni | https://www.yasni.com/${name_first,,}+${name_last,,}/check+people | EU people search |"
        echo "| Pipl | https://pipl.com/search/?q=${name_q} | Deep web profiles |"
    }
    [[ -n "$email1" ]] && \
        echo "| ThatsThem (email) | https://thatsthem.com/email/${email1} | Email reverse lookup |"
    [[ -n "$phone_clean" ]] && \
        echo "| ThatsThem (phone) | https://thatsthem.com/phone/${phone_clean} | Phone reverse lookup |"
    echo ""

    echo "## 📞 Phone Lookup"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$phone_clean" ]] && {
        echo "| WhoCalld | https://whocalld.com/+1${phone_clean} | Caller ID + spam reports |"
        echo "| SpyDialer | https://www.spydialer.com/default.aspx | Reverse phone (free) |"
        echo "| TrueCaller | https://www.truecaller.com/search/us/${phone_clean} | Carrier + name |"
        echo "| Whitepages | https://www.whitepages.com/phone/1-${phone_clean:0:3}-${phone_clean:3:3}-${phone_clean:6:4} | Name + address |"
        echo "| AnyWho Reverse | https://www.anywho.com/reverse-lookup/${phone_clean:0:3}-${phone_clean:3:3}-${phone_clean:6:4} | Landline lookup |"
        echo "| FoneFinder | https://www.fonefinder.net/index.php?city=&state=&country=1&npa=${phone_clean:0:3}&nxx=${phone_clean:3:3}&thoublock=${phone_clean:6:4} | Carrier block info |"
        echo "| FamilyTreeNow | https://www.familytreenow.com/search/genealogy/results?phoneno=${phone_clean} | Owner history |"
        echo "| NumSpy | https://numspy.pythonanywhere.com/?q=${phone_clean} | Free HLR lookup |"
        echo "| OpenCNAM | https://api.opencnam.com/v2/phone/+1${phone_clean} | CNAM lookup |"
    }
    echo ""

    echo "## 📧 Email Investigation"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$email1" ]] && {
        echo "| HIBP | https://haveibeenpwned.com/account/${email1} | Breach check |"
        echo "| DeHashed | https://dehashed.com/search?query=${email1} | Credential leaks |"
        echo "| Hudson Rock | https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${email1} | Infostealer logs |"
        echo "| IntelX | https://intelx.io/?s=${email1} | Dark web + leaks |"
        echo "| Epieos | https://epieos.com/?q=${email1} | Google account recon |"
        echo "| Hunter.io | https://hunter.io/email-verifier/${email1} | Deliverability |"
        echo "| Emailrep | https://emailrep.io/${email1} | Reputation |"
    }
    echo ""

    echo "## 🌐 Username Search"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    for uname in "${USERNAMES[@]+"${USERNAMES[@]}"}"; do
        echo "| WhatsMyName | https://whatsmyname.app/ | Search: ${uname} |"
        echo "| Namechk | https://namechk.com/ | Search: ${uname} |"
        echo "| NameCheckup | https://namecheckup.com/ | Search: ${uname} |"
        echo "| Keybase | https://keybase.io/${uname} | Crypto identity |"
        echo "| GitHub | https://github.com/${uname} | Code repos |"
        echo "| GitHub API | https://api.github.com/users/${uname}/events/public | Activity |"
        echo "| ProtonMail | https://api.protonmail.ch/pks/lookup?op=index&search=${uname}@protonmail.com | ProtonMail check |"
    done
    echo ""

    echo "## 🔍 Search Engine Dorking"
    echo "| Dork | Link |"
    echo "|------|------|"
    [[ -n "$name_q" ]] && {
        echo "| Google name search | https://www.google.com/search?q=%22${name_q/+/+}%22 |"
        echo "| Google + LinkedIn | https://www.google.com/search?q=%22${name_q}%22+site:linkedin.com |"
        echo "| Google + Facebook | https://www.google.com/search?q=%22${name_q}%22+site:facebook.com |"
        echo "| Bing | https://www.bing.com/search?q=%22${name_q}%22 |"
        echo "| DuckDuckGo | https://duckduckgo.com/?q=%22${name_q}%22 |"
        echo "| Yandex | https://yandex.com/search/?text=${name_q} |"
    }
    [[ -n "$email1" ]] && \
        echo "| Google email | https://www.google.com/search?q=%22${email1}%22 |"
    echo ""

    echo "## 📚 Archives & Cached Pages"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$name_q" ]] && {
        echo "| Wayback Machine | https://web.archive.org/web/*/${name_q} | Archived pages |"
        echo "| Google Cache | https://webcache.googleusercontent.com/search?q=cache:${name_q} | Google cache |"
        echo "| CachedView | https://cachedview.nl/ | Multi-cache viewer |"
    }
    echo ""

    echo "## 📸 Reverse Image Search"
    echo "| Tool | Link |"
    echo "|------|------|"
    echo "| Google Lens | https://lens.google.com/upload |"
    echo "| TinEye | https://tineye.com/search |"
    echo "| Bing Visual Search | https://www.bing.com/visualsearch |"
    echo "| Yandex Images | https://yandex.com/images/ |"
    echo "| FaceCheck ID | https://facecheck.id/ |"
    echo "| PimEyes | https://pimeyes.com/en |"
    echo ""

    echo "## 🏢 Business & Court Records"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$name_q" ]] && {
        echo "| OpenCorporates | https://opencorporates.com/officers?q=${name_q} | Global company officers |"
        echo "| SEC EDGAR | https://efts.sec.gov/LATEST/search-index?q=%22${name_q}%22 | SEC filings |"
        echo "| PACER (Federal Courts) | https://pacer.gov/ | Federal court records |"
        echo "| UniCourt | https://unicourt.com/search#page=1;q=${name_q} | Court records |"
        echo "| BRB Pub | https://www.brbpub.com/ | Public records by state |"
    }
    echo ""

    echo "## 🌑 Dark Web & Breach Data"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$email1" ]] && \
        echo "| Ahmia | https://ahmia.fi/search/?q=${email1} | Tor search engine |"
    [[ -n "$name_q" ]] && \
        echo "| Ahmia | https://ahmia.fi/search/?q=${name_q} | Tor search engine |"
    echo "| DeHashed | https://dehashed.com/ | Breach credential DB |"
    echo "| IntelX | https://intelx.io/ | Leaks + pastes + dark web |"
    echo "| Snusbase | https://snusbase.com/ | Breach search |"
    echo ""

    echo "## 📍 Geolocation"
    echo "| Tool | Link | Notes |"
    echo "|------|------|-------|"
    [[ -n "$name_q" ]] && \
        echo "| Google Maps | https://www.google.com/maps/search/${name_q} | Map search |"
    for addr in "${ADDRESSES[@]+"${ADDRESSES[@]}"}"; do
        local enc_addr="${addr// /+}"
        echo "| Google Maps | https://www.google.com/maps/search/${enc_addr} | ${addr} |"
        echo "| Bing Maps | https://www.bing.com/maps?q=${enc_addr} | ${addr} |"
        echo "| Historic Aerials | https://www.historicaerials.com/?javascript=& | Check address history |"
    done
    echo ""

    echo "## 📱 Social Media Manual Search"
    echo "| Platform | Search Link |"
    echo "|----------|-------------|"
    [[ -n "$name_q" ]] && {
        echo "| Facebook | https://www.facebook.com/public?query=${name_q} |"
        echo "| Facebook ID lookup | https://lookup-id.com/ |"
        echo "| LinkedIn | https://www.linkedin.com/search/results/people/?keywords=${name_q} |"
        echo "| Twitter/X | https://twitter.com/search?q=%22${name_q}%22&f=user |"
        echo "| Instagram | https://www.instagram.com/explore/search/keyword/?q=${name_q} |"
        echo "| TikTok | https://www.tiktok.com/search/user?q=${name_q} |"
        echo "| Reddit | https://www.reddit.com/search/?q=${name_q}&type=user |"
        echo "| Reddit Metis | https://redditmetis.com/ |"
        echo "| YouTube | https://www.youtube.com/results?search_query=${name_q}&sp=EgIQAg%3D%3D |"
        echo "| Tumblr | https://www.tumblr.com/search/${name_q}/blogs |"
    }
    [[ -n "$email1" ]] && {
        echo "| FB Email Search | https://www.facebook.com/public?query=${email1} |"
        echo "| FB Account Recovery | https://www.facebook.com/login/identify?ctx=recover |"
    }
    echo ""

    echo "## 💍 Marriage / Registry / Obituary"
    echo "| Tool | Link |"
    echo "|------|------|"
    [[ -n "$name_q" ]] && {
        echo "| The Knot | https://www.theknot.com/registry/couplesearch?keyword=${name_q} |"
        echo "| MyRegistry | https://www.myregistry.com/giftlist/search?q=${name_q} |"
        echo "| Amazon Registry | https://www.amazon.com/wedding/search?q=${name_q} |"
        echo "| The Bump | https://registry.thebump.com/babyregistrysearch?q=${name_q} |"
        echo "| Legacy Obituaries | https://www.legacy.com/search?q=${name_q} |"
        echo "| Obituaries.com | https://www.obituaries.com/search/?q=${name_q} |"
    }
    echo ""

    echo "---"
    echo "*Generated by osint.sh v${VERSION} — OSINT Framework integration*"
    } > "$f"
    ok "Reference links → reference_links.md ($(grep -c '|' "$f" 2>/dev/null || echo '?') entries)"
}


# ════════════════════════════════════════════════════════════════════════════
#  PACKAGE
# ════════════════════════════════════════════════════════════════════════════

package_dossier() {
    section "PACKAGING DOSSIER"

    local zip_name="${SAFE_NAME}_investigation.zip"
    local zip_path="${DESKTOP}/${zip_name}"
    mkdir -p "$DESKTOP"

    step "Creating zip archive..."
    (cd /tmp && zip -r "$zip_path" "${OUTDIR##*/}" -x "*.DS_Store") 2>/dev/null
    ok "Dossier saved → ${zip_path}"

    local size
    size="$(du -sh "$zip_path" | cut -f1)"

    echo
    echo -e "${C}${BOLD}  ╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${C}${BOLD}  ║  INVESTIGATION COMPLETE                                  ║${RESET}"
    echo -e "${C}${BOLD}  ╠══════════════════════════════════════════════════════════╣${RESET}"
    printf  "${C}${BOLD}  ║  %-56s║${RESET}\n" "  Archive : ${zip_path}"
    printf  "${C}${BOLD}  ║  %-56s║${RESET}\n" "  Size    : ${size}"
    printf  "${C}${BOLD}  ║  %-56s║${RESET}\n" "  Depth   : ${MAX_DEPTH}"
    printf  "${C}${BOLD}  ║  %-56s║${RESET}\n" "  Temp dir: ${OUTDIR}"
    echo -e "${C}${BOLD}  ╚══════════════════════════════════════════════════════════╝${RESET}"
    echo
    info "To open: xdg-open ${DESKTOP}/${zip_name}"
    info "Temp dir kept at ${OUTDIR} — delete when done"
}


# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════

main() {
    for dep in curl jq dig whois nmap; do
        has_tool "$dep" || { echo "Error: required tool '$dep' not found."; exit 1; }
    done

    enter_data "$@"
    review
    select_phases

    section "SETTING UP WORKSPACE"
    setup_dirs
    mark_seed_known
    ok "Working directory: ${OUTDIR}"
    info "Pivot depth: ${MAX_DEPTH}"

    # ── Depth 0: seed data ───────────────────────────────────────────────────
    $RUN_EMAIL    && phase_email
    $RUN_USERNAME && phase_username
    $RUN_PHONE    && phase_phone
    $RUN_FULLNAME && phase_fullname
    $RUN_DOMAIN   && phase_domain
    $RUN_IP       && phase_ip
    $RUN_NETWORK  && phase_network
    $RUN_ADDRESS  && phase_address

    # ── Pivot: follow discovered entities ────────────────────────────────────
    if (( MAX_DEPTH > 0 )); then
        local depth
        for depth in $(seq 1 "$MAX_DEPTH"); do

            # Determine which directory to scan for new entities
            local scan_dir
            if (( depth == 1 )); then
                scan_dir="$OUTDIR"  # scan depth-0 output
            else
                scan_dir="${OUTDIR}/pivot/depth_$((depth-1))"
            fi

            extract_new_entities "$scan_dir"

            local total=$(( ${#PIVOT_EMAILS[@]} + ${#PIVOT_USERNAMES[@]} \
                          + ${#PIVOT_DOMAINS[@]} + ${#PIVOT_IPS[@]} \
                          + ${#PIVOT_NAMES[@]}   + ${#PIVOT_PHONES[@]} ))

            if (( total == 0 )); then
                section "PIVOT  —  DEPTH ${depth} / ${MAX_DEPTH}"
                info "No new entities found — investigation converged at depth $((depth-1))."
                break
            fi

            show_pivot_discovery "$depth"
            run_pivot_pass "$depth"
        done
    fi

    # ── ExifTool pass on any images downloaded during investigation ──────────
    if has_tool exiftool; then
        local img_out="${OUTDIR}/exif_metadata.txt"
        find "$OUTDIR" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" \
             -o -iname "*.gif" -o -iname "*.tiff" -o -iname "*.heic" \) \
             -exec exiftool {} \; 2>/dev/null > "$img_out" || true
        local img_count
        img_count="$(grep -c "^=======" "$img_out" 2>/dev/null || echo 0)"
        [[ "$img_count" -gt 0 ]] && ok "exiftool: extracted metadata from ${img_count} images → exif_metadata.txt"
    fi

    # ── Generate unified output files ────────────────────────────────────────
    section "GENERATING OUTPUT FILES"
    gen_reference_links
    gen_maltego
    gen_burp
    gen_recon_ng
    gen_spiderfoot
    gen_summary
    gen_readme

    # Dossier now lives on Desktop — no zip needed
}

main "$@"
