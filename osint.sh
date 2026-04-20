#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  osint.sh v2.0  —  Interactive OSINT Investigation Framework
#  Output : ~/Desktop/{name}_investigation.zip
#  Import : Maltego  ·  Burp Suite  ·  recon-ng  ·  SpiderFoot
#
#  Pivot engine: after the initial pass, automatically extracts newly
#  discovered entities (emails, names, phones, IPs, domains) from tool
#  output and investigates them to the configured depth level.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DATE_HUMAN="$(date '+%Y-%m-%d %H:%M')"
DESKTOP="${HOME}/Desktop"
VERSION="2.0"

MAIGRET_BIN="/home/raze/.local/share/virtualenvs/operator_toolbox-X2A_8faL/bin/maigret"
SUBFINDER_BIN="${SCRIPT_DIR}/../subfinder"

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
RUN_ADDRESS=false

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
    echo "  ║   Investigation Framework  v${VERSION}  [pivot engine]        ║"
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
    collect PHONES    "Phone numbers"       "+1-555-867-5309, (212) 555-0100"
    collect USERNAMES "Usernames / handles" "janed_99, JaneDoe, jane.doe"
    collect FULLNAMES "Full names"          "Jane Doe, John A. Smith"
    collect DOMAINS   "Domains / websites"  "example.com, shop.example.com"
    collect IPS       "IP addresses"        "104.21.44.220, 192.168.1.1"
    collect ADDRESSES "Physical addresses"  "123 Main St Springfield IL 62701"
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
    OUTDIR="/tmp/${SAFE_NAME}_investigation_${TIMESTAMP}"

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
}

investigate_username() {
    local uname="$1" outdir="$2"

    if has_tool sherlock; then
        sherlock "$uname" --output "${outdir}/sherlock_${uname}.txt" \
            --timeout 10 2>/dev/null || true
        local hits
        hits="$(grep -c '^\[+\]' "${outdir}/sherlock_${uname}.txt" 2>/dev/null || echo 0)"
        ok "sherlock: ${hits} profiles  [${uname}]"
    fi

    if [[ -x "$MAIGRET_BIN" ]]; then
        mkdir -p "${outdir}/maigret_${uname}"
        "$MAIGRET_BIN" "$uname" \
            --folderoutput "${outdir}/maigret_${uname}" \
            --timeout 10 2>/dev/null || true
        ok "maigret done  [${uname}]"
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

    curl -s --max-time 8 \
        "http://apilayer.net/api/validate?access_key=free&number=${phone}" \
        2>/dev/null | jq '.' 2>/dev/null \
        > "${outdir}/carrier_${safe_p}.json" || true
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

    if python3 -m theHarvester --help &>/dev/null 2>&1; then
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
}

# Lighter IP scan for pivot passes (no nmap)
investigate_ip_light() {
    local ip="$1" outdir="$2"
    local safe_i="${ip//./_}"

    whois "$ip" 2>/dev/null > "${outdir}/whois/${safe_i}.txt" || true
    dig +short -x "$ip" 2>/dev/null > "${outdir}/reverse_dns/${safe_i}_rdns.txt" || true
    curl -s --max-time 8 "https://ipinfo.io/${ip}/json" 2>/dev/null \
        | jq '.' 2>/dev/null > "${outdir}/asn/${safe_i}_ipinfo.json" || true
    ok "IP light scan done  [${ip}]"
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
    offer_install sherlock sherlock
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
    while IFS= read -r val; do
        val="${val,,}"
        [[ -z "$val" ]] && continue
        [[ "$val" =~ noreply|no-reply|donotreply|example\.com|test\.|@sentry\.|@amplitude\. ]] && continue
        is_known email "$val" || PIVOT_EMAILS+=("$val")
    done < <(grep -rhoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
             "$search_dir" 2>/dev/null | sort -u) || true

    # ── IPs from DNS A records (skip private ranges) ─────────────────────────
    while IFS= read -r val; do
        [[ -z "$val" ]] && continue
        [[ "$val" =~ ^10\.|^192\.168\.|^127\.|^0\.|^169\.254\.|^255\. ]] && continue
        [[ "$val" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && continue
        is_known ip "$val" || PIVOT_IPS+=("$val")
    done < <(grep -rhoE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
             "${search_dir}"/{email_osint,domain_osint/dns} 2>/dev/null \
             | sort -u) || true

    # ── Subdomains from crt.sh / subfinder output ────────────────────────────
    while IFS= read -r val; do
        val="${val,,}"
        [[ -z "$val" || "$val" == "." ]] && continue
        [[ "$val" =~ ^\*\. ]] && val="${val:2}"
        # Only add if it looks like a real hostname (has at least one dot)
        [[ "$val" =~ \. ]] && is_known domain "$val" || continue
        is_known domain "$val" || PIVOT_DOMAINS+=("$val")
    done < <(find "${search_dir}" -name "*_all.txt" -path "*/subdomains/*" \
             -exec cat {} \; 2>/dev/null | grep -v '^#' | sort -u) || true

    # ── Names from WHOIS registrant fields ───────────────────────────────────
    while IFS= read -r val; do
        val="$(echo "$val" | xargs 2>/dev/null || echo "$val")"
        [[ -z "$val" ]] && continue
        is_known name "$val" || PIVOT_NAMES+=("$val")
    done < <(grep -rhi \
             -e 'Registrant Name:' -e 'Admin Name:' -e 'Tech Name:' \
             "${search_dir}" 2>/dev/null \
             | sed 's/.*:[[:space:]]*//' \
             | grep -vEi 'REDACTED|Privacy|Withheld|Ltd|LLC|Corp|Inc|GmbH|N\/A|^[[:space:]]*$' \
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
    if (( ${#PIVOT_USERNAMES[@]} > 0 )) && has_tool sherlock; then
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

    # ── Names: log them for Maltego, derive username candidates (already done) ─
    if (( ${#PIVOT_NAMES[@]} > 0 )); then
        log "[depth=${depth}] Discovered names: ${PIVOT_NAMES[*]}"
        for name in "${PIVOT_NAMES[@]}"; do mark_known name "$name"; done
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

        # Depth-0 sherlock profiles
        while IFS= read -r line; do
            [[ "$line" =~ ^\[\+\] ]] && \
                echo "maltego.URL,$(echo "$line" | awk '{print $NF}'),sherlock,0"
        done < <(cat "${OUTDIR}"/username_osint/sherlock_*.txt 2>/dev/null) || true

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

            # Sherlock profiles from pivot
            while IFS= read -r line; do
                [[ "$line" =~ ^\[\+\] ]] && \
                    echo "maltego.URL,$(echo "$line" | awk '{print $NF}'),pivot-sherlock,${depth}"
            done < <(cat "${pd}"/username_osint/sherlock_*.txt 2>/dev/null) || true

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
        echo "| sherlock social profiles | see username_osint/ + pivot/ |"
        echo "| nmap (depth 0 only) | see domain_osint/ + ip_osint/ |"

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
  OSINT INVESTIGATION DOSSIER  v2.0
  ${INVESTIGATION_NAME}
  Generated : ${DATE_HUMAN}
  Investigator: ${INVESTIGATOR}
  Pivot depth : ${MAX_DEPTH}
══════════════════════════════════════════════════════════════

DIRECTORY STRUCTURE
───────────────────
  seed/               Original seed data entered at start
  email_osint/        depth-0: holehe, DNS, WHOIS, theHarvester
  username_osint/     depth-0: sherlock, maigret
  phone_osint/        depth-0: phoneinfoga, carrier lookup
  domain_osint/       depth-0: WHOIS, DNS, subfinder, crt.sh, gau, nmap
  ip_osint/           depth-0: WHOIS, rDNS, ASN/geo, nmap, Shodan
  network_osint/      MAC vendors, SSID scan, Wigle
  address_osint/      Nominatim geocoding, map links
  pivot/
    depth_N/          Entities discovered and investigated at depth N
      discovered_entities.txt  — what triggered this depth
      email_osint/
      username_osint/
      domain_osint/   (WHOIS, DNS, subfinder, crt.sh — no nmap)
      ip_osint/       (WHOIS, rDNS, ASN/geo — no nmap)
  maltego/            entities.csv with all depths tagged
  burp/               scope.json + target_list.txt
  recon_ng/           workspace.rc (includes pivot-discovered entities)
  spiderfoot/         targets.txt
  summary.md          Full summary including pivot results
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

    # ── Generate unified output files ────────────────────────────────────────
    section "GENERATING OUTPUT FILES"
    gen_maltego
    gen_burp
    gen_recon_ng
    gen_spiderfoot
    gen_summary
    gen_readme

    package_dossier
}

main "$@"
