#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  se_email_security.sh — Email Spoofing Surface Analysis      ║
# ║  SPF/DKIM/DMARC enumeration + spoofability verdict (Phase 2) ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="se_email_security.sh"
SCRIPT_DESC="Email Security Analysis"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Analyze SPF, DKIM, and DMARC records for email spoofing surface."
    echo "  Produces composite spoofability verdict per domain."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "2" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ]; then
    err "Provide --domain or --domains"
    script_usage
    exit 1
fi

# ── Build domain list ──
domains_list="${OUT_DIR}/se_email_domains.txt"
> "$domains_list"
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    sed 's/\*\.//' "$DOMAINS_FILE" | sort -u >> "$domains_list"
fi
if [ -n "${DOMAIN:-}" ]; then
    echo "$DOMAIN" | sed 's/\*\.//' >> "$domains_list"
fi
sort -u -o "$domains_list" "$domains_list"

findings_file="${OUT_DIR}/email_findings.txt"
detail_file="${OUT_DIR}/email_detail.txt"
> "$findings_file"
> "$detail_file"

# ── Common DKIM selectors ──
DKIM_SELECTORS=(
    "default" "google" "selector1" "selector2"
    "k1" "k2" "k3" "dkim" "mail" "email"
    "s1" "s2" "mandrill" "amazonses" "sendgrid"
    "protonmail" "protonmail2" "protonmail3"
    "mimecast20190104" "fm1" "fm2" "fm3"
)

analyze_domain() {
    local domain="$1"
    info "Analyzing: ${domain}"
    local verdict="UNKNOWN"
    local spf_result="" dmarc_result="" dkim_found=0
    local spf_mechanism="" dmarc_policy="" dmarc_subdomain="" dmarc_pct=""

    echo "══════ ${domain} ══════" >> "$detail_file"

    # ── SPF Record ──
    local spf_record
    spf_record=$(dig +short TXT "$domain" 2>/dev/null | grep -i 'v=spf1' | tr -d '"' | head -1)

    if [ -n "$spf_record" ]; then
        echo "SPF: ${spf_record}" >> "$detail_file"

        # Check mechanism
        if echo "$spf_record" | grep -q '\-all'; then
            spf_mechanism="hardfail"
            spf_result="STRICT"
        elif echo "$spf_record" | grep -q '\~all'; then
            spf_mechanism="softfail"
            spf_result="PERMISSIVE"
        elif echo "$spf_record" | grep -q '?all'; then
            spf_mechanism="neutral"
            spf_result="WEAK"
        elif echo "$spf_record" | grep -q '+all'; then
            spf_mechanism="pass_all"
            spf_result="NONE"
        else
            spf_mechanism="no_all"
            spf_result="WEAK"
        fi

        # Count DNS lookups (include, a, mx, ptr, redirect, exists)
        local lookup_count=0
        lookup_count=$(echo "$spf_record" | grep -oP '(include:|a:|mx:|ptr:|redirect=|exists:)' | wc -l)
        if [ "$lookup_count" -gt 10 ]; then
            echo "SPF_WARNING: ${lookup_count} DNS lookups (>10 = permerror)" >> "$detail_file"
            spf_result="BROKEN"
        fi

        echo "SPF_MECHANISM: ${spf_mechanism} (${spf_result})" >> "$detail_file"
    else
        echo "SPF: NOT FOUND" >> "$detail_file"
        spf_result="MISSING"
    fi

    # ── DMARC Record ──
    local dmarc_record
    dmarc_record=$(dig +short TXT "_dmarc.${domain}" 2>/dev/null | grep -i 'v=DMARC1' | tr -d '"' | head -1)

    if [ -n "$dmarc_record" ]; then
        echo "DMARC: ${dmarc_record}" >> "$detail_file"

        # Extract policy
        dmarc_policy=$(echo "$dmarc_record" | grep -oP 'p=\K[^;]+' | tr -d ' ' | head -1)
        dmarc_subdomain=$(echo "$dmarc_record" | grep -oP 'sp=\K[^;]+' | tr -d ' ' | head -1)
        dmarc_pct=$(echo "$dmarc_record" | grep -oP 'pct=\K[0-9]+' | head -1)

        case "$dmarc_policy" in
            reject)   dmarc_result="STRICT" ;;
            quarantine) dmarc_result="MODERATE" ;;
            none)     dmarc_result="MONITOR_ONLY" ;;
            *)        dmarc_result="UNKNOWN" ;;
        esac

        # pct < 100 means not fully enforced
        if [ -n "$dmarc_pct" ] && [ "$dmarc_pct" -lt 100 ]; then
            echo "DMARC_WARNING: pct=${dmarc_pct}% (not fully enforced)" >> "$detail_file"
            dmarc_result="${dmarc_result}_PARTIAL"
        fi

        # Subdomain policy
        if [ -n "$dmarc_subdomain" ]; then
            echo "DMARC_SUBDOMAIN_POLICY: sp=${dmarc_subdomain}" >> "$detail_file"
            if [ "$dmarc_subdomain" = "none" ]; then
                echo "DMARC_WARNING: Subdomain policy is 'none' — subdomains spoofable" >> "$detail_file"
            fi
        fi

        echo "DMARC_POLICY: p=${dmarc_policy} (${dmarc_result})" >> "$detail_file"
    else
        echo "DMARC: NOT FOUND" >> "$detail_file"
        dmarc_result="MISSING"
    fi

    # ── DKIM Selectors ──
    echo "DKIM_PROBING: ${#DKIM_SELECTORS[@]} selectors" >> "$detail_file"
    local dkim_selectors_found=()
    for selector in "${DKIM_SELECTORS[@]}"; do
        local dkim_record
        dkim_record=$(dig +short TXT "${selector}._domainkey.${domain}" 2>/dev/null | head -1)
        if [ -n "$dkim_record" ] && echo "$dkim_record" | grep -qi 'v=DKIM1\|k=rsa\|p='; then
            dkim_selectors_found+=("$selector")
            ((dkim_found++)) || true
            echo "DKIM_FOUND: ${selector}._domainkey.${domain}" >> "$detail_file"
        fi
    done
    if [ "$dkim_found" -eq 0 ]; then
        echo "DKIM: No selectors found (${#DKIM_SELECTORS[@]} tested)" >> "$detail_file"
    else
        echo "DKIM: ${dkim_found} selector(s) found: ${dkim_selectors_found[*]}" >> "$detail_file"
    fi

    # ── MX Record ──
    local mx_records
    mx_records=$(dig +short MX "$domain" 2>/dev/null | sort -n)
    if [ -n "$mx_records" ]; then
        echo "MX:" >> "$detail_file"
        echo "$mx_records" | while IFS= read -r mx; do
            echo "  ${mx}" >> "$detail_file"
        done

        # Fingerprint mail provider
        local mail_provider="unknown"
        if echo "$mx_records" | grep -qi 'google\|gmail'; then
            mail_provider="Google Workspace"
        elif echo "$mx_records" | grep -qi 'outlook\|microsoft'; then
            mail_provider="Microsoft 365"
        elif echo "$mx_records" | grep -qi 'protonmail\|proton'; then
            mail_provider="ProtonMail"
        elif echo "$mx_records" | grep -qi 'mimecast'; then
            mail_provider="Mimecast"
        elif echo "$mx_records" | grep -qi 'barracuda'; then
            mail_provider="Barracuda"
        elif echo "$mx_records" | grep -qi 'pphosted\|proofpoint'; then
            mail_provider="Proofpoint"
        fi
        echo "MAIL_PROVIDER: ${mail_provider}" >> "$detail_file"
    else
        echo "MX: NOT FOUND" >> "$detail_file"
    fi

    # ── Composite Verdict ──
    if [ "$spf_result" = "MISSING" ] && [ "$dmarc_result" = "MISSING" ]; then
        verdict="SPOOFABLE_HIGH"
    elif [ "$dmarc_result" = "MISSING" ] && [[ "$spf_result" =~ ^(WEAK|NONE|PERMISSIVE|BROKEN)$ ]]; then
        verdict="SPOOFABLE_HIGH"
    elif [ "$dmarc_result" = "MONITOR_ONLY" ] || [[ "$dmarc_result" =~ PARTIAL ]]; then
        verdict="SPOOFABLE_MEDIUM"
    elif [ "$spf_result" = "MISSING" ] && [ "$dmarc_result" = "MODERATE" ]; then
        verdict="SPOOFABLE_MEDIUM"
    elif [ "$spf_result" = "BROKEN" ]; then
        verdict="SPOOFABLE_MEDIUM"
    elif [ "$dmarc_result" = "STRICT" ] && [ "$spf_result" = "STRICT" ] && [ "$dkim_found" -gt 0 ]; then
        verdict="NOT_SPOOFABLE"
    elif [ "$dmarc_result" = "STRICT" ] && [ "$spf_result" = "STRICT" ]; then
        verdict="LOW"
    elif [ "$dmarc_result" = "MODERATE" ] && [[ "$spf_result" =~ ^(STRICT|PERMISSIVE)$ ]]; then
        verdict="LOW"
    else
        verdict="SPOOFABLE_MEDIUM"
    fi

    echo "VERDICT: ${verdict}" >> "$detail_file"
    echo "" >> "$detail_file"

    # ── Write finding if spoofable ──
    if [[ "$verdict" =~ ^SPOOFABLE ]]; then
        local severity_tag
        if [ "$verdict" = "SPOOFABLE_HIGH" ]; then
            severity_tag="[P3:EMAIL_SPOOF:HIGH]"
        else
            severity_tag="[P3:EMAIL_SPOOF:MEDIUM]"
        fi
        echo "${severity_tag} ${domain} | SPF:${spf_result} DMARC:${dmarc_result} DKIM:${dkim_found}_selectors | ${verdict}" >> "$findings_file"
    fi
}

# ── Run analysis per domain ──
while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    analyze_domain "$domain"
done < "$domains_list"

# ── Nuclei DNS templates (if available) ──
if check_tool "nuclei" 2>/dev/null && [ -d "${NUCLEI_TEMPLATES}/dns" ]; then
    info "Running nuclei DNS templates..."
    nuclei_dns_out="${OUT_DIR}/nuclei_email_dns.txt"
    nuclei -l "$domains_list" -t "${NUCLEI_TEMPLATES}/dns/" -silent \
        "${HUNT_UA_ARGS[@]}" 2>/dev/null > "$nuclei_dns_out" || true
    if [ -s "$nuclei_dns_out" ]; then
        log "Nuclei DNS findings: $(count_lines "$nuclei_dns_out")"
        # Append relevant findings
        grep -iP '(spf|dmarc|dkim|email|mail)' "$nuclei_dns_out" >> "$findings_file" || true
    fi
fi

# ── Summary ──
finding_count=$(count_lines "$findings_file")
log "Email security findings: ${finding_count}"
if [ "$finding_count" -gt 0 ]; then
    warn "Spoofable domains found:"
    cat "$findings_file"
fi
log "Detailed analysis: ${detail_file}"
