#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  ap_soap_xxe.sh — SOAP & XXE Testing                        ║
# ║  WSDL discovery · ASMX/SVC/JWS probing · operation enum ·   ║
# ║  XXE injection · SOAP injection                              ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="ap_soap_xxe.sh"
SCRIPT_DESC="SOAP & XXE Testing"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover SOAP/WSDL endpoints, enumerate operations, and test"
    echo "  for XXE (XML External Entity) injection in SOAP request bodies"
    echo "  and other XML-accepting endpoints."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "6" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Output files ─────────────────────────────────────────────
> "${OUT_DIR}/ap_soap_xxe_findings.txt"
WSDL_DIR="${OUT_DIR}/wsdl_dumps"
mkdir -p "$WSDL_DIR"

# ── Build target list ────────────────────────────────────────
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("https://${d}")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("https://${DOMAIN}")
fi

# ── Counters ─────────────────────────────────────────────────
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
WSDL_COUNT=0

record_finding() {
    local severity="$1" url="$2" test_name="$3" detail="$4"
    echo "[${severity}] ${test_name} | ${url} | ${detail}" >> "${OUT_DIR}/ap_soap_xxe_findings.txt"
    case "$severity" in
        HIGH|CRITICAL) ((HIGH_COUNT++)) || true; warn "[${severity}] ${test_name}: ${url}" ;;
        MEDIUM)        ((MEDIUM_COUNT++)) || true; log "[MEDIUM] ${test_name}: ${url}" ;;
        *)             ((LOW_COUNT++)) || true ;;
    esac
}

# ── WSDL suffix patterns ────────────────────────────────────
WSDL_SUFFIXES=("?WSDL" "?wsdl" "?singlewsdl" "?singleWSDL")

# ── Common SOAP/WS endpoint paths ───────────────────────────
SOAP_PATHS=(
    "/service.asmx"
    "/services.asmx"
    "/webservice.asmx"
    "/api.asmx"
    "/ws/service.asmx"
    "/WebService.asmx"
    "/Service.asmx"
    "/Service.svc"
    "/services.svc"
    "/api.svc"
    "/ws.svc"
    "/WebService.svc"
    "/service.jws"
    "/ws/service"
    "/soap"
    "/soap/v1"
    "/soap/v2"
    "/ws"
    "/wso2"
    "/axis2/services"
    "/axis/services"
    "/services"
    "/CXF"
    "/cxf"
    "/metro"
)

# ── XML content-type paths to test for XXE ───────────────────
XML_PATHS=(
    "/api"
    "/upload"
    "/import"
    "/parse"
    "/process"
    "/submit"
    "/convert"
    "/transform"
    "/validate"
    "/xmlrpc.php"
    "/xmlrpc"
)

# ══════════════════════════════════════════════════════════════
# Stage 1: WSDL Discovery
# ══════════════════════════════════════════════════════════════
info "Stage 1: WSDL & SOAP endpoint discovery..."

DISCOVERED_SOAP="${OUT_DIR}/ap_soap_endpoints.txt"
> "$DISCOVERED_SOAP"

# Pull known SOAP URLs from earlier phases
if [ -f "${OUT_DIR}/ac_api_findings.txt" ] && [ -s "${OUT_DIR}/ac_api_findings.txt" ]; then
    grep -oP 'https?://[^\s]+\.(asmx|svc|jws)(\?[^\s]*)?' "${OUT_DIR}/ac_api_findings.txt" 2>/dev/null | sort -u >> "$DISCOVERED_SOAP"
    info "  Imported SOAP URLs from ac_api_findings.txt"
fi

# Pull from URLS_FILE
if [ -n "${URLS_FILE:-}" ] && [ -f "$URLS_FILE" ]; then
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        echo "$u" >> "$DISCOVERED_SOAP"
    done < "$URLS_FILE"
fi

# Probe common SOAP paths on each target
for base_url in "${targets[@]}"; do
    host=$(echo "$base_url" | sed 's|https\?://||;s|/.*||')
    info "  Probing: ${host}"

    for spath in "${SOAP_PATHS[@]}"; do
        soap_url="${base_url}${spath}"
        result=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}:%{size_download}" "$soap_url" 2>/dev/null || echo "000:0")
        status="${result%%:*}"
        size="${result##*:}"

        if [[ "$status" =~ ^(200|301|302|401|403)$ ]] && [ "${size:-0}" -gt 50 ]; then
            echo "$soap_url" >> "$DISCOVERED_SOAP"

            # Check response for SOAP indicators
            body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$soap_url" 2>/dev/null | head -100 || echo "")

            if echo "$body" | grep -qiE '(wsdl|soap|xmlns|envelope|service\s+description|asmx)'; then
                record_finding "MEDIUM" "$soap_url" "SOAP Endpoint" \
                    "SOAP/WSDL endpoint detected (HTTP ${status}, ${size}B)"
                log "    SOAP endpoint: ${soap_url} (HTTP ${status})"
            fi
        fi
    done
done

sort -u -o "$DISCOVERED_SOAP" "$DISCOVERED_SOAP"
soap_count=$(count_lines "$DISCOVERED_SOAP")
info "  Discovered ${soap_count} SOAP endpoint(s)"

# ══════════════════════════════════════════════════════════════
# Stage 2: WSDL extraction and operation enumeration
# ══════════════════════════════════════════════════════════════
info "Stage 2: WSDL extraction and operation enumeration..."

while IFS= read -r soap_url; do
    [ -z "$soap_url" ] && continue

    for suffix in "${WSDL_SUFFIXES[@]}"; do
        wsdl_url="${soap_url}${suffix}"
        wsdl_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -w "\n%{http_code}" "$wsdl_url" 2>/dev/null || echo "000")
        wsdl_code=$(echo "$wsdl_resp" | tail -1)
        wsdl_body=$(echo "$wsdl_resp" | sed '$d')

        if [ "$wsdl_code" = "200" ] && echo "$wsdl_body" | grep -qiE '(definitions|wsdl:|schema|service|portType|binding)'; then
            ((WSDL_COUNT++)) || true

            # Save WSDL to file
            safe_name=$(echo "$wsdl_url" | sed 's|https\?://||;s|[^a-zA-Z0-9._-]|_|g')
            wsdl_file="${WSDL_DIR}/${safe_name}.xml"
            echo "$wsdl_body" > "$wsdl_file"

            record_finding "HIGH" "$wsdl_url" "WSDL Exposed" \
                "Full WSDL document accessible — API surface enumerable"
            log "    WSDL saved: ${wsdl_file}"

            # Extract operations
            operations=$(echo "$wsdl_body" | python3 -c "
import sys, re
xml = sys.stdin.read()
# Operation names from portType/binding
ops = re.findall(r'<(?:wsdl:)?operation\s+name=[\"\\x27]([^\"\\x27]+)', xml)
# Element names from schema
elems = re.findall(r'<(?:s|xsd|xs):element\s+name=[\"\\x27]([^\"\\x27]+)', xml)
# Service names
services = re.findall(r'<(?:wsdl:)?service\s+name=[\"\\x27]([^\"\\x27]+)', xml)
# Port names with addresses
ports = re.findall(r'<(?:soap|soap12|http):address\s+location=[\"\\x27]([^\"\\x27]+)', xml)

if services:
    print(f'SERVICES: {', '.join(sorted(set(services)))}')
if ops:
    print(f'OPERATIONS ({len(set(ops))}): {', '.join(sorted(set(ops)))}')
if elems:
    print(f'ELEMENTS ({len(set(elems))}): {', '.join(sorted(set(elems))[:40])}')
if ports:
    print(f'ENDPOINTS: {', '.join(sorted(set(ports)))}')

# Flag sensitive operations
sens_ops = [o for o in set(ops) if any(kw in o.lower() for kw in ['admin', 'delete', 'user', 'password', 'config', 'upload', 'execute', 'command', 'file', 'debug', 'internal'])]
if sens_ops:
    print(f'SENSITIVE: {', '.join(sens_ops)}')
" 2>/dev/null || echo "")

            if [ -n "$operations" ]; then
                echo "  ${wsdl_url}:" >> "${OUT_DIR}/ap_soap_xxe_findings.txt"
                echo "$operations" | while IFS= read -r op_line; do
                    echo "    ${op_line}" >> "${OUT_DIR}/ap_soap_xxe_findings.txt"
                done

                # Check for sensitive operations
                if echo "$operations" | grep -q "SENSITIVE:"; then
                    sens_ops=$(echo "$operations" | grep "SENSITIVE:" | sed 's/SENSITIVE: //')
                    record_finding "HIGH" "$wsdl_url" "Sensitive SOAP Operations" \
                        "WSDL exposes sensitive operations: ${sens_ops}"
                fi
            fi

            break  # Found WSDL with this suffix, skip others
        fi
    done
done < "$DISCOVERED_SOAP"

# Also try WSDL on base targets (not just discovered SOAP paths)
for base_url in "${targets[@]}"; do
    for wsdl_path in "/wsdl" "/WSDL" "/service?wsdl" "/services?wsdl" "/api?wsdl"; do
        wsdl_url="${base_url}${wsdl_path}"
        wsdl_code=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -o /dev/null -w "%{http_code}" "$wsdl_url" 2>/dev/null || echo "000")
        if [ "$wsdl_code" = "200" ]; then
            wsdl_body=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$wsdl_url" 2>/dev/null | head -200 || echo "")
            if echo "$wsdl_body" | grep -qiE '(definitions|wsdl:|service|portType)'; then
                ((WSDL_COUNT++)) || true
                record_finding "HIGH" "$wsdl_url" "WSDL Exposed" \
                    "WSDL document accessible at non-standard path"
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 3: XXE injection testing
# ══════════════════════════════════════════════════════════════
info "Stage 3: XXE injection testing..."

# XXE payloads — safe probes that don't exfiltrate data
# We test for entity processing by checking if the entity is resolved
XXE_BASIC='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe_probe "XXE_PROBE_CANARY_12345">
]>
<test>&xxe_probe;</test>'

XXE_PARAMETER='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % xxe_param "XXE_PARAM_CANARY_67890">
  %xxe_param;
]>
<test>probe</test>'

# SOAP envelope with XXE
XXE_SOAP='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe_soap "XXE_SOAP_CANARY_24680">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe_soap;</test>
  </soap:Body>
</soap:Envelope>'

# Test SOAP endpoints for XXE
while IFS= read -r soap_url; do
    [ -z "$soap_url" ] && continue
    info "  XXE testing: ${soap_url}"

    # Test 1: Basic XML entity injection
    xxe_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/xml" \
        -d "$XXE_BASIC" \
        "$soap_url" 2>/dev/null || echo "")

    if echo "$xxe_resp" | grep -q "XXE_PROBE_CANARY_12345"; then
        record_finding "CRITICAL" "$soap_url" "XXE (Basic Entity)" \
            "XML external entity resolved — canary string reflected in response"
    fi

    # Test 2: SOAP envelope with XXE
    soap_xxe_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: text/xml" \
        -H "SOAPAction: test" \
        -d "$XXE_SOAP" \
        "$soap_url" 2>/dev/null || echo "")

    if echo "$soap_xxe_resp" | grep -q "XXE_SOAP_CANARY_24680"; then
        record_finding "CRITICAL" "$soap_url" "XXE (SOAP Envelope)" \
            "XXE in SOAP envelope — entity resolved in SOAP response"
    fi

    # Test 3: Check if XML is processed at all (DOCTYPE detection)
    if echo "$xxe_resp" | grep -qiE '(DOCTYPE|entity|SYSTEM|PUBLIC)'; then
        record_finding "MEDIUM" "$soap_url" "XXE (DTD Processing)" \
            "Server processes DTD declarations — XXE may be possible with out-of-band techniques"
    fi

    # Test 4: Error-based XXE detection
    xxe_error='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % xxe SYSTEM "file:///dev/null">
  %xxe;
]>
<test>error-probe</test>'

    error_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/xml" \
        -d "$xxe_error" \
        "$soap_url" 2>/dev/null || echo "")

    # Different error from a request with no DOCTYPE indicates DTD processing
    normal_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: application/xml" \
        -d '<?xml version="1.0"?><test>normal</test>' \
        "$soap_url" 2>/dev/null || echo "")

    if [ -n "$error_resp" ] && [ -n "$normal_resp" ] && [ "$error_resp" != "$normal_resp" ]; then
        error_size=${#error_resp}
        normal_size=${#normal_resp}
        size_diff=$(( error_size - normal_size ))
        [ "$size_diff" -lt 0 ] && size_diff=$(( -size_diff ))

        if [ "$size_diff" -gt 50 ]; then
            if echo "$error_resp" | grep -qiE '(file|system|entity|dtd|external|parse|xml)'; then
                record_finding "HIGH" "$soap_url" "XXE (Error-Based)" \
                    "DTD with SYSTEM entity triggers different error (${error_size}B vs ${normal_size}B) — OOB XXE likely"
            fi
        fi
    fi

done < "$DISCOVERED_SOAP"

# Test XML paths on base targets
for base_url in "${targets[@]}"; do
    for xml_path in "${XML_PATHS[@]}"; do
        test_url="${base_url}${xml_path}"

        # First check if endpoint accepts XML
        xml_check=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
            -X POST -H "Content-Type: application/xml" \
            -d '<?xml version="1.0"?><test>probe</test>' \
            -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null || echo "000")

        if [[ "$xml_check" =~ ^(200|201|400|500)$ ]]; then
            # Endpoint accepts XML — test for XXE
            xxe_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: application/xml" \
                -d "$XXE_BASIC" \
                "$test_url" 2>/dev/null || echo "")

            if echo "$xxe_resp" | grep -q "XXE_PROBE_CANARY_12345"; then
                record_finding "CRITICAL" "$test_url" "XXE (XML Endpoint)" \
                    "External entity resolved on XML-accepting endpoint"
            elif echo "$xxe_resp" | grep -qiE '(entity|DOCTYPE|SYSTEM|dtd)'; then
                record_finding "MEDIUM" "$test_url" "XXE (DTD Awareness)" \
                    "Endpoint processes XML DTD (HTTP ${xml_check}) — test with OOB techniques"
            fi

            # Also test Content-Type: text/xml
            xxe_text_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                -X POST -H "Content-Type: text/xml" \
                -d "$XXE_BASIC" \
                "$test_url" 2>/dev/null || echo "")

            if echo "$xxe_text_resp" | grep -q "XXE_PROBE_CANARY_12345"; then
                record_finding "CRITICAL" "$test_url" "XXE (text/xml)" \
                    "External entity resolved via text/xml content-type"
            fi
        fi
    done
done

# ══════════════════════════════════════════════════════════════
# Stage 4: SOAP injection testing
# ══════════════════════════════════════════════════════════════
info "Stage 4: SOAP injection testing..."

SOAP_INJECT='<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>
      <param>test</param></test><injected>true</injected><test><param>end</param>
    </test>
  </soap:Body>
</soap:Envelope>'

while IFS= read -r soap_url; do
    [ -z "$soap_url" ] && continue

    inject_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: text/xml" \
        -H "SOAPAction: test" \
        -d "$SOAP_INJECT" \
        "$soap_url" 2>/dev/null || echo "")

    if echo "$inject_resp" | grep -qiE '(injected|true)'; then
        record_finding "HIGH" "$soap_url" "SOAP Injection" \
            "Injected XML tags processed in SOAP body"
    fi

    # Test CDATA injection
    cdata_inject='<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test><![CDATA[<script>alert(1)</script>]]></test>
  </soap:Body>
</soap:Envelope>'

    cdata_resp=$(curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
        -X POST -H "Content-Type: text/xml" \
        -d "$cdata_inject" \
        "$soap_url" 2>/dev/null || echo "")

    if echo "$cdata_resp" | grep -qiE '<script>alert'; then
        record_finding "HIGH" "$soap_url" "SOAP CDATA Injection" \
            "CDATA content reflected unescaped in SOAP response"
    fi

done < "$DISCOVERED_SOAP"

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
total_findings=$(count_lines "${OUT_DIR}/ap_soap_xxe_findings.txt")

echo ""
log "SOAP & XXE testing complete:"
log "  SOAP endpoints:  ${soap_count}"
log "  WSDLs exposed:   ${WSDL_COUNT}"
log "  HIGH/CRITICAL:   ${HIGH_COUNT}"
log "  MEDIUM:          ${MEDIUM_COUNT}"
log "  LOW/INFO:        ${LOW_COUNT}"
log "  Total findings:  ${total_findings}"
log "Results:"
log "  ${OUT_DIR}/ap_soap_xxe_findings.txt"
[ "$WSDL_COUNT" -gt 0 ] && log "  WSDL dumps: ${WSDL_DIR}/"

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo ""
    warn "HIGH/CRITICAL findings:"
    grep -E '^\[(HIGH|CRITICAL)\]' "${OUT_DIR}/ap_soap_xxe_findings.txt" 2>/dev/null | while IFS= read -r line; do
        warn "  ${line}"
    done
fi
