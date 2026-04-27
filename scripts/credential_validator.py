#!/usr/bin/env python3
"""
credential_validator.py — Validate Extracted Credentials Against APIs
Tests discovered API keys, tokens, and secrets for actual exploitability.
Converts P5 "key found in code" → P2+ "key exploited" findings.

Usage:
  python3 credential_validator.py -i secrets.txt -o validated.txt -t 10
  python3 credential_validator.py -i secrets.txt -o /dev/stdout --dry-run
  python3 credential_validator.py --scan-dir ./hunts/Target_20260301/ -o validated.txt
"""

import argparse
import base64
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Credential Patterns ──
PATTERNS = {
    "aws_access_key": re.compile(r'(AKIA[0-9A-Z]{16})'),
    "aws_secret_key": re.compile(r'(?:aws_secret_access_key|aws_secret|AWS_SECRET)["\s:=]+([A-Za-z0-9/+=]{40})'),
    "datadog_api_key": re.compile(r'(?:dd_api_key|datadog_api_key|DD_API_KEY|DATADOG_API_KEY)["\s:=]+([a-f0-9]{32})', re.I),
    "datadog_app_key": re.compile(r'(?:dd_app_key|datadog_app_key|DD_APP_KEY)["\s:=]+([a-f0-9]{40})', re.I),
    "datadog_client_token": re.compile(r'(pub[a-f0-9]{32})'),
    "google_api_key": re.compile(r'(AIza[0-9A-Za-z_-]{35})'),
    "google_oauth_secret": re.compile(r'(?:client_secret)["\s:=]+(GOCSPX-[A-Za-z0-9_-]{28})'),
    "stripe_secret": re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'),
    "stripe_publishable": re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'),
    "sendgrid_key": re.compile(r'(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})'),
    "twilio_sid": re.compile(r'(AC[a-f0-9]{32})'),
    "twilio_auth": re.compile(r'(?:auth_token|TWILIO_AUTH)["\s:=]+([a-f0-9]{32})', re.I),
    "slack_token": re.compile(r'(xox[bpoas]-[0-9]{10,}-[0-9a-zA-Z-]+)'),
    "slack_webhook": re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)'),
    "github_token": re.compile(r'(gh[ps]_[A-Za-z0-9_]{36,})'),
    "gitlab_token": re.compile(r'(glpat-[A-Za-z0-9_-]{20,})'),
    "sentry_dsn": re.compile(r'(https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+)'),
    "launchdarkly_sdk": re.compile(r'(sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'),
    "launchdarkly_client": re.compile(r'(?:clientSideID|ld_client)["\s:=]+([a-f0-9]{24})', re.I),
    "auth0_client_id": re.compile(r'(?:client_id|clientId|auth0_client)["\s:=]+([A-Za-z0-9]{32})', re.I),
    "firebase_key": re.compile(r'(AIza[0-9A-Za-z_-]{35})'),
    "mailgun_key": re.compile(r'(key-[0-9a-f]{32})'),
    "shopify_token": re.compile(r'(shpat_[a-fA-F0-9]{32})'),
    "heroku_api_key": re.compile(r'(?:HEROKU_API_KEY)["\s:=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.I),
    "mapbox_token": re.compile(r'(pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_-]{20,})'),
    "azure_sas": re.compile(r'(sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*?&sig=[A-Za-z0-9%/+=]+)'),
    "jwt_token": re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)'),
}

# Keys that are public by design and should NOT be reported
PUBLIC_BY_DESIGN = {
    "datadog_client_token",  # RUM client tokens are public
    "stripe_publishable",    # Publishable keys are public
    "firebase_key",          # Client-side Firebase keys are public
}

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "noleak"})
SESSION.verify = False
TIMEOUT = 10
FINDINGS = []
LOCK = threading.Lock()


def log_finding(severity, cred_type, key_preview, detail, source=""):
    """Thread-safe finding logger."""
    preview = key_preview[:12] + "..." if len(key_preview) > 15 else key_preview
    line = f"[{severity}:{cred_type}] {preview} | {detail}"
    if source:
        line += f" | source={source}"
    with LOCK:
        FINDINGS.append(line)
        print(f"  [+] {line}", file=sys.stderr)


# ── Validators ──

def validate_aws_key(access_key, secret_key=None, source=""):
    """Test AWS key via STS GetCallerIdentity."""
    if not secret_key:
        log_finding("P3:INFO", "AWS_KEY", access_key,
                    "Access key found but no secret key — cannot validate", source)
        return
    try:
        import hmac
        import hashlib
        from datetime import datetime, timezone
        # Use STS GetCallerIdentity — read-only, no side effects
        r = SESSION.get(
            "https://sts.amazonaws.com/",
            params={"Action": "GetCallerIdentity", "Version": "2011-06-15"},
            headers={"Authorization": f"AWS4-HMAC-SHA256 ..."},  # Would need proper SigV4
            timeout=TIMEOUT,
        )
        if r.status_code == 200 and "Arn" in r.text:
            log_finding("P1:CRIT", "AWS_KEY", access_key,
                        f"VALID — {r.text[:200]}", source)
        elif r.status_code == 403:
            log_finding("P3:LOW", "AWS_KEY", access_key,
                        "Key exists but forbidden (may be restricted)", source)
    except Exception:
        pass


def validate_datadog_api_key(key, source=""):
    """Test Datadog API key via validation endpoint."""
    try:
        r = SESSION.get(
            "https://api.datadoghq.com/api/v1/validate",
            headers={"DD-API-KEY": key},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("valid"):
                log_finding("P2:HIGH", "DATADOG_API", key,
                            "VALID — Full Datadog API access", source)
                return
        # Try EU endpoint
        r = SESSION.get(
            "https://api.datadoghq.eu/api/v1/validate",
            headers={"DD-API-KEY": key},
            timeout=TIMEOUT,
        )
        if r.status_code == 200 and r.json().get("valid"):
            log_finding("P2:HIGH", "DATADOG_API", key,
                        "VALID — Full Datadog EU API access", source)
            return
        log_finding("P5:INFO", "DATADOG_API", key, "INVALID key", source)
    except Exception as e:
        log_finding("P5:INFO", "DATADOG_API", key, f"Error: {e}", source)


def validate_google_api_key(key, source=""):
    """Test Google API key via Maps/custom search."""
    try:
        # Test against Maps API (free tier, no side effects)
        r = SESSION.get(
            f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}",
            timeout=TIMEOUT,
        )
        data = r.json()
        if data.get("status") == "OK":
            log_finding("P2:HIGH", "GOOGLE_API", key,
                        "VALID — Google Maps API access (pay-per-use abuse)", source)
        elif data.get("status") == "REQUEST_DENIED":
            # Key exists but restricted to specific APIs
            error = data.get("error_message", "")
            if "not authorized" in error.lower():
                log_finding("P4:LOW", "GOOGLE_API", key,
                            f"Key valid but restricted: {error[:100]}", source)
            else:
                log_finding("P5:INFO", "GOOGLE_API", key, f"Denied: {error[:100]}", source)
        elif data.get("error", {}).get("code") == 400:
            log_finding("P5:INFO", "GOOGLE_API", key, "INVALID key", source)
    except Exception:
        pass


def validate_stripe_secret(key, source=""):
    """Test Stripe secret key via balance endpoint."""
    try:
        r = SESSION.get(
            "https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            log_finding("P1:CRIT", "STRIPE_SECRET", key,
                        f"VALID — Stripe live secret key! Balance accessible", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "STRIPE_SECRET", key, "INVALID key", source)
        elif r.status_code == 403:
            log_finding("P3:MED", "STRIPE_SECRET", key,
                        "Key valid but restricted (RBP)", source)
    except Exception:
        pass


def validate_sendgrid_key(key, source=""):
    """Test SendGrid API key via scopes endpoint."""
    try:
        r = SESSION.get(
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {key}"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            scopes = r.json().get("scopes", [])
            log_finding("P2:HIGH", "SENDGRID", key,
                        f"VALID — {len(scopes)} scopes: {', '.join(scopes[:5])}", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "SENDGRID", key, "INVALID key", source)
    except Exception:
        pass


def validate_twilio(sid, auth_token=None, source=""):
    """Test Twilio SID/auth via account info endpoint."""
    if not auth_token:
        log_finding("P3:INFO", "TWILIO_SID", sid,
                    "SID found but no auth token — cannot validate", source)
        return
    try:
        r = SESSION.get(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
            auth=(sid, auth_token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            log_finding("P1:CRIT", "TWILIO", sid,
                        f"VALID — Account: {data.get('friendly_name','?')}, Status: {data.get('status','?')}", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "TWILIO", sid, "INVALID credentials", source)
    except Exception:
        pass


def validate_slack_token(token, source=""):
    """Test Slack token via auth.test."""
    try:
        r = SESSION.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=TIMEOUT,
        )
        data = r.json()
        if data.get("ok"):
            log_finding("P1:CRIT", "SLACK_TOKEN", token,
                        f"VALID — Team: {data.get('team','?')}, User: {data.get('user','?')}", source)
        else:
            log_finding("P5:INFO", "SLACK_TOKEN", token,
                        f"Invalid: {data.get('error','?')}", source)
    except Exception:
        pass


def validate_slack_webhook(url, source=""):
    """Test Slack webhook — POST check only, no message sent."""
    try:
        # Send empty payload to test if webhook is alive without posting a message
        r = SESSION.post(url, json={}, timeout=TIMEOUT)
        if r.status_code == 200 or "no_text" in r.text:
            log_finding("P3:MED", "SLACK_WEBHOOK", url.split("/")[-1],
                        "VALID — Webhook active (can post to channel)", source)
        elif r.status_code == 404:
            log_finding("P5:INFO", "SLACK_WEBHOOK", url.split("/")[-1],
                        "Webhook removed/invalid", source)
    except Exception:
        pass


def validate_github_token(token, source=""):
    """Test GitHub token via user endpoint."""
    try:
        r = SESSION.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            log_finding("P1:CRIT", "GITHUB_TOKEN", token,
                        f"VALID — User: {data.get('login','?')}, Repos: {data.get('public_repos','?')}", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "GITHUB_TOKEN", token, "INVALID/expired", source)
    except Exception:
        pass


def validate_gitlab_token(token, source=""):
    """Test GitLab token via user endpoint."""
    try:
        r = SESSION.get(
            "https://gitlab.com/api/v4/user",
            headers={"PRIVATE-TOKEN": token},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            log_finding("P1:CRIT", "GITLAB_TOKEN", token,
                        f"VALID — User: {data.get('username','?')}, Admin: {data.get('is_admin',False)}", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "GITLAB_TOKEN", token, "INVALID/expired", source)
    except Exception:
        pass


def validate_sentry_dsn(dsn, source=""):
    """Test Sentry DSN — can inject fake error events."""
    try:
        # Parse DSN: https://{key}@{host}/{project_id}
        m = re.match(r'https://([a-f0-9]+)@(.+)/(\d+)', dsn)
        if not m:
            return
        key, host, project_id = m.groups()
        # Test envelope endpoint (Sentry SDK uses this)
        envelope = f'{{"dsn":"{dsn}"}}\n{{"type":"event"}}\n{{"message":"bugcrowd-test","level":"info"}}'
        r = SESSION.post(
            f"https://{host}/api/{project_id}/envelope/",
            headers={"Content-Type": "application/x-sentry-envelope",
                     "X-Sentry-Auth": f"Sentry sentry_key={key}, sentry_version=7"},
            data=envelope,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            log_finding("P4:LOW", "SENTRY_DSN", key[:12],
                        f"VALID — Can inject events into project {project_id} at {host}", source)
        elif r.status_code == 401 or r.status_code == 403:
            log_finding("P5:INFO", "SENTRY_DSN", key[:12],
                        f"DSN rejected: {r.status_code}", source)
    except Exception:
        pass


def validate_launchdarkly(client_id, source=""):
    """Test LaunchDarkly client ID — enumerate feature flags."""
    try:
        user_key = base64.b64encode(b'{"key":"anonymous"}').decode()
        r = SESSION.get(
            f"https://clientsdk.launchdarkly.com/sdk/evalx/{client_id}/contexts/{user_key}",
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            try:
                flags = r.json()
                flag_count = len(flags) if isinstance(flags, dict) else 0
                # Look for security-relevant flags
                sec_flags = [k for k in flags.keys() if any(
                    w in k.lower() for w in ["admin", "auth", "sso", "debug", "bypass",
                                              "security", "access", "permission", "secret",
                                              "internal", "disable", "enable"]
                )] if isinstance(flags, dict) else []
                sec_detail = f", security flags: {sec_flags[:5]}" if sec_flags else ""
                log_finding("P3:MED", "LAUNCHDARKLY", client_id[:12],
                            f"VALID — {flag_count} flags enumerated{sec_detail}", source)
            except json.JSONDecodeError:
                log_finding("P4:LOW", "LAUNCHDARKLY", client_id[:12],
                            "Response received but not JSON", source)
        elif r.status_code == 404:
            log_finding("P5:INFO", "LAUNCHDARKLY", client_id[:12],
                        "INVALID client ID", source)
    except Exception:
        pass


def validate_mailgun_key(key, source=""):
    """Test Mailgun API key via domains endpoint."""
    try:
        r = SESSION.get(
            "https://api.mailgun.net/v3/domains",
            auth=("api", key),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            domains = [d["name"] for d in data.get("items", [])]
            log_finding("P1:CRIT", "MAILGUN", key,
                        f"VALID — {len(domains)} domains: {', '.join(domains[:3])}", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "MAILGUN", key, "INVALID key", source)
    except Exception:
        pass


def validate_shopify_token(token, source=""):
    """Test Shopify admin token via shop endpoint."""
    try:
        # Shopify tokens need a shop domain — try common patterns
        r = SESSION.get(
            "https://admin.shopify.com/api/2024-01/shop.json",
            headers={"X-Shopify-Access-Token": token},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            log_finding("P1:CRIT", "SHOPIFY", token,
                        "VALID — Shopify admin API access", source)
    except Exception:
        pass


def validate_mapbox_token(token, source=""):
    """Test Mapbox token via token metadata endpoint."""
    try:
        r = SESSION.get(
            f"https://api.mapbox.com/tokens/v2?access_token={token}",
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            # Mapbox public tokens are expected — only report secret tokens
            if data.get("token", {}).get("usage") == "sk":
                log_finding("P2:HIGH", "MAPBOX_SECRET", token[:20],
                            f"VALID — Secret token! Scopes: {data.get('token',{}).get('scopes',[])}", source)
            else:
                log_finding("P5:INFO", "MAPBOX_PUB", token[:20],
                            "Public token (by design)", source)
    except Exception:
        pass


def validate_heroku_key(key, source=""):
    """Test Heroku API key via account endpoint."""
    try:
        r = SESSION.get(
            "https://api.heroku.com/account",
            headers={"Authorization": f"Bearer {key}",
                     "Accept": "application/vnd.heroku+json; version=3"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            log_finding("P1:CRIT", "HEROKU", key[:12],
                        f"VALID — Email: {data.get('email','?')}", source)
        elif r.status_code == 401:
            log_finding("P5:INFO", "HEROKU", key[:12], "INVALID key", source)
    except Exception:
        pass


def validate_jwt(token, source=""):
    """Analyze JWT token claims for interesting data."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return
        # Decode header and payload (without verification)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

        # Check expiration
        exp = payload.get("exp")
        now = time.time()
        expired = exp and exp < now

        # Check interesting claims
        interesting = {}
        for key in ["admin", "role", "roles", "scope", "scopes", "permissions",
                     "is_admin", "is_staff", "group", "groups", "aud", "iss",
                     "email", "sub", "name", "org", "tenant"]:
            if key in payload:
                interesting[key] = payload[key]

        alg = header.get("alg", "?")
        iss = payload.get("iss", "?")

        if interesting:
            severity = "P3:MED" if not expired else "P4:LOW"
            detail = f"alg={alg} iss={iss} expired={expired} claims={json.dumps(interesting)[:150]}"
            log_finding(severity, "JWT", token[:20], detail, source)
    except Exception:
        pass


# ── Main Scan Logic ──

def validate_nuclei_extracted(value, source=""):
    """Try to identify and validate nuclei-extracted secrets."""
    # Try each specific validator based on value format
    if value.startswith("AKIA"):
        validate_aws_key(value, source=source)
    elif value.startswith("sk_live_"):
        validate_stripe_secret(value, source)
    elif value.startswith("SG."):
        validate_sendgrid_key(value, source)
    elif value.startswith("xox"):
        validate_slack_token(value, source)
    elif value.startswith("gh") and "_" in value:
        validate_github_token(value, source)
    elif value.startswith("glpat-"):
        validate_gitlab_token(value, source)
    elif "sentry.io" in value:
        validate_sentry_dsn(value, source)
    elif len(value) == 32 and all(c in "0123456789abcdef" for c in value):
        # Could be Datadog API key
        validate_datadog_api_key(value, source)
    elif value.startswith("AIza"):
        validate_google_api_key(value, source)
    else:
        log_finding("P4:INFO", "EXTRACTED", value[:15],
                    "Unidentified secret — manual review needed", source)


VALIDATOR_MAP = {
    "aws_access_key": lambda k, s: validate_aws_key(k, source=s),
    "datadog_api_key": validate_datadog_api_key,
    "datadog_app_key": validate_datadog_api_key,
    "google_api_key": validate_google_api_key,
    "stripe_secret": validate_stripe_secret,
    "sendgrid_key": validate_sendgrid_key,
    "twilio_sid": lambda k, s: validate_twilio(k, source=s),
    "slack_token": validate_slack_token,
    "slack_webhook": validate_slack_webhook,
    "github_token": validate_github_token,
    "gitlab_token": validate_gitlab_token,
    "sentry_dsn": validate_sentry_dsn,
    "launchdarkly_sdk": validate_launchdarkly,
    "launchdarkly_client": validate_launchdarkly,
    "mailgun_key": validate_mailgun_key,
    "shopify_token": validate_shopify_token,
    "mapbox_token": validate_mapbox_token,
    "heroku_api_key": validate_heroku_key,
    "jwt_token": validate_jwt,
    "nuclei_extracted": validate_nuclei_extracted,
    "auth0_client_id": lambda k, s: log_finding("P5:INFO", "AUTH0_CLIENT", k[:15],
                                                  "Client ID (public by design in OIDC)", s),
}


def extract_credentials(text, source=""):
    """Extract all credentials from text using regex patterns."""
    creds = []
    for cred_type, pattern in PATTERNS.items():
        if cred_type in PUBLIC_BY_DESIGN:
            continue
        for match in pattern.finditer(text):
            value = match.group(1)
            # Skip very short matches (likely false positives)
            if len(value) < 10:
                continue
            # Deduplicate
            if not any(c["value"] == value for c in creds):
                creds.append({
                    "type": cred_type,
                    "value": value,
                    "source": source,
                })

    # Also extract from nuclei-format output: ["KEY = "value""]
    nuclei_pattern = re.compile(
        r'\["(?:CLIENT_SECRET|API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|'
        r'apiKey|api_key|secret|token|password|credential|AWS_ACCESS_KEY_ID|'
        r'AWS_SECRET_ACCESS_KEY|DATADOG_API_KEY|SENTRY_DSN|SENDGRID_API_KEY|'
        r'SLACK_TOKEN|GITHUB_TOKEN)\s*[=:]\s*"([^"]{10,})"', re.I
    )
    for match in nuclei_pattern.finditer(text):
        value = match.group(1)
        if not any(c["value"] == value for c in creds):
            creds.append({
                "type": "nuclei_extracted",
                "value": value,
                "source": source,
            })

    # Extract Sentry DSNs from any format
    sentry_pattern = re.compile(r'(https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.(?:us\.)?sentry\.io/\d+)')
    for match in sentry_pattern.finditer(text):
        value = match.group(1)
        if not any(c["value"] == value for c in creds):
            creds.append({
                "type": "sentry_dsn",
                "value": value,
                "source": source,
            })

    # Extract LaunchDarkly IDs from any format (24-char hex)
    ld_pattern = re.compile(r'(?:clientSideID|launchDarkly|launch_darkly|ld_client_id)["\s:=]+["\']?([a-f0-9]{24})["\']?', re.I)
    for match in ld_pattern.finditer(text):
        value = match.group(1)
        if not any(c["value"] == value for c in creds):
            creds.append({
                "type": "launchdarkly_client",
                "value": value,
                "source": source,
            })

    return creds


def scan_file(filepath):
    """Scan a single file for credentials."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        return extract_credentials(content, source=str(filepath))
    except Exception:
        return []


def scan_directory(dirpath):
    """Recursively scan a directory for credentials."""
    creds = []
    extensions = {".txt", ".json", ".js", ".html", ".xml", ".yaml", ".yml",
                  ".env", ".cfg", ".conf", ".log", ".csv", ".map"}
    dirpath = Path(dirpath)

    # Priority files from hunt.sh output
    priority_files = [
        "secretfinder_results.txt",
        "nuclei_js_secrets.txt",
        "cariddi_results.txt",
        "grep_secrets.txt",
        "js_endpoints.txt",
    ]

    for pf in priority_files:
        p = dirpath / pf
        if p.exists():
            print(f"  [*] Scanning priority file: {pf}", file=sys.stderr)
            creds.extend(scan_file(p))

    # Scan JS downloads
    js_dir = dirpath / "js_downloads"
    if js_dir.exists():
        js_files = list(js_dir.glob("*.js"))
        print(f"  [*] Scanning {len(js_files)} JS files...", file=sys.stderr)
        for jf in js_files:
            creds.extend(scan_file(jf))

    # Scan other relevant files
    for fp in dirpath.rglob("*"):
        if fp.is_file() and fp.suffix in extensions and fp.name not in priority_files:
            if fp.stat().st_size < 10_000_000:  # Skip files > 10MB
                creds.extend(scan_file(fp))

    return creds


def validate_credential(cred, dry_run=False):
    """Validate a single credential."""
    cred_type = cred["type"]
    value = cred["value"]
    source = cred["source"]

    if dry_run:
        print(f"  [DRY-RUN] Would validate {cred_type}: {value[:20]}... (from {source})",
              file=sys.stderr)
        return

    validator = VALIDATOR_MAP.get(cred_type)
    if validator:
        try:
            validator(value, source)
        except TypeError:
            # Some validators take different args
            validator(value, source=source)
    else:
        log_finding("P5:INFO", cred_type.upper(), value[:15],
                    f"No validator — manual review needed", source)


def main():
    parser = argparse.ArgumentParser(
        description="Validate extracted credentials against live APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i secrets.txt -o validated.txt
  %(prog)s --scan-dir ./hunts/Target_20260301/ -o validated.txt
  %(prog)s -i secrets.txt -o /dev/stdout --dry-run
        """,
    )
    parser.add_argument("-i", "--input", help="File with raw text containing credentials")
    parser.add_argument("--scan-dir", help="Hunt output directory to scan recursively")
    parser.add_argument("-o", "--output", default="validated_credentials.txt",
                        help="Output file for validated findings")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Concurrent validation threads (default: 10)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Extract but don't validate credentials")
    parser.add_argument("--json", action="store_true",
                        help="Output findings as JSON")
    args = parser.parse_args()

    if not args.input and not args.scan_dir:
        parser.error("Either -i/--input or --scan-dir is required")

    print("[*] Credential Validator v1.0", file=sys.stderr)

    # ── Extract Credentials ──
    all_creds = []

    if args.input:
        print(f"[*] Scanning input file: {args.input}", file=sys.stderr)
        all_creds.extend(scan_file(args.input))

    if args.scan_dir:
        print(f"[*] Scanning hunt directory: {args.scan_dir}", file=sys.stderr)
        all_creds.extend(scan_directory(args.scan_dir))

    # Deduplicate by value
    seen = set()
    unique_creds = []
    for c in all_creds:
        if c["value"] not in seen:
            seen.add(c["value"])
            unique_creds.append(c)

    print(f"[*] Found {len(unique_creds)} unique credentials ({len(all_creds)} total matches)",
          file=sys.stderr)

    # Group by type for summary
    type_counts = {}
    for c in unique_creds:
        type_counts[c["type"]] = type_counts.get(c["type"], 0) + 1
    for ctype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {ctype}: {count}", file=sys.stderr)

    if not unique_creds:
        print("[!] No credentials found", file=sys.stderr)
        sys.exit(0)

    # ── Validate ──
    print(f"\n[*] Validating {len(unique_creds)} credentials "
          f"({'DRY RUN' if args.dry_run else f'{args.threads} threads'})...",
          file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(validate_credential, cred, args.dry_run): cred
            for cred in unique_creds
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                cred = futures[future]
                print(f"  [!] Error validating {cred['type']}: {e}", file=sys.stderr)

    # ── Output ──
    if args.json:
        output = json.dumps([{"finding": f} for f in FINDINGS], indent=2)
    else:
        output = "\n".join(FINDINGS)

    if args.output == "/dev/stdout":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output + "\n")
        print(f"\n[*] {len(FINDINGS)} findings written to {args.output}", file=sys.stderr)

    # Summary
    valid = [f for f in FINDINGS if "VALID" in f or "P1:" in f or "P2:" in f]
    print(f"[*] Summary: {len(valid)} VALID credentials, "
          f"{len(FINDINGS)} total findings", file=sys.stderr)


if __name__ == "__main__":
    main()
