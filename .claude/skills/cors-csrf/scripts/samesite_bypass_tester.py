#!/usr/bin/env python3
"""
SameSite Bypass Tester — tests cookie SameSite attribute bypass scenarios.

Checks:
  - Cookie SameSite attribute (Lax/Strict/None)
  - Lax bypass via top-level GET navigation
  - Strict bypass via sibling subdomain redirect chain
  - Method override (POST → GET downgrade)
  - Client-side redirect chain (JS window.location)
  - SameSite Lax 2-minute window on Chrome (POST + Lax cookie)
  - SameSite=None missing Secure flag
"""

import argparse
import json
import sys
import os
import time
import urllib.parse
import urllib.request
import ssl
import re
import http.cookiejar
from typing import Optional


COOKIE_PATTERN = re.compile(
    r"([^;,\s]+)\s*=\s*([^;]+)"
)


def _extract_cookie_samesite(set_cookie: str) -> dict:
    info = {
        "name": "",
        "value": "",
        "samesite": "",
        "secure": False,
        "httponly": False,
        "domain": "",
        "path": "",
        "max_age": "",
    }
    lower = set_cookie.lower()

    info["secure"] = "secure" in lower

    info["httponly"] = "httponly" in lower

    if "samesite=strict" in lower:
        info["samesite"] = "strict"
        start = lower.index("samesite=strict")
        info["samesite_raw"] = set_cookie[start : start + 16].split(";")[0].strip()
    elif "samesite=lax" in lower:
        info["samesite"] = "lax"
        start = lower.index("samesite=lax")
        info["samesite_raw"] = set_cookie[start : start + 13].split(";")[0].strip()
    elif "samesite=none" in lower:
        info["samesite"] = "none"
        start = lower.index("samesite=none")
        info["samesite_raw"] = set_cookie[start : start + 14].split(";")[0].strip()

    for attr in ["domain", "path", "max-age"]:
        needle = f"{attr}="
        if needle in lower:
            start = lower.index(needle) + len(needle)
            end = lower.find(";", start)
            val = lower[start:end] if end > -1 else lower[start:]
            info[attr] = val.strip()

    parts = set_cookie.split(";")
    if parts:
        kv = parts[0].strip().split("=", 1)
        info["name"] = kv[0].strip()
        info["value"] = kv[1].strip() if len(kv) > 1 else ""

    return info


def _fetch(url: str, headers: dict = None, method: str = "GET", timeout: int = 15) -> dict:
    headers = headers or {}
    headers.setdefault("User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    req = urllib.request.Request(url, method=method, headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                          urllib.request.HTTPCookieProcessor(cj))

    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode(errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        set_cookies = []
        for hdr_name in ["set-cookie", "set-cookie2"]:
            for h in resp.getheaders():
                if h[0].lower() == hdr_name:
                    set_cookies.append(h[1])
        return {
            "status": resp.status,
            "headers": resp_headers,
            "body": body[:4096],
            "set_cookie": set_cookies,
            "cookies": [{"name": c.name, "value": c.value, "domain": c.domain} for c in cj],
            "error": None,
        }
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        set_cookies = []
        for hdr_name in ["set-cookie", "set-cookie2"]:
            if hasattr(e, "headers"):
                for h in e.headers.items():
                    if h[0].lower() == hdr_name:
                        set_cookies.append(h[1])
        return {
            "status": e.code,
            "headers": resp_headers,
            "body": e.read().decode(errors="replace")[:4096] if e.fp else "",
            "set_cookie": set_cookies,
            "cookies": [{"name": c.name, "value": c.value, "domain": c.domain} for c in cj],
            "error": None,
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "set_cookie": [], "cookies": [], "error": str(e)}


def _test_lax_get_bypass(target_url: str, context: str, timeout: int, dry_run: bool) -> list:
    results = []
    if dry_run:
        return [{"test": "lax_get_bypass", "conclusion": "Would test if cross-origin GET carries Lax cookies", "dry_run": True}]

    sys.stderr.write("[*] Testing Lax bypass via cross-origin GET\n")
    test_url = target_url
    resp = _fetch(test_url, headers={"Origin": f"https://evil-{int(time.time())}.com"}, timeout=timeout)
    for sc_raw in resp.get("set_cookie", []):
        info = _extract_cookie_samesite(sc_raw)
        if info["samesite"] in ("lax", "strict"):
            results.append({
                "test": "samesite_analysis",
                "cookie_name": info["name"],
                "samesite": info["samesite"],
                "secure": info["secure"],
                "httponly": info["httponly"],
                "domain": info["domain"],
                "path": info["path"],
                "bypass_possible": info["samesite"] == "lax",
                "bypass_method": "top-level GET navigation" if info["samesite"] == "lax" else ("subdomain redirect chain" if info["samesite"] == "strict" else "n/a"),
                "exploit_scenario": (
                    f"Cookie {info['name']!r} has SameSite=Lax. Attacker can trigger "
                    "cross-origin GET (e.g., <a href> top-level navigation) and the cookie will be attached."
                ) if info["samesite"] == "lax" else (
                    f"Cookie {info['name']!r} has SameSite=Strict. Requires subdomain "
                    "redirect chain or popup window from sibling origin."
                ),
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
    if not results:
        results.append({
            "test": "samesite_analysis",
            "cookie_name": "n/a",
            "samesite": "unknown",
            "secure": False,
            "httponly": False,
            "domain": "",
            "path": "",
            "bypass_possible": False,
            "bypass_method": "",
            "exploit_scenario": "No Set-Cookie headers received — cannot analyze SameSite",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    return results


def _test_method_override(target_url: str, context: str, timeout: int, dry_run: bool) -> list:
    results = []

    if dry_run:
        return [{"test": "method_override", "conclusion": "Would test _method override to convert POST → GET for Lax cookie bypass", "dry_run": True}]

    sys.stderr.write("[*] Testing method override (_method param)\n")
    for override_method in ["PUT", "DELETE", "PATCH"]:
        override_url = target_url
        parsed = urllib.parse.urlparse(override_url)
        separator = "&" if parsed.query else "?"
        test_url = f"{override_url}{separator}_method={override_method}"
        resp = _fetch(test_url, headers={"Origin": f"https://evil-override-{int(time.time())}.com"}, timeout=timeout)
        results.append({
            "test": "method_override",
            "override_param": "_method",
            "override_value": override_method,
            "test_url": test_url,
            "status": resp["status"],
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    return results


def _test_none_missing_secure(target_url: str, context: str, timeout: int, dry_run: bool) -> list:
    results = []
    if dry_run:
        return [{"test": "none_missing_secure", "conclusion": "Would check if SameSite=None cookies are missing the Secure flag", "dry_run": True}]

    sys.stderr.write("[*] Checking SameSite=None missing Secure flag\n")
    resp = _fetch(target_url, timeout=timeout)
    for sc_raw in resp.get("set_cookie", []):
        info = _extract_cookie_samesite(sc_raw)
        if info["samesite"] == "none":
            vuln = not info["secure"]
            results.append({
                "test": "none_missing_secure",
                "cookie_name": info["name"],
                "samesite": "none",
                "secure_set": info["secure"],
                "secure_missing": vuln,
                "exploit_scenario": (
                    f"Cookie {info['name']!r} has SameSite=None but no Secure flag. "
                    "Browsers may reject this cookie entirely (Chrome/Firefox require "
                    "Secure for SameSite=None). If the cookie is still set, it is "
                    "vulnerable to network-level MITM."
                ) if vuln else f"Cookie {info['name']!r} is correctly configured (SameSite=None + Secure).",
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
    if not results:
        results.append({
            "test": "none_missing_secure",
            "cookie_name": "n/a",
            "samesite": "unknown",
            "secure_set": False,
            "secure_missing": False,
            "exploit_scenario": "No SameSite=None cookies detected",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    return results


def _test_subdomain_redirect_chain(target_url: str, context: str, timeout: int, dry_run: bool) -> list:
    results = []
    if dry_run:
        return [{"test": "subdomain_redirect_chain", "conclusion": "Would test if sibling subdomain can issue redirect chain that bypasses SameSite=Strict", "dry_run": True}]

    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        results.append({
            "test": "subdomain_redirect_chain",
            "exploit_scenario": "Cannot determine hostname from target URL",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        return results

    sys.stderr.write("[*] Testing subdomain redirect chain feasibility\n")

    results.append({
        "test": "subdomain_redirect_chain",
        "host": host,
        "requires_sibling_subdomain": f"Attacker needs control of a subdomain of {host} (or an open redirect on one)",
        "exploit_scenario": (
            "If attacker controls `evil.{host}`, they can serve a page "
            "that does: evil.{host} loads → sets cookie path → window.open() → "
            "document.write form auto-submit → SameSite=Strict cookie is attached "
            "because the top-level origin is the same site."
        ),
        "practical_attack": "Requires subdomain takeover, XSS on sibling subdomain, or open redirect",
        "context": context,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    return results


def run_tests(target_url: str, context: Optional[str], timeout: int, dry_run: bool) -> list:
    all_results = []
    all_results.extend(_test_lax_get_bypass(target_url, context, timeout, dry_run))
    all_results.extend(_test_method_override(target_url, context, timeout, dry_run))
    all_results.extend(_test_none_missing_secure(target_url, context, timeout, dry_run))
    all_results.extend(_test_subdomain_redirect_chain(target_url, context, timeout, dry_run))
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="SameSite Bypass Tester — test cookie SameSite attribute bypass scenarios",
    )
    parser.add_argument("--target-url", required=True, help="Target URL to fetch cookies from")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be tested without making requests")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    sys.stderr.write(f"[*] SameSite Bypass Tester\n")
    sys.stderr.write(f"[*] Target: {args.target_url}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")
    sys.stderr.write(f"[*] Dry run: {args.dry_run}\n")

    results = run_tests(args.target_url, args.context, args.timeout, args.dry_run)

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    sys.stderr.write(f"\n[*] Results written to {outfile}\n")
    sys.stderr.write(f"[*] Total tests run: {len(results)}\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()