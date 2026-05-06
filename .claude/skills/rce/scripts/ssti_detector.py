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

SSTI_POLYGLOT = "${{<%[%'\"}}%\\"

SSTI_PAYLOADS = [
    {"payload": "{{7*7}}", "name": "jinja2_twig_double_braces", "engine": "Jinja2 / Twig / Django (misconfig)", "detect_output": "49"},
    {"payload": "${7*7}", "name": "freemarker_velocity_dollar", "engine": "FreeMarker / Velocity", "detect_output": "49"},
    {"payload": "<%= 7*7 %>", "name": "eruby_erb_percent", "engine": "ERB / eRuby", "detect_output": "49"},
    {"payload": "#{7*7}", "name": "ruby_string_interp", "engine": "Ruby string interpolation", "detect_output": "49"},
    {"payload": "{{= 7*7 }}", "name": "tornado_express_equal", "engine": "Tornado / Express-like", "detect_output": "49"},
    {"payload": "${{7*7}}", "name": "groovy_gstring", "engine": "Groovy GString", "detect_output": "49"},
    {"payload": "{{=7*7}}", "name": "tornado_equal_tight", "engine": "Tornado", "detect_output": "49"},
    {"payload": "{{#expr}}{{7*7}}{{/expr}}", "name": "handlebars_expr_block", "engine": "Handlebars (with helpers)", "detect_output": "49"},
    {"payload": "{{%7*7}}", "name": "custom_percent_braces", "engine": "Custom / Unknown", "detect_output": "49"},
    {"payload": "{% print(7*7) %}", "name": "jinja2_tag_print", "engine": "Jinja2 / Twig", "detect_output": "49"},
    {"payload": "{% if 7*7==49 %}Yes{% endif %}", "name": "jinja2_if_tag", "engine": "Jinja2 / Twig", "detect_output": "Yes"},
    {"payload": "${7*7}", "name": "velocity_dollar_brace", "engine": "Velocity", "detect_output": "49", "header": "User-Agent"},
    {"payload": "@(7*7)", "name": "razor_at_paren", "engine": "Razor", "detect_output": "49"},
    {"payload": "${'7'*7}", "name": "freemarker_repeat_string", "engine": "FreeMarker", "detect_output": "7777777"},
    {"payload": "{% debug %}", "name": "jinja2_debug", "engine": "Jinja2 / Twig", "detect_output": None},
]

SSTI_ERROR_SIGNATURES = {
    "Jinja2": [
        re.compile(r"jinja2\.exceptions\.", re.IGNORECASE),
        re.compile(r"TemplateSyntaxError", re.IGNORECASE),
        re.compile(r"UndefinedError", re.IGNORECASE),
        re.compile(r"File .*jinja2.*\.py", re.IGNORECASE),
    ],
    "Twig": [
        re.compile(r"Twig_Error", re.IGNORECASE),
        re.compile(r"Unknown\s+\"[^\"]+\"\s+in\s+.*\.twig", re.IGNORECASE),
        re.compile(r"twig.*runtimeerror", re.IGNORECASE),
    ],
    "FreeMarker": [
        re.compile(r"freemarker\.", re.IGNORECASE),
        re.compile(r"FreeMarker template error", re.IGNORECASE),
        re.compile(r"Expression .* is undefined", re.IGNORECASE),
    ],
    "Velocity": [
        re.compile(r"velocity\.exception", re.IGNORECASE),
        re.compile(r"org\.apache\.velocity", re.IGNORECASE),
    ],
    "ERB": [
        re.compile(r"\(erb\):", re.IGNORECASE),
        re.compile(r"SyntaxError in.*\.erb", re.IGNORECASE),
    ],
    "Smarty": [
        re.compile(r"SmartyCompilerException", re.IGNORECASE),
        re.compile(r"Smarty error", re.IGNORECASE),
    ],
    "Handlebars": [
        re.compile(r"handlebars", re.IGNORECASE),
        re.compile(r"Parse error on line", re.IGNORECASE),
        re.compile(r"handlebars\.runtime", re.IGNORECASE),
    ],
    "Mustache": [
        re.compile(r"MustacheException", re.IGNORECASE),
    ],
    "Pug/Jade": [
        re.compile(r"pug.*error", re.IGNORECASE),
        re.compile(r"jade.*error", re.IGNORECASE),
    ],
    "Slim": [
        re.compile(r"Slim::Parser::SyntaxError", re.IGNORECASE),
    ],
    "Mako": [
        re.compile(r"Mako.*error", re.IGNORECASE),
        re.compile(r"mako\.exceptions", re.IGNORECASE),
    ],
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


def detect_ssti_error(response_text, detect_output):
    detected_engine = None
    for engine, sigs in SSTI_ERROR_SIGNATURES.items():
        for sig in sigs:
            if sig.search(response_text):
                detected_engine = engine
                break
        if detected_engine:
            break
    if detected_engine:
        return detected_engine
    if detect_output and detect_output in response_text:
        for pdef in SSTI_PAYLOADS:
            if pdef.get("detect_output") == detect_output:
                return pdef.get("engine", "Unknown")
    return None


def compute_confidence(engine_detected, output_found, payload_name):
    if engine_detected and output_found:
        return 0.9
    elif engine_detected:
        return 0.7
    elif output_found:
        return 0.6
    return 0.3


def test_ssti_payload(url, param, pdef, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload": pdef["payload"],
        "payload_name": pdef["name"],
        "expected_engine": pdef.get("engine", "Unknown"),
        "technique": "ssti",
        "detected_engine": None,
        "output_match": False,
        "error_match": False,
        "polyglot_reflected": False,
        "status_code": 0,
        "response_length": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        test_url = inject_payload(url, param, pdef["payload"])
        print(f"[dry-run] SSTI: {test_url} engine={pdef.get('engine', 'Unknown')}", file=sys.stderr)
        return result
    try:
        detect_output = pdef.get("detect_output")
        test_url = inject_payload(url, param, pdef["payload"])
        if pdef.get("header"):
            custom_headers = {pdef["header"]: pdef["payload"]}
            resp = session.get(test_url, headers=custom_headers, timeout=timeout, allow_redirects=True)
        else:
            resp = session.get(test_url, timeout=timeout, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)
        output_found = False
        if detect_output and detect_output in resp.text:
            output_found = True
            result["output_match"] = True
        if output_found:
            snippet_idx = resp.text.find(detect_output)
            start = max(0, snippet_idx - 40)
            end = min(len(resp.text), snippet_idx + len(detect_output) + 60)
            result["evidence"] = resp.text[start:end]
        detected_engine = detect_ssti_error(resp.text, detect_output)
        result["detected_engine"] = detected_engine or pdef.get("engine", "Unknown")
        result["error_match"] = detected_engine is not None
        if output_found or detected_engine:
            result["confidence"] = compute_confidence(detected_engine is not None, output_found, pdef["name"])
            print(f"[ssti] {url} param={param} engine={result['detected_engine']} conf={result['confidence']}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.RequestException:
        pass
    return result


def test_ssti_polyglot(url, param, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload": SSTI_POLYGLOT,
        "payload_name": "ssti_polyglot",
        "expected_engine": "Unknown",
        "technique": "ssti_polyglot",
        "detected_engine": None,
        "output_match": False,
        "error_match": False,
        "polyglot_reflected": False,
        "status_code": 0,
        "response_length": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        test_url = inject_payload(url, param, SSTI_POLYGLOT)
        print(f"[dry-run] SSTI Polyglot: {test_url}", file=sys.stderr)
        return result
    try:
        test_url = inject_payload(url, param, SSTI_POLYGLOT)
        resp = session.get(test_url, timeout=timeout, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)
        if SSTI_POLYGLOT in resp.text:
            result["polyglot_reflected"] = True
            result["confidence"] = 0.3
        detected_engine = detect_ssti_error(resp.text, None)
        if detected_engine:
            result["detected_engine"] = detected_engine
            result["error_match"] = True
            result["confidence"] = 0.7
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.RequestException:
        pass
    return result


def main():
    parser = argparse.ArgumentParser(
        description="SSTI Detector — detect Server-Side Template Injection across multiple template engines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Engine detection by output fingerprint:
  49      = Jinja2, Twig, FreeMarker, Velocity, ERB, Tornado (7*7)
  7777777 = FreeMarker ('7'*7 string repeat)
  Yes     = Jinja2 if-tag

Examples:
  %(prog)s --urls live_urls.txt --context .bb/context.json
  %(prog)s --urls single_url.txt --context .bb/context.json --dry-run
  %(prog)s --urls urls.txt --rate-limit 5 --timeout 10 --no-polyglot
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--concurrency", type=int, default=3, help="Thread pool concurrency (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--no-polyglot", action="store_true", help="Skip SSTI polyglot injection")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP proxy")
    parser.add_argument("--retries", type=int, default=2, help="Retries (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "ssti_findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        print("[error] No URLs loaded from --urls file.", file=sys.stderr)
        sys.exit(1)

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session_base = requests.Session()
    session_base.headers.update({"User-Agent": args.user_agent})
    if proxy_dict:
        session_base.proxies.update(proxy_dict)
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session_base.mount("https://", adapter)
    session_base.mount("http://", adapter)

    tasks = []
    for url in urls:
        params = extract_params_from_url(url)
        if not params:
            params = ["q", "search", "id", "name", "email", "message", "text", "template", "view", "page", "content", "title", "description", "body", "payload", "input", "data", "value", "preview", "render"]
        for param in params:
            for pdef in SSTI_PAYLOADS:
                tasks.append((url, param, pdef))
            if not args.no_polyglot:
                tasks.append((url, param, {"payload": SSTI_POLYGLOT, "name": "ssti_polyglot", "engine": "Unknown", "detect_output": None, "polyglot": True}))

    print(f"[info] Prepared {len(tasks)} SSTI probe tasks across {len(urls)} URLs", file=sys.stderr)

    if args.dry_run:
        for url, param, pdef in tasks:
            if pdef.get("polyglot"):
                test_ssti_polyglot(url, param, session_base, args.timeout, args.rate_limit, dry_run=True)
            else:
                test_ssti_payload(url, param, pdef, session_base, args.timeout, args.rate_limit, dry_run=True)
        print(f"[dry-run] Dry run complete — {len(tasks)} tasks.", file=sys.stderr)
        return

    all_findings = []
    completed = 0
    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url, param, pdef in tasks:
                if pdef.get("polyglot"):
                    future = executor.submit(test_ssti_polyglot, url, param, requests.Session(), args.timeout, args.rate_limit, dry_run=False)
                else:
                    future = executor.submit(test_ssti_payload, url, param, pdef, requests.Session(), args.timeout, args.rate_limit, dry_run=False)
                futures[future] = (url, param, pdef)
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    continue
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("confidence", 0) >= 0.3:
                    all_findings.append(result)
                if completed % 100 == 0:
                    print(f"[progress] {completed}/{len(tasks)} probes", file=sys.stderr)

    summary = {
        "total_probes": len(tasks),
        "total_findings": len(all_findings),
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()