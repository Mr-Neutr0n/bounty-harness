#!/usr/bin/env python3
"""LLM Surface Mapper — discover LLM endpoints, chatbots, MCP servers, and AI integrations."""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

LLM_BODY_INDICATORS = [
    re.compile(r"as an AI", re.IGNORECASE),
    re.compile(r"as a language model", re.IGNORECASE),
    re.compile(r"I'm an AI", re.IGNORECASE),
    re.compile(r"I am an AI", re.IGNORECASE),
    re.compile(r"chatbot", re.IGNORECASE),
    re.compile(r"AI assistant", re.IGNORECASE),
]

LLM_PATH_PATTERNS = [
    "/v1/chat/completions",
    "/api/generate",
    "/chat",
    "/completions",
    "/api/ask",
    "/api/llm",
    "/ai",
    "/copilot",
    "/api/v1/chat",
    "/v1/completions",
    "/api/v1/llm",
    "/query",
    "/ask",
    "/api/chat",
    "/api/generate",
]

LLM_HEADER_INDICATORS = [
    "x-llm",
    "x-model",
    "x-model-id",
    "openai-",
    "x-ai-provider",
    "x-request-id",
    "x-anthropic",
]

MCP_PATHS = [
    "/.well-known/mcp",
    "/mcp",
    "/api/mcp",
    "/v1/mcp",
]

BENIGN_PROBE = "Hello, what is 2+2?"


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
                if not line.startswith("http"):
                    line = "https://" + line
                urls.append(line.rstrip("/"))
    return set(urls)


def check_body_indicators(text):
    found = []
    for pattern in LLM_BODY_INDICATORS:
        if pattern.search(text):
            found.append(pattern.pattern)
    return found


def check_llm_headers(headers):
    found = []
    for key in headers:
        key_lower = key.lower()
        for indicator in LLM_HEADER_INDICATORS:
            if indicator in key_lower:
                found.append(f"{key}: {headers[key]}")
                break
    return found


def check_sse(text, content_type):
    signals = []
    if "text/event-stream" in content_type.lower():
        signals.append("sse_content_type")
    if re.search(r"data:\s*\[DONE\]", text, re.IGNORECASE):
        signals.append("sse_done_marker")
    if re.search(r"data:\s*\{.*\"content\"", text, re.IGNORECASE):
        signals.append("sse_json_content")
    if re.search(r"event:\s*(message|completion|delta)", text, re.IGNORECASE):
        signals.append("sse_event_stream")
    return signals


def check_llm_like_response(text):
    score = 0
    if re.search(r"\b4\b.*", text) and ("2+2" in text.lower() or "two plus two" in text.lower()):
        score += 1
    if re.search(r"(the answer|the result|equals|is .*4)", text, re.IGNORECASE):
        score += 1
    if re.search(r"(hello|hi there|greetings|how can I help)", text, re.IGNORECASE) and len(text) > 20:
        score += 1
    if re.search(r"(I('| a)m|I can|I will|I don't|I cannot|I am unable)", text, re.IGNORECASE):
        score += 1
    return score >= 2


def probe_single(url_str, session, timeout, rate_limit, dry_run, outdir):
    result = {
        "url": url_str,
        "llm_indicator": False,
        "detection_type": [],
        "endpoint_type": "unknown",
        "response_indicators": [],
        "mcp_detected": False,
        "suggested_workflow": None,
        "status_code": 0,
        "response_length": 0,
        "error": None,
        "dry_run": dry_run,
    }
    if dry_run:
        print(f"[dry-run] Would probe {url_str}", file=sys.stderr)
        return result

    try:
        start = time.time()
        resp = session.get(url_str, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)

        if resp.status_code == 404 or resp.status_code == 000:
            return result

        body_indicators = check_body_indicators(resp.text.lower())
        header_indicators = check_llm_headers(dict(resp.headers))
        content_type = resp.headers.get("Content-Type", "")
        sse_signals = check_sse(resp.text, content_type)

        if body_indicators:
            result["llm_indicator"] = True
            result["detection_type"].append("body_indicator")
            result["response_indicators"].extend(body_indicators)
            result["endpoint_type"] = "llm_response"

        if header_indicators:
            result["llm_indicator"] = True
            result["detection_type"].append("header_indicator")
            result["response_indicators"].extend(header_indicators)
            result["endpoint_type"] = "llm_api"

        if sse_signals:
            result["llm_indicator"] = True
            result["detection_type"].append("sse_streaming")
            result["response_indicators"].extend(sse_signals)
            result["endpoint_type"] = "llm_streaming"

        parsed = urllib.parse.urlparse(url_str)
        path = parsed.path.lower().rstrip("/")
        for llm_path in LLM_PATH_PATTERNS:
            if path.endswith(llm_path) or path == llm_path:
                result["llm_indicator"] = True
                result["detection_type"].append("path_match")
                result["endpoint_type"] = "llm_api"
                result["response_indicators"].append(f"path_matches_llm_pattern:{llm_path}")
                break

        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        print(f"[timeout] {url_str}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection_error: {e}"
        print(f"[conn_err] {url_str}: {e}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"[err] {url_str}: {e}", file=sys.stderr)

    return result


def probe_llm_response(url_str, session, timeout, rate_limit, dry_run):
    """Send a benign probe to check if the endpoint produces LLM-like responses."""
    result = {
        "url": url_str,
        "llm_response_detected": False,
        "probe_payload": BENIGN_PROBE,
        "response_snippet": None,
        "status_code": 0,
        "error": None,
    }
    if dry_run:
        print(f"[dry-run] Would probe LLM response for {url_str}", file=sys.stderr)
        return result

    openai_body = {
        "messages": [{"role": "user", "content": BENIGN_PROBE}],
        "max_tokens": 50,
    }
    anthropic_body = {
        "prompt": f"\n\nHuman: {BENIGN_PROBE}\n\nAssistant:",
        "max_tokens_to_sample": 50,
    }
    raw_body = {"message": BENIGN_PROBE, "prompt": BENIGN_PROBE, "query": BENIGN_PROBE}

    bodies_to_try = [openai_body, raw_body, anthropic_body]

    for body in bodies_to_try:
        try:
            resp = session.post(url_str, json=body, timeout=timeout, allow_redirects=True)
            result["status_code"] = resp.status_code
            if resp.status_code == 200 and len(resp.text) > 20:
                result["response_snippet"] = resp.text[:300]
                if check_llm_like_response(resp.text):
                    result["llm_response_detected"] = True
                if rate_limit > 0:
                    time.sleep(1.0 / rate_limit)
                return result
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            pass
        except requests.exceptions.RequestException:
            pass

    return result


def probe_mcp(url_str, session, timeout, dry_run):
    """Check for MCP server at the URL."""
    result = {
        "url": url_str,
        "mcp_detected": False,
        "mcp_tools": [],
        "error": None,
    }
    if dry_run:
        print(f"[dry-run] Would probe MCP at {url_str}", file=sys.stderr)
        return result

    try:
        resp = session.post(
            url_str,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            timeout=timeout,
        )
        if resp.status_code == 200 and "jsonrpc" in resp.text.lower():
            try:
                data = resp.json()
                if "result" in data and "tools" in data.get("result", {}):
                    tools = data["result"]["tools"]
                    result["mcp_detected"] = True
                    result["mcp_tools"] = [t.get("name", "unknown") for t in tools]
            except json.JSONDecodeError:
                pass
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        result["error"] = "timeout_or_connection"
    except requests.exceptions.RequestException:
        result["error"] = "request_error"

    return result


def main():
    parser = argparse.ArgumentParser(
        description="LLM Surface Mapper — discover LLM endpoints, MCP servers, and chatbot surfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --urls live_hosts.txt --context .bb/context.json
  %(prog)s --urls live_hosts.txt --context .bb/context.json --dry-run
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--urls", required=True, help="File with target URLs, one per line")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--rate-limit", type=int, default=10, help="Max requests per second (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--concurrency", type=int, default=5, help="Thread pool concurrency (default: 5)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without executing")
    parser.add_argument("--user-agent", default="BugBountyAgent/2.0 LLM Mapper (security research)", help="Custom User-Agent header")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "ai-llm", "surface_findings.jsonl")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    urls = list(load_urls(args.urls))
    if not urls:
        print("[error] No URLs loaded from --urls file.", file=sys.stderr)
        sys.exit(1)

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "application/json,text/html,text/plain,*/*",
        "Accept-Language": "en-US,en;q=0.5",
    })
    if proxy_dict:
        session.proxies.update(proxy_dict)
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    print(f"[info] Probing {len(urls)} URLs for LLM indicators", file=sys.stderr)

    if args.dry_run:
        for url in urls:
            probe_single(url, session, args.timeout, args.rate_limit, dry_run=True, outdir=outdir)
        print(f"[dry-run] Dry run complete — {len(urls)} URLs would be probed.", file=sys.stderr)
        return

    all_findings = []
    mcp_endpoints = []
    surface_map = {"llm_endpoints": [], "streaming_endpoints": [], "mcp_endpoints": [], "chatbot_widgets": []}
    completed = 0

    with open(output_path, "w") as outfile:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {}
            for url in urls:
                future = executor.submit(probe_single, url, session, args.timeout, args.rate_limit, dry_run=False, outdir=outdir)
                futures[future] = url
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"[fatal] Unexpected error in worker: {e}", file=sys.stderr)
                    continue
                result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                outfile.write(json.dumps(result) + "\n")
                completed += 1
                if result.get("llm_indicator"):
                    all_findings.append(result)
                    for dtype in result.get("detection_type", []):
                        if dtype == "sse_streaming":
                            surface_map["streaming_endpoints"].append(result["url"])
                        elif dtype in ("path_match", "header_indicator"):
                            surface_map["llm_endpoints"].append(result["url"])
                        elif dtype == "body_indicator":
                            surface_map["chatbot_widgets"].append(result["url"])
                if completed % 10 == 0:
                    print(f"[progress] {completed}/{len(urls)} URLs probed", file=sys.stderr)

    surface_map_path = os.path.join(os.path.dirname(output_path), "surface.json")
    with open(surface_map_path, "w") as sf:
        json.dump(surface_map, sf, indent=2)

    summary = {
        "total_urls": len(urls),
        "total_probed": completed,
        "llm_endpoints_found": len(all_findings),
        "surface_map_path": surface_map_path,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Surface findings written to {output_path}", file=sys.stderr)
    print(f"[done] Surface map written to {surface_map_path}", file=sys.stderr)


if __name__ == "__main__":
    main()