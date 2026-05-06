#!/usr/bin/env python3
"""BOLA/IDOR Fuzzer -- test for broken object-level authorization."""
import argparse, json, os, sys, time, urllib.parse, urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def make_request(url, cookies=None, headers=None, proxy=None, timeout=15):
    ssl_ctx = build_ctx()
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req.add_header("Cookie", cookie_str)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    opener = urllib.request.build_opener(*handlers)
    resp = opener.open(req, timeout=timeout)
    body = resp.read().decode(errors="replace")[:4096]
    return resp.getcode(), resp.headers, body

def parse_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

def fuzz_resource(api_base, resource_path, id_start, id_end, id_step, cookies, headers, proxy, timeout, dry_run):
    findings = []
    template_url = urllib.parse.urljoin(api_base, resource_path)

    if "{id}" in template_url or "{ID}" in template_url or "%7Bid%7D" in template_url.lower():
        pass
    else:
        parsed = urllib.parse.urlparse(template_url)
        path_parts = parsed.path.rstrip("/").split("/")
        candidate = None
        for part in path_parts:
            if part.isdigit():
                candidate = part
                break
        if not candidate:
            findings.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_fuzz",
                "url": template_url,
                "status": "skip",
                "evidence": "No {id} placeholder or numeric segment found in URL; use path like /api/users/{id}",
                "vulnerable": False,
            })
            return findings

    def fuzz_one(rid):
        url = template_url.replace("{id}", str(rid)).replace("{ID}", str(rid))
        if dry_run:
            return {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_fuzz",
                "url": url,
                "resource_id": rid,
                "status": "dry_run",
                "vulnerable": False,
                "evidence": "dry-run: no request sent",
            }
        try:
            code, resp_headers, body = make_request(url, cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
            body_len = len(body)
            return {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_fuzz",
                "url": url,
                "resource_id": rid,
                "response_status": code,
                "response_length": body_len,
                "response_preview": body[:500],
                "status": "completed",
                "vulnerable": code in (200, 201, 202) and body_len > 0,
                "evidence": f"HTTP {code}, {body_len} bytes returned",
            }
        except urllib.error.HTTPError as e:
            return {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_fuzz",
                "url": url,
                "resource_id": rid,
                "response_status": e.code,
                "status": "http_error",
                "vulnerable": False,
                "evidence": f"HTTP {e.code} {e.reason}",
            }
        except Exception as e:
            return {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_fuzz",
                "url": url,
                "resource_id": rid,
                "status": "error",
                "vulnerable": False,
                "evidence": f"Error: {e}",
            }

    ids = list(range(id_start, id_end + 1, id_step))
    print(f"[*] Fuzzing {len(ids)} IDs ({id_start}..{id_end}, step={id_step})", file=sys.stderr)

    if dry_run:
        results = [fuzz_one(rid) for rid in ids[:min(len(ids), 50)]]
        findings.extend(results)
        for r in results:
            print(f"    [DRY-RUN] {r['url']}", file=sys.stderr)
        return findings

    results = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(fuzz_one, rid): rid for rid in ids}
        done = 0
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            done += 1
            if done % 50 == 0 or done == len(ids):
                print(f"    [{done}/{len(ids)}] complete", file=sys.stderr)

    findings.extend(results)
    return findings

def cross_account_test(api_base, resource_path, id_range, auth_cookies, auth_headers,
                        unauth_cookies, unauth_headers, proxy, timeout, dry_run):
    findings = []
    template_url = urllib.parse.urljoin(api_base, resource_path)

    for rid in id_range:
        url = template_url.replace("{id}", str(rid))
        if dry_run:
            findings.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_cross_account",
                "url": url,
                "resource_id": rid,
                "status": "dry_run",
                "vulnerable": False,
                "evidence": "dry-run: cross-account test not sent",
            })
            continue
        try:
            code, _, body = make_request(url, cookies=unauth_cookies or {}, headers=unauth_headers or {}, proxy=proxy, timeout=timeout)
            vulnerable = code in (200, 201, 202) and len(body) > 0
            findings.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_cross_account",
                "url": url,
                "resource_id": rid,
                "response_status": code,
                "response_length": len(body),
                "status": "completed",
                "vulnerable": vulnerable,
                "evidence": f"Cross-account access: HTTP {code}, {len(body)} bytes",
            })
        except Exception as e:
            findings.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "test": "bola_cross_account",
                "url": url,
                "resource_id": rid,
                "status": "error",
                "vulnerable": False,
                "evidence": str(e),
            })

    return findings

def main():
    parser = argparse.ArgumentParser(description="BOLA/IDOR Fuzzer")
    parser.add_argument("--api-base", required=True, help="API base URL (e.g. https://api.example.com)")
    parser.add_argument("--resource-path", required=True, help="Resource path with {id} placeholder (e.g. /api/users/{id}/profile)")
    parser.add_argument("--id-start", type=int, default=1, help="Start of ID range")
    parser.add_argument("--id-end", type=int, default=1000, help="End of ID range")
    parser.add_argument("--id-step", type=int, default=1, help="Step between IDs")
    parser.add_argument("--cookie", default="", help="Authenticated session cookies")
    parser.add_argument("--header", action="append", default=[], help="Auth headers (Name:Value), repeatable")
    parser.add_argument("--unauth-cookie", default="", help="Unauthenticated / different-user cookies for cross-account test")
    parser.add_argument("--unauth-header", action="append", default=[], help="Unauthenticated headers, repeatable")
    parser.add_argument("--cross-account", action="store_true", help="Also test with different user credentials")
    parser.add_argument("--proxy", default="", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without sending")
    parser.add_argument("--output", default="bola_findings.jsonl", help="JSONL output file")
    args = parser.parse_args()

    cookies = parse_cookies(args.cookie)
    headers = parse_headers(args.header)
    unauth_cookies = parse_cookies(args.unauth_cookie)
    unauth_headers = parse_headers(args.unauth_header)

    full_url = urllib.parse.urljoin(args.api_base.rstrip("/") + "/", args.resource_path.lstrip("/"))

    print(f"[*] BOLA/IDOR Fuzzer", file=sys.stderr)
    print(f"[*] API Base: {args.api_base}", file=sys.stderr)
    print(f"[*] Resource: {full_url}", file=sys.stderr)
    print(f"[*] ID Range: {args.id_start}..{args.id_end} (step {args.id_step})", file=sys.stderr)
    print(f"[*] Auth: {'Yes' if cookies or headers else 'None'}", file=sys.stderr)
    print(f"[*] Cross-account: {'Yes' if args.cross_account else 'No'}", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- no requests will be sent", file=sys.stderr)
    print(f"[*] Output: {args.output}", file=sys.stderr)

    all_findings = []

    print(f"\n[*] [1/2] Fuzzing with authenticated session...", file=sys.stderr)
    findings = fuzz_resource(args.api_base, args.resource_path, args.id_start, args.id_end, args.id_step,
                              cookies, headers, args.proxy, args.timeout, args.dry_run)
    all_findings.extend(findings)

    if args.cross_account and (args.unauth_cookie or args.unauth_header):
        print(f"\n[*] [2/2] Cross-account testing...", file=sys.stderr)
        sample_ids = list(range(args.id_start, min(args.id_end + 1, args.id_start + 50)))
        findings = cross_account_test(args.api_base, args.resource_path, sample_ids,
                                       cookies, headers, unauth_cookies, unauth_headers,
                                       args.proxy, args.timeout, args.dry_run)
        all_findings.extend(findings)

    with open(args.output, "w") as outfile:
        for e in all_findings:
            outfile.write(json.dumps(e) + "\n")

    vulnerable = sum(1 for f in all_findings if f.get("vulnerable"))
    total = len(all_findings)
    print(f"\n[*] {vulnerable}/{total} resources accessible (potential BOLA/IDOR)", file=sys.stderr)
    print(f"[*] Findings written to {args.output}", file=sys.stderr)

    sys.exit(1 if vulnerable > 0 else 0)

if __name__ == "__main__":
    main()