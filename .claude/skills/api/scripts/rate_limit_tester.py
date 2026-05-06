#!/usr/bin/env python3
"""API Rate Limit Tester -- burst requests and detect rate limit thresholds."""
import argparse, asyncio, json, os, sys, time
import urllib.parse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

def parse_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

def main():
    parser = argparse.ArgumentParser(description="API Rate Limit Tester")
    parser.add_argument("--url", required=True, help="API endpoint to test")
    parser.add_argument("--method", default="GET", help="HTTP method (GET, POST, PUT, DELETE)")
    parser.add_argument("--data", default="", help="POST/PUT body (JSON string or key=value&key2=value2)")
    parser.add_argument("--burst", type=int, default=100, help="Number of concurrent requests")
    parser.add_argument("--cookie", default="", help="Session cookies (key=value; key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Extra headers (Name:Value), repeatable")
    parser.add_argument("--proxy", default="", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without sending requests")
    parser.add_argument("--output", default="rate_limit_findings.jsonl", help="JSONL output file")
    args = parser.parse_args()

    cookies = parse_cookies(args.cookie)
    headers = parse_headers(args.header)

    print(f"[*] API Rate Limit Tester", file=sys.stderr)
    print(f"[*] URL: {args.url}", file=sys.stderr)
    print(f"[*] Method: {args.method}", file=sys.stderr)
    print(f"[*] Burst size: {args.burst}", file=sys.stderr)
    if args.data:
        print(f"[*] Data: {args.data[:100]}", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- no requests will be sent", file=sys.stderr)
    print(f"[*] Output: {args.output}", file=sys.stderr)

    if args.dry_run:
        dry_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "test": "rate_limit_burst",
            "url": args.url,
            "burst_size": args.burst,
            "total_sent": 0,
            "success_count": 0,
            "rate_limited_count": 0,
            "error_count": 0,
            "elapsed_seconds": 0,
            "rate_limit_detected": False,
            "rate_limit_threshold": None,
            "rate_limit_window": None,
            "status": "dry_run",
            "evidence": "dry-run: no requests sent",
        }
        with open(args.output, "w") as outfile:
            outfile.write(json.dumps(dry_entry) + "\n")
        print(f"[*] Dry run complete", file=sys.stderr)
        return

    start_time = time.monotonic()
    results = []

    if HAS_AIOHTTP:
        results = asyncio.run(_async_burst(args.url, args.method, args.data, args.burst,
                                            cookies, headers, args.proxy, args.timeout))
    else:
        results = _sync_burst(args.url, args.method, args.data, args.burst,
                              cookies, headers, args.proxy, args.timeout)

    elapsed = time.monotonic() - start_time

    status_counts = {}
    rate_limited_count = 0
    success_count = 0
    error_count = 0
    rate_limit_values = []
    retry_after_values = []

    for r in results:
        code = r.get("status_code", 0)
        status_counts[code] = status_counts.get(code, 0) + 1
        if code == 429:
            rate_limited_count += 1
            retry = r.get("retry_after")
            if retry:
                retry_after_values.append(int(retry))
        elif code and 200 <= code < 300:
            success_count += 1
        elif code and 400 <= code:
            rate_limited_count += 1 if code in (429, 403, 503) else 0
            error_count += 1 if code not in (429, 403, 503) else 0
        else:
            error_count += 1

    rate_limit_detected = rate_limited_count > 0
    threshold = None
    if rate_limit_detected:
        first_429_idx = None
        for i, r in enumerate(results):
            if r.get("status_code") == 429:
                first_429_idx = i
                break
        threshold = first_429_idx + 1 if first_429_idx is not None else None

    rl_window = None
    if retry_after_values:
        rl_window = max(retry_after_values)

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "rate_limit_burst",
        "url": args.url,
        "method": args.method,
        "burst_size": args.burst,
        "total_sent": len(results),
        "success_count": success_count,
        "rate_limited_count": rate_limited_count,
        "error_count": error_count,
        "status_code_distribution": status_counts,
        "elapsed_seconds": round(elapsed, 2),
        "requests_per_second": round(args.burst / elapsed, 2) if elapsed > 0 else 0,
        "rate_limit_detected": rate_limit_detected,
        "rate_limit_threshold": threshold,
        "rate_limit_window_seconds": rl_window,
        "first_429_index": next((i for i, r in enumerate(results) if r.get("status_code") == 429), None),
    }

    if rate_limit_detected:
        entry["evidence"] = f"Rate limiting DETECTED at ~{threshold} requests"
        if rl_window:
            entry["evidence"] += f", Retry-After: {rl_window}s window"
    else:
        entry["evidence"] = f"No rate limiting detected -- all {args.burst} requests completed without 429 response"

    with open(args.output, "w") as outfile:
        outfile.write(json.dumps(entry) + "\n")

    print(f"\n[*] === RESULTS ===", file=sys.stderr)
    print(f"    Total sent: {len(results)}", file=sys.stderr)
    print(f"    Success (2xx): {success_count}", file=sys.stderr)
    print(f"    Rate limited (429): {rate_limited_count}", file=sys.stderr)
    print(f"    Errors: {error_count}", file=sys.stderr)
    print(f"    Elapsed: {elapsed:.2f}s", file=sys.stderr)
    print(f"    Throughput: {entry['requests_per_second']} req/s", file=sys.stderr)
    print(f"    Status codes: {status_counts}", file=sys.stderr)
    if rate_limit_detected:
        print(f"    Rate limiting: DETECTED at ~{threshold} requests (Retry-After: {rl_window}s)", file=sys.stderr)
        print(f"    [FINDING] Rate limit threshold: ~{threshold} requests per {rl_window}s window", file=sys.stderr)
    else:
        print(f"    Rate limiting: NOT DETECTED", file=sys.stderr)
        print(f"    [FINDING] No rate limiting -- potential DoS/brute-force vector", file=sys.stderr)

    print(f"\n[*] Findings written to {args.output}", file=sys.stderr)
    sys.exit(0)

async def _async_burst(url, method, data, burst, cookies, headers, proxy, timeout):
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=100)

    async def send_one(session, idx):
        try:
            kwargs = {"headers": headers, "cookies": cookies, "timeout": aiohttp.ClientTimeout(total=timeout)}
            if proxy:
                kwargs["proxy"] = proxy

            if method == "GET":
                async with session.get(url, **kwargs) as resp:
                    return {"index": idx, "status_code": resp.status, "retry_after": resp.headers.get("Retry-After")}
            elif method == "POST":
                body = data if isinstance(data, str) else json.dumps(data)
                if not kwargs.get("headers"):
                    kwargs["headers"] = {}
                kwargs["headers"].setdefault("Content-Type", "application/json" if data.startswith("{") else "application/x-www-form-urlencoded")
                async with session.post(url, data=body, **kwargs) as resp:
                    return {"index": idx, "status_code": resp.status, "retry_after": resp.headers.get("Retry-After")}
            elif method == "PUT":
                body = data if isinstance(data, str) else json.dumps(data)
                async with session.put(url, data=body, **kwargs) as resp:
                    return {"index": idx, "status_code": resp.status, "retry_after": resp.headers.get("Retry-After")}
            elif method == "DELETE":
                async with session.delete(url, **kwargs) as resp:
                    return {"index": idx, "status_code": resp.status, "retry_after": resp.headers.get("Retry-After")}
            else:
                async with session.get(url, **kwargs) as resp:
                    return {"index": idx, "status_code": resp.status, "retry_after": resp.headers.get("Retry-After")}
        except aiohttp.ClientError as e:
            return {"index": idx, "status_code": 0, "error": str(e)}
        except asyncio.TimeoutError:
            return {"index": idx, "status_code": 0, "error": "timeout"}
        except Exception as e:
            return {"index": idx, "status_code": 0, "error": str(e)}

    print(f"[*] Sending {burst} concurrent requests...", file=sys.stderr)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [send_one(session, i) for i in range(burst)]
        results = await asyncio.gather(*tasks)
        results = sorted(results, key=lambda x: x["index"])
    return results

def _sync_burst(url, method, data, burst, cookies, headers, proxy, timeout):
    import urllib.request
    import ssl
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    def send_one(idx):
        try:
            req = urllib.request.Request(url, method=method)
            if data and method in ("POST", "PUT"):
                req.data = data.encode() if isinstance(data, str) else data
                if not req.get_header("Content-Type"):
                    req.add_header("Content-Type", "application/x-www-form-urlencoded")
            for k, v in headers.items():
                req.add_header(k, v)
            if cookies:
                req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
            handlers = []
            if proxy:
                handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
            opener = urllib.request.build_opener(*handlers)
            resp = opener.open(req, timeout=timeout)
            return {"index": idx, "status_code": resp.getcode(), "retry_after": resp.headers.get("Retry-After")}
        except urllib.error.HTTPError as e:
            return {"index": idx, "status_code": e.code, "retry_after": e.headers.get("Retry-After")}
        except Exception as e:
            return {"index": idx, "status_code": 0, "error": str(e)}

    print(f"[*] Sending {burst} concurrent requests (threaded)...", file=sys.stderr)
    results = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(send_one, i): i for i in range(burst)}
        done = 0
        for future in as_completed(futures):
            results.append(future.result())
            done += 1
            if done % 20 == 0 or done == burst:
                print(f"    [{done}/{burst}] complete", file=sys.stderr)
    results.sort(key=lambda x: x["index"])
    return results

if __name__ == "__main__":
    main()