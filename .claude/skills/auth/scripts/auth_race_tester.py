#!/usr/bin/env python3
"""Auth Race Condition Tester -- sends concurrent requests to auth endpoints."""
import argparse
import concurrent.futures
import json
import time
import urllib.error
import urllib.request


def parse_headers(header_values):
    headers = {}
    for header in header_values or []:
        if ":" not in header:
            continue
        name, value = header.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def send_request(url, method, body, headers, timeout):
    data = body.encode() if body and method not in {"GET", "HEAD"} else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(1024)
            return {
                "status": resp.status,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": None,
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(e),
        }


def main():
    parser = argparse.ArgumentParser(description="Auth race-condition tester")
    parser.add_argument("--url", required=True, help="Endpoint to race")
    parser.add_argument("--method", default="POST", help="HTTP method")
    parser.add_argument("--data", default="{}", help="Request body")
    parser.add_argument("--n", type=int, default=10, help="Concurrent request count")
    parser.add_argument("--cookie", default="", help="Cookie header value")
    parser.add_argument("--header", action="append", default=[], help="Extra header as Name: Value")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned requests without sending")
    parser.add_argument("-o", "--output", default="race_results.json", help="JSON output file")
    args = parser.parse_args()

    method = args.method.upper()
    headers = parse_headers(args.header)
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.data and method not in {"GET", "HEAD"} and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    plan = {
        "url": args.url,
        "method": method,
        "concurrency": args.n,
        "context": args.context,
        "dry_run": args.dry_run,
    }

    if args.dry_run:
        print(json.dumps({"planned": plan}, indent=2))
        return 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.n) as pool:
        futures = [pool.submit(send_request, args.url, method, args.data, headers, args.timeout) for _ in range(args.n)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    status_counts = {}
    for result in results:
        status_counts[str(result["status"])] = status_counts.get(str(result["status"]), 0) + 1

    report = {
        **plan,
        "status_counts": status_counts,
        "results": results,
        "signals": [
            "multiple successful state-changing responses" if len([r for r in results if str(r["status"]).startswith("2")]) > 1 else "no obvious duplicate success",
        ],
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({"output": args.output, "status_counts": status_counts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
