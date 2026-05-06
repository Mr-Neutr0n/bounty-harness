#!/usr/bin/env python3
"""
Race Engine — sends concurrent HTTP requests to detect race condition windows.

Uses asyncio + aiohttp for truly parallel requests.
Times each request start/end precisely.
Detects race windows by comparing response differences.

Outputs: race_results.json with timing data, response variance, and race window analysis.
"""

import argparse
import json
import sys
import os
import time
import asyncio
import urllib.parse
from typing import Optional

try:
    import aiohttp
except ImportError:
    sys.stderr.write("[!] aiohttp not installed. Run: pip install aiohttp\n")
    aiohttp = None  # type: ignore


async def _send_single(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    headers: dict,
    body: Optional[bytes],
    timeout_sec: int,
    index: int,
    conn: aiohttp.TCPConnector,
) -> dict:
    start = time.time()
    send_ts = time.time_ns() // 1000
    try:
        async with session.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=aiohttp.ClientTimeout(total=timeout_sec),
            ssl=False,
        ) as resp:
            text = await resp.text()
            end = time.time()
            recv_ts = time.time_ns() // 1000
            return {
                "index": index,
                "status": resp.status,
                "headers": dict(resp.headers),
                "body_preview": text[:4096],
                "body_length": len(text),
                "start_time": start,
                "end_time": end,
                "duration_ms": round((end - start) * 1000, 2),
                "send_timestamp_us": send_ts,
                "recv_timestamp_us": recv_ts,
                "error": None,
            }
    except asyncio.TimeoutError:
        end = time.time()
        return {
            "index": index,
            "status": 0,
            "headers": {},
            "body_preview": "",
            "body_length": 0,
            "start_time": start,
            "end_time": end,
            "duration_ms": round((end - start) * 1000, 2),
            "send_timestamp_us": send_ts,
            "recv_timestamp_us": time.time_ns() // 1000,
            "error": "timeout",
        }
    except Exception as e:
        end = time.time()
        return {
            "index": index,
            "status": 0,
            "headers": {},
            "body_preview": "",
            "body_length": 0,
            "start_time": start,
            "end_time": end,
            "duration_ms": round((end - start) * 1000, 2),
            "send_timestamp_us": send_ts,
            "recv_timestamp_us": time.time_ns() // 1000,
            "error": str(e),
        }


async def _fire_concurrently(
    url: str,
    method: str,
    headers: dict,
    body: Optional[bytes],
    concurrent_count: int,
    timeout_sec: int,
    delay_us: int,
) -> list:
    connector = aiohttp.TCPConnector(force_close=True, limit=0)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for i in range(concurrent_count):
            tasks.append(
                _send_single(session, url, method, headers, body, timeout_sec, i, connector)
            )
            if delay_us > 0 and i < concurrent_count - 1:
                await asyncio.sleep(delay_us / 1_000_000)

        results = await asyncio.gather(*tasks)
        return results


def _analyze_race_window(responses: list) -> dict:
    analysis = {
        "total_requests": len(responses),
        "success_count": 0,
        "failure_count": 0,
        "error_count": 0,
        "timing": {},
        "response_variations": [],
        "race_window_detected": False,
        "race_window_details": "",
    }

    durations = []
    statuses = []

    for r in responses:
        if r.get("error"):
            analysis["error_count"] += 1
            continue
        if r["status"] >= 200 and r["status"] < 300:
            analysis["success_count"] += 1
        elif r["status"] >= 400:
            analysis["failure_count"] += 1
        durations.append(r["duration_ms"])
        statuses.append(r["status"])

    if durations:
        analysis["timing"] = {
            "min_ms": round(min(durations), 2),
            "max_ms": round(max(durations), 2),
            "avg_ms": round(sum(durations) / len(durations), 2),
            "spread_ms": round(max(durations) - min(durations) if len(durations) > 1 else 0, 2),
            "median_ms": round(sorted(durations)[len(durations) // 2], 2),
        }

    send_times = [r["send_timestamp_us"] for r in responses if not r.get("error")]
    if send_times:
        analysis["send_sync"] = {
            "earliest_us": min(send_times),
            "latest_us": max(send_times),
            "spread_us": max(send_times) - min(send_times),
        }

    body_map = {}
    for r in responses:
        key = f"{r['status']}_{r.get('body_length', 0)}"
        body_map[key] = body_map.get(key, 0) + 1

    unique_statuses = set(statuses)
    if len(unique_statuses) > 1:
        analysis["race_window_detected"] = True
        analysis["race_window_details"] = (
            f"Multiple status codes returned: {sorted(unique_statuses)} — "
            f"indicates state changed between concurrent requests"
        )

    if len(body_map) > 1 and not analysis["race_window_detected"]:
        analysis["response_variations"] = [
            {"key": k, "count": v} for k, v in sorted(body_map.items(), key=lambda x: -x[1])
        ]
        if len(body_map) >= 2:
            analysis["race_window_detected"] = True
            analysis["race_window_details"] = (
                f"Response body differed across {len(body_map)} variant(s) "
                f"(by status+length) — possible race behavior"
            )

    return analysis


def parse_headers(header_list: list) -> dict:
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            sys.stderr.write(f"[!] Skipping malformed header: {h}\n")
    return headers


def run_engine(
    url: str,
    method: str,
    headers: dict,
    body: Optional[str],
    concurrent_count: int,
    timeout_sec: int,
    delay_us: int,
    context: Optional[str],
    dry_run: bool,
) -> dict:
    start_time = time.time()

    if dry_run:
        return {
            "dry_run": True,
            "url": url,
            "method": method,
            "concurrent_count": concurrent_count,
            "delay_us": delay_us,
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    if aiohttp is None:
        return {
            "error": "aiohttp not installed. Run: pip install aiohttp",
            "url": url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    body_bytes = body.encode("utf-8") if body else None

    sys.stderr.write(f"[*] Firing {concurrent_count} concurrent {method} requests...\n")
    sys.stderr.write(f"    delay={delay_us}us, timeout={timeout_sec}s\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        responses = loop.run_until_complete(
            _fire_concurrently(url, method, headers, body_bytes, concurrent_count, timeout_sec, delay_us)
        )
    finally:
        loop.close()

    analysis = _analyze_race_window(responses)
    elapsed = round(time.time() - start_time, 2)

    result = {
        "url": url,
        "method": method,
        "concurrent_count": concurrent_count,
        "delay_us": delay_us,
        "total_elapsed_s": elapsed,
        "requests": responses,
        "analysis": analysis,
        "context": context,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    sys.stderr.write(f"\n[*] Race engine completed in {elapsed}s\n")
    sys.stderr.write(f"[*] Success: {analysis['success_count']}, "
                     f"Failures: {analysis['failure_count']}, "
                     f"Errors: {analysis['error_count']}\n")
    if analysis.get("timing"):
        t = analysis["timing"]
        sys.stderr.write(f"[*] Timing: min={t['min_ms']}ms, max={t['max_ms']}ms, "
                         f"avg={t['avg_ms']}ms, spread={t['spread_ms']}ms\n")

    if analysis.get("race_window_detected"):
        sys.stderr.write(f"[!] RACE WINDOW DETECTED: {analysis['race_window_details']}\n")
    else:
        sys.stderr.write("[*] No race window detected\n")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Race Engine — detect race condition windows with concurrent HTTP requests",
        epilog="Example: python3 race_engine.py --url https://example.com/api/coupon --method POST --headers 'Content-Type: application/json' --body '{\"code\":\"TEST\"}' --concurrent-count 20",
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--headers", nargs="*", default=[], help="Headers as 'Key: Value' pairs")
    parser.add_argument("--body", default=None, help="Request body (for POST/PUT)")
    parser.add_argument("--concurrent-count", type=int, default=20, help="Number of concurrent requests (default: 20)")
    parser.add_argument("--timeout", type=int, default=30, help="Per-request timeout in seconds (default: 30)")
    parser.add_argument("--delay-us", type=int, default=0, help="Microsecond delay between dispatches (default: 0)")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--dry-run", action="store_true", help="Show configuration without executing")
    parser.add_argument("--output", default=None, help="Output JSON file path (default: race_results.json)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    headers = parse_headers(args.headers)

    sys.stderr.write(f"[*] Race Engine\n")
    sys.stderr.write(f"[*] URL: {args.url}\n")
    sys.stderr.write(f"[*] Method: {args.method}\n")
    sys.stderr.write(f"[*] Headers: {headers}\n")
    sys.stderr.write(f"[*] Concurrent requests: {args.concurrent_count}\n")
    sys.stderr.write(f"[*] Delay: {args.delay_us}us\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")

    result = run_engine(args.url, args.method, headers, args.body, args.concurrent_count,
                        args.timeout, args.delay_us, args.context, args.dry_run)

    outfile = args.output or "race_results.json"
    serializable_result = result.copy()
    if "requests" in serializable_result:
        for r in serializable_result["requests"]:
            r.pop("start_time", None)
            r.pop("end_time", None)

    with open(outfile, "w") as f:
        json.dump(serializable_result, f, indent=2)

    sys.stderr.write(f"[*] Results written to {outfile}\n")
    print(json.dumps(serializable_result, indent=2))


if __name__ == "__main__":
    main()