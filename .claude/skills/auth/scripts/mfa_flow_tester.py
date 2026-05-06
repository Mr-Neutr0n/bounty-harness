#!/usr/bin/env python3
"""MFA Flow Tester -- test MFA bypass techniques."""
import argparse, json, os, sys, time, urllib.parse, urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def make_request(url, method="GET", data=None, cookies=None, headers=None, proxy=None, timeout=15):
    ssl_ctx = build_ctx()
    req = urllib.request.Request(url, method=method)
    if data:
        req.data = data if isinstance(data, bytes) else urllib.parse.urlencode(data).encode()
        if not req.get_header("Content-Type"):
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

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
    body = resp.read().decode(errors="replace")[:8192]
    return resp.getcode(), resp.headers, body

def test_direct_access(protected_url, cookies, headers, proxy, timeout, dry_run):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "direct_access_no_mfa",
        "url": protected_url,
    }
    if dry_run:
        entry["status"] = "dry_run"
        entry["bypassed"] = False
        entry["evidence"] = "dry-run: no request sent"
        return entry

    try:
        code, resp_headers, body = make_request(protected_url, "GET", cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
        entry["response_status"] = code
        entry["response_length"] = len(body)
        entry["status"] = "completed"

        success_indicators = code == 200 and ("dashboard" in body.lower() or "profile" in body.lower() or "account" in body.lower())
        if success_indicators:
            entry["bypassed"] = True
            entry["evidence"] = f"HTTP {code} - accessed protected resource without MFA"
        else:
            entry["bypassed"] = False
            entry["evidence"] = f"HTTP {code} - MFA may be enforced (redirect/deny)"
            if code in (302, 303, 307, 308):
                entry["redirect"] = resp_headers.get("Location", "unknown")
    except urllib.error.HTTPError as e:
        entry["status"] = "http_error"
        entry["response_status"] = e.code
        entry["bypassed"] = False
        entry["evidence"] = f"HTTP {e.code} {e.reason}"
    except Exception as e:
        entry["status"] = "error"
        entry["bypassed"] = False
        entry["evidence"] = f"Error: {e}"

    return entry

def test_response_manipulation(protected_url, mfa_verify_url, cookies, headers, proxy, timeout, dry_run):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "response_manipulation",
        "url": protected_url,
    }
    if dry_run:
        entry["status"] = "dry_run"
        entry["bypassed"] = False
        entry["evidence"] = "dry-run: no request sent"
        return entry

    try:
        modified_headers = dict(headers or {})
        modified_headers["X-Original-Status"] = "200"
        modified_headers["X-Forwarded-For"] = "127.0.0.1"

        code, resp_headers, body = make_request(protected_url, "GET", cookies=cookies, headers=modified_headers, proxy=proxy, timeout=timeout)
        entry["response_status"] = code
        entry["status"] = "completed"
        entry["response_length"] = len(body)

        if code == 200:
            entry["bypassed"] = True
            entry["evidence"] = f"HTTP 200 with status spoofing headers"
        else:
            entry["bypassed"] = False
            entry["evidence"] = f"HTTP {code} - manipulation headers ignored"
    except Exception as e:
        entry["status"] = "error"
        entry["bypassed"] = False
        entry["evidence"] = str(e)

    return entry

def test_otp_reuse(otp_verify_url, otp_code, cookies, headers, proxy, timeout, reuse_count, dry_run):
    entries = []
    template_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "otp_reuse",
        "url": otp_verify_url,
    }

    if dry_run:
        e = dict(template_entry)
        e["status"] = "dry_run"
        e["attempt"] = "1..N"
        e["bypassed"] = False
        e["evidence"] = f"dry-run: would send {reuse_count} OTP reuse attempts"
        entries.append(e)
        return entries

    data = {"otp": otp_code, "submit": "verify"}
    success_count = 0
    for i in range(reuse_count):
        e = dict(template_entry)
        e["attempt"] = i + 1
        try:
            code, resp_headers, body = make_request(otp_verify_url, "POST", data=data, cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
            e["response_status"] = code
            e["status"] = "completed"
            if "success" in body.lower() or "verified" in body.lower() or code == 200:
                e["bypassed"] = True
                e["evidence"] = f"OTP reuse attempt {i+1} succeeded"
                success_count += 1
            else:
                e["bypassed"] = False
                e["evidence"] = f"OTP reuse attempt {i+1} rejected"
        except Exception as ex:
            e["status"] = "error"
            e["bypassed"] = False
            e["evidence"] = str(ex)
        entries.append(e)
        if not dry_run:
            time.sleep(0.1)

    return entries

def test_otp_rate_limit(otp_send_url, cookies, headers, proxy, timeout, burst_count, dry_run):
    entries = []
    template_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test": "otp_rate_limit",
        "url": otp_send_url,
    }

    if dry_run:
        e = dict(template_entry)
        e["status"] = "dry_run"
        e["bypassed"] = False
        e["evidence"] = f"dry-run: would send {burst_count} OTP send bursts"
        entries.append(e)
        return entries

    def send_otp(idx):
        try:
            code, _, body = make_request(otp_send_url, "POST", data={"action": "send_otp"}, cookies=cookies, headers=headers, proxy=proxy, timeout=timeout)
            return idx, code, body[:500]
        except Exception as e:
            return idx, None, str(e)

    results = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(send_otp, i): i for i in range(burst_count)}
        for future in as_completed(futures):
            results.append(future.result())

    status_codes = {}
    for idx, code, body in results:
        status_codes[code] = status_codes.get(code, 0) + 1

    entry = dict(template_entry)
    entry["burst_count"] = burst_count
    entry["status_codes"] = status_codes
    entry["status"] = "completed"
    rate_limited = status_codes.get(429, 0) > 0
    entry["bypassed"] = not rate_limited
    entry["evidence"] = f"Status codes: {status_codes} -- {'rate limited' if rate_limited else 'no rate limiting detected'}"
    entries.append(entry)
    return entries

def main():
    parser = argparse.ArgumentParser(description="MFA Flow Tester -- bypass detection")
    parser.add_argument("--protected-url", required=True, help="URL requiring MFA-protected access")
    parser.add_argument("--otp-verify-url", default="", help="OTP verification endpoint")
    parser.add_argument("--otp-send-url", default="", help="OTP send/resend endpoint for rate-limiting test")
    parser.add_argument("--otp-code", default="123456", help="OTP code to reuse (default: 123456)")
    parser.add_argument("--reuse-count", type=int, default=5, help="Number of OTP reuse attempts")
    parser.add_argument("--burst-count", type=int, default=20, help="Number of OTP send bursts for rate-limit test")
    parser.add_argument("--cookie", default="", help="Session cookies (key=value; key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Extra headers (Name:Value), repeatable")
    parser.add_argument("--proxy", default="", help="Proxy URL (http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned tests without sending requests")
    parser.add_argument("--output", default="mfa_findings.jsonl", help="JSONL output file")
    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    print(f"[*] MFA Flow Tester", file=sys.stderr)
    print(f"[*] Protected URL: {args.protected_url}", file=sys.stderr)
    if args.otp_verify_url:
        print(f"[*] OTP Verify URL: {args.otp_verify_url}", file=sys.stderr)
    if args.otp_send_url:
        print(f"[*] OTP Send URL: {args.otp_send_url}", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- no requests will be sent", file=sys.stderr)
    print(f"[*] Output: {args.output}", file=sys.stderr)

    all_findings = []

    print(f"\n[*] [1/4] Testing direct access without MFA...", file=sys.stderr)
    r = test_direct_access(args.protected_url, cookies, headers, args.proxy, args.timeout, args.dry_run)
    all_findings.append(r)
    status = "[BYPASSED]" if r.get("bypassed") else ""
    print(f"    Direct access: {status}", file=sys.stderr)

    print(f"[*] [2/4] Testing response manipulation...", file=sys.stderr)
    r = test_response_manipulation(args.protected_url, "", cookies, headers, args.proxy, args.timeout, args.dry_run)
    all_findings.append(r)
    status = "[BYPASSED]" if r.get("bypassed") else ""
    print(f"    Response manipulation: {status}", file=sys.stderr)

    if args.otp_verify_url:
        print(f"[*] [3/4] Testing OTP reuse ({args.reuse_count} attempts)...", file=sys.stderr)
        results = test_otp_reuse(args.otp_verify_url, args.otp_code, cookies, headers, args.proxy, args.timeout, args.reuse_count, args.dry_run)
        all_findings.extend(results)
        reused = sum(1 for r in results if r.get("bypassed"))
        print(f"    OTP reuse: {reused}/{len(results)} successes", file=sys.stderr)

    if args.otp_send_url:
        print(f"[*] [4/4] Testing OTP rate limit ({args.burst_count} bursts)...", file=sys.stderr)
        results = test_otp_rate_limit(args.otp_send_url, cookies, headers, args.proxy, args.timeout, args.burst_count, args.dry_run)
        all_findings.extend(results)
        not_limited = sum(1 for r in results if r.get("bypassed"))
        if not_limited > 0:
            print(f"    OTP rate limit: [BYPASSED] -- no rate limiting", file=sys.stderr)
        else:
            print(f"    OTP rate limit: rate limiting enforced", file=sys.stderr)

    with open(args.output, "w") as outfile:
        for e in all_findings:
            outfile.write(json.dumps(e) + "\n")

    total_bypassed = sum(1 for f in all_findings if f.get("bypassed"))
    print(f"\n[*] {total_bypassed}/{len(all_findings)} tests indicated MFA bypass potential", file=sys.stderr)
    print(f"[*] Findings written to {args.output}", file=sys.stderr)

    sys.exit(1 if total_bypassed > 0 else 0)

if __name__ == "__main__":
    main()