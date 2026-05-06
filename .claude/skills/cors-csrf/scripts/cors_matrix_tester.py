#!/usr/bin/env python3
"""
CORS Matrix Tester — tests all CORS origin misconfiguration vectors.

Checks:
  - Origin reflection (random domain)
  - Null origin
  - Subdomain prefix (evil.TARGET)
  - Suffix spoof (TARGET.com.evil.com)
  - Protocol mismatch (http vs https)
  - Preflight response (OPTIONS)
  - Wildcard + credentials combo
  - Credentials reflection (Access-Control-Allow-Credentials)

Outputs findings.jsonl — one JSON object per tested vector.
"""

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
import ssl
import re
from typing import Optional

VULN_THRESHOLDS = {
    "wildcard_with_credentials": "CRITICAL",
    "null_origin_accepted_with_credentials": "HIGH",
    "origin_reflected_with_credentials": "HIGH",
    "origin_reflected_without_credentials": "MEDIUM",
    "null_origin_accepted": "MEDIUM",
    "suffix_spoof_reflected": "MEDIUM",
    "protocol_mismatch_bypass": "MEDIUM",
    "subdomain_prefix_reflected": "LOW",
    "preflight_missing": "INFO",
}


def _origin_header_to_value(header_str: str) -> Optional[str]:
    try:
        _, val = header_str.split(":", 1)
        return val.strip()
    except ValueError:
        return None


def _fetch(url: str, headers: dict, method: str = "GET", timeout: int = 15) -> dict:
    req = urllib.request.Request(url, method=method, headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode(errors="replace")
        response_headers = {k.lower(): v for k, v in resp.getheaders()}
        return {
            "status": resp.status,
            "headers": response_headers,
            "body": body[:4096],
            "error": None,
        }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {},
            "body": e.read().decode(errors="replace")[:4096] if e.fp else "",
            "error": None,
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _analyze_response(resp: dict, origin_sent: str, expected_origin: str, vector_name: str) -> dict:
    acao = resp["headers"].get("access-control-allow-origin", "")
    acac = resp["headers"].get("access-control-allow-credentials", "")
    acam = resp["headers"].get("access-control-allow-methods", "")
    acheaders = resp["headers"].get("access-control-allow-headers", "")

    vulnerable = False
    severity = "INFO"
    scenario = ""
    vuln_type = ""

    if acao == "*" and acac.lower() == "true":
        vulnerable = True
        severity = "CRITICAL"
        vuln_type = "wildcard_with_credentials"
        scenario = "Wildcard origin with credentials allows any origin to make credentialed requests"
    elif acao == "*":
        vuln_type = "wildcard_no_credentials"
        scenario = "Wildcard ACAO without credentials — read-only CORS for any origin"
    elif acao and (acao == origin_sent or acao == expected_origin):
        vulnerable = True
        vuln_type = "origin_reflected"
        if acac.lower() == "true":
            severity = "HIGH"
            vuln_type = "origin_reflected_with_credentials"
            scenario = f"Origin {origin_sent!r} reflected in ACAO with credentials"
        else:
            severity = "MEDIUM"
            vuln_type = "origin_reflected_without_credentials"
            scenario = f"Origin {origin_sent!r} reflected in ACAO without credentials (read-only)"
    elif acao and (origin_sent == "null" or acao == "null"):
        if acao == "null":
            vulnerable = True
            vuln_type = "null_origin_accepted"
            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            scenario = "Null origin accepted" + (" with credentials" if acac.lower() == "true" else "")
    elif acao == expected_origin and expected_origin != origin_sent:
        vulnerable = True
        vuln_type = "origin_trimmed_reflected"
        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
        scenario = f"Origin trimmed to {expected_origin!r} and reflected"

    if vector_name == "protocol_mismatch" and vulnerable:
        vuln_type = "protocol_mismatch_bypass"
        scenario = "HTTP origin accepted against HTTPS endpoint"

    if vector_name == "suffix_spoof" and vulnerable:
        vuln_type = "suffix_spoof_reflected"
        scenario = "Suffix-spoofed domain reflected in ACAO"

    return {
        "vector": vector_name,
        "origin_sent": origin_sent,
        "acao_value": acao,
        "acac_value": acac,
        "acam_value": acam,
        "acheaders_value": acheaders,
        "status": resp["status"],
        "vulnerable": vulnerable,
        "vuln_type": vuln_type,
        "severity": severity,
        "exploit_scenario": scenario,
        "error": resp["error"],
    }


def _test_preflight(target_url: str, origin: str, timeout: int) -> dict:
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type,X-Custom",
    }
    resp = _fetch(target_url, headers, method="OPTIONS", timeout=timeout)
    acao = resp["headers"].get("access-control-allow-origin", "")
    acac = resp["headers"].get("access-control-allow-credentials", "")
    acam = resp["headers"].get("access-control-allow-methods", "")
    acheaders = resp["headers"].get("access-control-allow-headers", "")

    vulnerable = acao == origin or acao == "*"
    vuln_type = "preflight_origin_reflected" if acao == origin else "preflight_wildcard" if acao == "*" else "preflight_blocked"

    return {
        "vector": "preflight_test",
        "origin_sent": origin,
        "acao_value": acao,
        "acac_value": acac,
        "acam_value": acam,
        "acheaders_value": acheaders,
        "status": resp["status"],
        "vulnerable": vulnerable,
        "vuln_type": vuln_type,
        "severity": "MEDIUM" if (vulnerable and acac.lower() == "true") else ("LOW" if vulnerable else "INFO"),
        "exploit_scenario": "Preflight CORS headers allow cross-origin requests" if vulnerable else "Preflight blocks CORS",
        "error": resp["error"],
    }


def run_tests(target_url: str, context: Optional[str] = None, timeout: int = 15, dry_run: bool = False) -> list:
    parsed = urllib.parse.urlparse(target_url)
    target_host = parsed.hostname or ""

    vectors = []

    if target_host:
        vectors.append(("random_domain", f"https://evil-{int(time.time())}.com"))
        vectors.append(("null_origin", "null"))
        vectors.append(("subdomain_prefix", f"http://evil.{target_host}"))
        vectors.append(("suffix_spoof", f"https://{target_host}.evil.com"))
    else:
        sys.stderr.write("[!] Could not parse host from target URL; skipping host-based vectors\n")

    if target_host:
        proto = parsed.scheme
        flip_proto = "http" if proto == "https" else "https"
        vectors.append(("protocol_mismatch", f"{flip_proto}://{target_host}"))

        vectors.append(("same_origin_self", f"{proto}://{target_host}"))

    results = []

    for vector_name, origin_value in vectors:
        if dry_run:
            sys.stderr.write(f"[dry-run] Would test vector={vector_name} origin={origin_value}\n")
            results.append({
                "vector": vector_name,
                "origin_sent": origin_value,
                "acao_value": "",
                "acac_value": "",
                "status": 0,
                "vulnerable": False,
                "vuln_type": "",
                "severity": "INFO",
                "exploit_scenario": "",
                "error": None,
                "dry_run": True,
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            continue

        sys.stderr.write(f"[*] Testing vector: {vector_name} (origin={origin_value})\n")
        headers = {"Origin": origin_value}
        resp = _fetch(target_url, headers, timeout=timeout)
        finding = _analyze_response(resp, origin_value, origin_value, vector_name)
        finding["context"] = context
        finding["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if resp["status"] == 0:
            finding["error"] = resp["error"]
        results.append(finding)

    if target_host:
        random_origin = f"https://evil-{int(time.time())}.com"
        if dry_run:
            sys.stderr.write(f"[dry-run] Would test preflight with origin={random_origin}\n")
            results.append({
                "vector": "preflight_test",
                "origin_sent": random_origin,
                "acao_value": "",
                "acac_value": "",
                "status": 0,
                "vulnerable": False,
                "vuln_type": "",
                "severity": "INFO",
                "exploit_scenario": "",
                "error": None,
                "dry_run": True,
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
        else:
            sys.stderr.write("[*] Testing preflight (OPTIONS)\n")
            pf = _test_preflight(target_url, random_origin, timeout)
            pf["context"] = context
            pf["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            results.append(pf)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="CORS Matrix Tester — test all CORS origin misconfiguration vectors",
    )
    parser.add_argument("--target-url", required=True, help="Target URL to test CORS against")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be tested without making requests")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if not args.target_url:
        parser.error("--target-url is required")

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    sys.stderr.write(f"[*] CORS Matrix Tester\n")
    sys.stderr.write(f"[*] Target: {args.target_url}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")
    sys.stderr.write(f"[*] Dry run: {args.dry_run}\n")

    results = run_tests(args.target_url, context=args.context, timeout=args.timeout, dry_run=args.dry_run)

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    sys.stderr.write(f"\n[*] Results written to {outfile}\n")

    vuln_count = sum(1 for r in results if r.get("vulnerable"))
    total = len(results)
    sys.stderr.write(f"[*] Summary: {vuln_count}/{total} vectors flagged as vulnerable\n")

    for r in results:
        if r.get("vulnerable"):
            sys.stderr.write(f"  [{r['severity']}] {r['vector']}: {r['exploit_scenario']}\n")

    if vuln_count == 0:
        sys.stderr.write("[*] No CORS vulnerabilities detected\n")

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()