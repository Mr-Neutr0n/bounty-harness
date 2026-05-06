#!/usr/bin/env python3
"""Cross-Origin Policy Auditor — checks COOP, COEP, CORP, Permissions-Policy, and CORS headers."""

import argparse
import json
import os
import sys
import re
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


HEADER_CHECKS = {
    "Cross-Origin-Opener-Policy": {
        "key": "coop",
        "description": "Prevents cross-origin openers from having synchronous access",
        "secure_values": ["same-origin", "same-origin-allow-popups"],
        "insecure_values": ["unsafe-none"],
        "check": lambda v: v.strip().lower() in ("same-origin", "same-origin-allow-popups"),
    },
    "Cross-Origin-Embedder-Policy": {
        "key": "coep",
        "description": "Controls which cross-origin resources may be loaded",
        "secure_values": ["require-corp", "credentialless"],
        "insecure_values": ["unsafe-none"],
        "check": lambda v: v.strip().lower() in ("require-corp", "credentialless"),
    },
    "Cross-Origin-Resource-Policy": {
        "key": "corp",
        "description": "Restricts resource loading from cross-origin contexts",
        "secure_values": ["same-origin", "same-site"],
        "insecure_values": ["cross-origin"],
        "check": lambda v: v.strip().lower() in ("same-origin", "same-site"),
    },
    "Permissions-Policy": {
        "key": "permissions_policy",
        "description": "Controls browser features available to the page and embedded frames",
        "secure_values": [],
        "insecure_values": [],
        "check": lambda v: len(v) > 0,
    },
    "Access-Control-Allow-Origin": {
        "key": "acao",
        "description": "CORS — which origins may access this resource via XHR/fetch",
        "secure_values": [],
        "insecure_values": ["*", "null"],
        "check": lambda v: v.strip() != "*" and v.strip().lower() != "null",
    },
    "Access-Control-Allow-Credentials": {
        "key": "acac",
        "description": "Allows credentialed cross-origin requests",
        "secure_values": [],
        "insecure_values": [],
        "check": lambda v: v.strip().lower() == "true",
    },
    "Timing-Allow-Origin": {
        "key": "tao",
        "description": "Controls which origins may observe resource timing",
        "secure_values": [],
        "insecure_values": ["*"],
        "check": lambda v: v.strip() != "*",
    },
}

HEADER_KEYS_LOWER = {k.lower(): k for k in HEADER_CHECKS}


def build_parser():
    p = argparse.ArgumentParser(description="Audit cross-origin isolation and CORS policies for URLs")
    p.add_argument("--urls", default=None, nargs="*", help="One or more target URLs")
    p.add_argument("--urls-file", default=None, help="File with URLs (one per line)")
    p.add_argument("--context", default="default", help="Assessment context label")
    p.add_argument("--output", default=None, help="Output path for findings.jsonl")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--concurrency", type=int, default=10, help="Parallel request count")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    p.add_argument("--user-agent", default="cross_origin_auditor/1.0", help="User-Agent header")
    p.add_argument("--method", default="GET", choices=["GET", "HEAD", "OPTIONS"], help="HTTP method")
    return p


def fetch_headers(url, timeout, user_agent, method):
    headers = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": user_agent}, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            for k, v in resp.getheaders():
                headers[k] = v
            headers[":status"] = resp.status
    except urllib.error.HTTPError as e:
        for k, v in e.headers.items():
            headers[k] = v
        headers[":status"] = e.code
    except Exception as exc:
        headers[":error"] = str(exc)
    return headers


def score_isolation(headers_dict):
    score = 0
    max_score = 6
    details = {}

    coop_raw = headers_dict.get("Cross-Origin-Opener-Policy", "")
    if coop_raw:
        lowered = coop_raw.strip().lower()
        if lowered == "same-origin":
            score += 1
            details["coop"] = "secure (same-origin)"
        elif lowered == "same-origin-allow-popups":
            score += 1
            details["coop"] = "secure (same-origin-allow-popups)"
    else:
        details["coop"] = "missing"

    coep_raw = headers_dict.get("Cross-Origin-Embedder-Policy", "")
    if coep_raw:
        lowered = coep_raw.strip().lower()
        if lowered in ("require-corp", "credentialless"):
            score += 1
            details["coep"] = f"secure ({lowered})"
    else:
        details["coep"] = "missing"

    corp_raw = headers_dict.get("Cross-Origin-Resource-Policy", "")
    if corp_raw:
        lowered = corp_raw.strip().lower()
        if lowered in ("same-origin", "same-site"):
            score += 1
            details["corp"] = f"secure ({lowered})"
        else:
            details["corp"] = f"weak ({lowered})"
    else:
        details["corp"] = "missing"

    pp_raw = headers_dict.get("Permissions-Policy", "")
    has_pp = bool(pp_raw.strip())
    if has_pp:
        directives = [d.strip() for d in pp_raw.split(",") if d.strip()]
        restrictive = any(
            "self" in d.lower() or "none" in d.lower() or "()" in d.lower()
            for d in directives
        )
        if restrictive:
            score += 1
            details["permissions_policy"] = "configured (restrictive)"
        else:
            details["permissions_policy"] = "configured (permissive)"
    else:
        details["permissions_policy"] = "missing"

    acao = headers_dict.get("Access-Control-Allow-Origin", "")
    if acao.strip() == "*":
        score -= 1
        details["acao"] = "wildcard (*) — permissive"
    elif not acao:
        details["acao"] = "missing"
    else:
        details["acao"] = f"restricted to: {acao.strip()}"

    acac = headers_dict.get("Access-Control-Allow-Credentials", "")
    if acac.strip().lower() == "true" and acao.strip() == "*":
        score -= 1
        details["acac"] = "credentials=true with wildcard origin — browser will block"
    elif acac.strip().lower() == "true":
        details["acac"] = "credentials enabled (requires specific origin)"

    tao = headers_dict.get("Timing-Allow-Origin", "")
    if tao.strip() == "*":
        details["tao"] = "wildcard (*) — timing leaks via Resource Timing API"
    elif tao:
        details["tao"] = f"restricted: {tao.strip()}"

    score = max(0, min(score, max_score))
    percentage = round((score / max_score) * 100)

    if percentage >= 80:
        isolation_level = "strong"
    elif percentage >= 50:
        isolation_level = "moderate"
    elif percentage >= 20:
        isolation_level = "weak"
    else:
        isolation_level = "none"

    return {
        "isolation_score": score,
        "isolation_max": max_score,
        "isolation_percent": percentage,
        "isolation_level": isolation_level,
        "details": details,
    }


def check_misconfigurations(headers_dict, isolation):
    issues = []

    acao = headers_dict.get("Access-Control-Allow-Origin", "")
    acac = headers_dict.get("Access-Control-Allow-Credentials", "")

    if acao.strip() == "*":
        if acac.strip().lower() == "true":
            issues.append("ACAO wildcard + credentials — will be blocked by browser (but indicates intent)")

    if acao.strip() == "null":
        issues.append("ACAO set to 'null' — sandboxed/null-origin access allowed")

    if not headers_dict.get("X-Content-Type-Options"):
        issues.append("Missing X-Content-Type-Options: nosniff")
    if not headers_dict.get("X-Frame-Options"):
        issues.append("Missing X-Frame-Options — no clickjacking protection via header")

    if isolation["isolation_level"] == "none" and not issues:
        issues.append("No cross-origin isolation headers configured at all")

    return issues


def audit_url(url, args):
    finding = {
        "tool": "cross_origin_auditor",
        "context": args.context,
        "target": url,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status_code": None,
        "headers": {},
        "isolation_score": 0,
        "isolation_level": "none",
        "isolation_details": {},
        "misconfigurations": [],
        "risk_level": "none",
        "risk_notes": "",
        "errors": [],
    }

    if args.dry_run:
        finding["dry_run"] = True
        finding["risk_notes"] = "DRY RUN — would fetch headers and audit policies"
        return finding

    headers = fetch_headers(url, args.timeout, args.user_agent, args.method)
    if ":error" in headers:
        finding["errors"].append(headers[":error"])
        finding["risk_level"] = "unknown"
        finding["risk_notes"] = f"Connection error: {headers[':error']}"
        return finding

    finding["status_code"] = headers.pop(":status", None)
    finding["headers"] = headers

    isolation = score_isolation(headers)
    finding["isolation_score"] = isolation["isolation_score"]
    finding["isolation_level"] = isolation["isolation_level"]
    finding["isolation_details"] = isolation["details"]

    misconfigs = check_misconfigurations(headers, isolation)
    finding["misconfigurations"] = misconfigs

    if isolation["isolation_level"] == "none":
        finding["risk_level"] = "high"
    elif isolation["isolation_level"] == "weak":
        finding["risk_level"] = "medium"
    elif isolation["isolation_level"] == "moderate":
        finding["risk_level"] = "low"
    else:
        finding["risk_level"] = "none"

    finding["risk_notes"] = f"Isolation: {isolation['isolation_level']} ({isolation['isolation_percent']}%). " + (
        f"Misconfigs: {len(misconfigs)}." if misconfigs else "No misconfigurations detected."
    )

    return finding


def main():
    parser = build_parser()
    args = parser.parse_args()

    urls = []
    if args.urls_file:
        if os.path.isfile(args.urls_file):
            with open(args.urls_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        else:
            print(f"Error: urls-file not found: {args.urls_file}", file=sys.stderr)
            sys.exit(1)
    if args.urls:
        urls.extend(args.urls)

    if not urls:
        print("Error: No URLs provided (--urls or --urls-file)", file=sys.stderr)
        sys.exit(1)

    urls = list(dict.fromkeys(urls))

    findings = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_map = {executor.submit(audit_url, url, args): url for url in urls}
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                findings.append(future.result())
            except Exception as exc:
                findings.append({
                    "tool": "cross_origin_auditor",
                    "context": args.context,
                    "target": url,
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "risk_level": "unknown",
                    "risk_notes": f"Thread error: {exc}",
                    "errors": [str(exc)],
                })

    findings.sort(key=lambda f: f.get("target", ""))

    out_fh = sys.stdout
    close_out = False
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        out_fh = open(args.output, "a")
        close_out = True

    try:
        for f in findings:
            out_fh.write(json.dumps(f, default=str) + "\n")
        out_fh.flush()
    finally:
        if close_out:
            out_fh.close()

    high_misconfig = sum(1 for f in findings if f["risk_level"] in ("high", "medium"))
    total = len(findings)
    if total:
        print(f"Audited {total} URL(s): {high_misconfig} with medium+ risk", file=sys.stderr)


if __name__ == "__main__":
    main()