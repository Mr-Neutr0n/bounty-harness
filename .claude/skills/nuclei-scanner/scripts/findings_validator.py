#!/usr/bin/env python3
"""Findings Validator — validates nuclei results with direct curl verification and confidence scoring."""

import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


def build_parser():
    p = argparse.ArgumentParser(description="Validate nuclei findings via curl verification")
    p.add_argument("--nuclei-jsonl", required=True, help="Path to nuclei JSONL results file")
    p.add_argument("--context", default="default", help="Assessment context label")
    p.add_argument("--output", default=None, help="Output path for validated_findings.jsonl")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--concurrency", type=int, default=10, help="Parallel verification count")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    p.add_argument("--sample-size", type=int, default=0, help="Max findings to validate (0=all)")
    p.add_argument("--verify-ssl", action="store_true", default=False, help="Verify SSL certificates")
    p.add_argument("--method", default="GET", help="HTTP method for verification request")
    p.add_argument("--follow-redirects", action="store_true", default=True, help="Follow HTTP redirects")
    return p


def load_nuclei_findings(path, sample_size):
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                findings.append(obj)
            except json.JSONDecodeError:
                continue

    if sample_size and len(findings) > sample_size:
        import random
        return random.sample(findings, sample_size)
    return findings


def extract_url_from_matched(matched_at, host):
    if not matched_at:
        return host if host and host.startswith("http") else None

    candidate = matched_at.strip()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    if host and host.startswith("http"):
        if candidate.startswith("/"):
            return host.rstrip("/") + candidate
        else:
            return host.rstrip("/") + "/" + candidate
    return None


def fetch_response(url, timeout, verify_ssl, method, follow_redirects):
    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "body_sample": "",
        "body_length": 0,
        "error": None,
    }

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    redirect_handler = urllib.request.HTTPRedirectHandler() if follow_redirects else NoRedirectHandler()
    opener = urllib.request.build_opener(redirect_handler)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "findings_validator/1.0"}, method=method)
        with opener.open(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            result["headers"] = dict(resp.headers.items())
            body = resp.read(4096)
            result["body_sample"] = body.decode("utf-8", errors="replace")[:2000]
            result["body_length"] = int(resp.headers.get("content-length", 0)) or len(body)
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["headers"] = dict(e.headers.items())
        try:
            body = e.read(4096)
            result["body_sample"] = body.decode("utf-8", errors="replace")[:2000]
            result["body_length"] = int(e.headers.get("content-length", 0)) or len(body)
        except Exception:
            pass
    except urllib.error.URLError as e:
        result["error"] = f"URLError: {e.reason}"
    except Exception as e:
        result["error"] = str(e)

    return result


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def pattern_present_in_body(body, pattern_str):
    if not pattern_str or not body:
        return False
    try:
        return bool(re.search(re.escape(pattern_str), body, re.IGNORECASE))
    except re.error:
        lower_pat = pattern_str.lower()
        lowered_body = body.lower()
        return lower_pat in lowered_body


def extract_match_indicators(finding):
    indicators = []

    raw = finding.get("raw", finding)

    for key in ["matched-at", "matched", "match"]:
        val = raw.get(key, "")
        if val:
            indicators.append(str(val))

    curl_cmd = raw.get("curl-command", raw.get("curl_command", ""))
    if curl_cmd:
        indicators.append(str(curl_cmd))

    if isinstance(raw.get("info"), dict):
        indicators.append(raw["info"].get("name", ""))

        classification = raw["info"].get("classification", {})
        if isinstance(classification, dict):
            indicators.append(classification.get("cve-id", [""])[0] if classification.get("cve-id") else "")
            indicators.append(classification.get("cwe-id", [""])[0] if classification.get("cwe-id") else "")

    extracted = raw.get("extracted-results", raw.get("extracted_results", []))
    if isinstance(extracted, list):
        for ex in extracted:
            if isinstance(ex, str):
                indicators.append(ex)

    request_str = raw.get("request", "")
    response_str = raw.get("response", "")

    if request_str:
        for subkey in ["path"]:
            pass

    if response_str:
        for line in response_str.split("\n")[:10]:
            stripped = line.strip()
            if stripped and len(stripped) > 4 and not stripped.startswith("<") and not stripped.startswith("HTTP"):
                indicators.append(stripped)

    return [i for i in indicators if i]


def validate_finding(finding, args):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    host = finding.get("host", "")
    matched_at = finding.get("matched_at", "")
    url = extract_url_from_matched(matched_at, host)

    result = {
        "tool": "findings_validator",
        "context": args.context,
        "template_id": finding.get("template_id", ""),
        "template_name": finding.get("template_name", ""),
        "severity": finding.get("severity", "unknown"),
        "risk_level": finding.get("risk_level", "unknown"),
        "host": host,
        "matched_at": matched_at,
        "url_used": url,
        "timestamp": timestamp,
        "validation_result": "unvalidated",
        "confidence": 0.0,
        "details": "",
        "response_status": None,
        "response_body_sample": "",
        "errors": [],
    }

    if args.dry_run:
        result["dry_run"] = True
        result["details"] = "DRY RUN — would verify URL via curl"
        return result

    if not url:
        result["validation_result"] = "unvalidated"
        result["confidence"] = 0.0
        result["details"] = "No verifiable URL extracted from finding"
        result["errors"].append("No URL available")
        return result

    try:
        response = fetch_response(
            url, args.timeout, args.verify_ssl, args.method, args.follow_redirects
        )
    except Exception as exc:
        result["validation_result"] = "unvalidated"
        result["confidence"] = 0.0
        result["details"] = f"Fetch error: {exc}"
        result["errors"].append(str(exc))
        return result

    result["response_status"] = response["status_code"]
    result["response_headers"] = response["headers"]
    result["response_body_sample"] = response["body_sample"]
    result["response_length"] = response["body_length"]

    if response["error"]:
        result["validation_result"] = "unreachable"
        result["confidence"] = 0.0
        result["details"] = f"URL unreachable: {response['error']}"
        result["errors"].append(response["error"])
        return result

    score = 0.0
    reasons = []

    if response["status_code"] and 200 <= response["status_code"] < 500:
        score += 0.2
        reasons.append(f"URL accessible (status {response['status_code']})")
    elif response["status_code"]:
        result["validation_result"] = "unreachable"
        result["confidence"] = 0.0
        result["details"] = f"Non-success status code: {response['status_code']}"
        return result

    indicators = extract_match_indicators(finding)
    match_found = False
    body = response["body_sample"] or ""

    for ind in indicators:
        if len(ind) < 3:
            continue
        if pattern_present_in_body(body, ind):
            match_found = True
            reasons.append(f"Pattern matched in response: '{ind[:80]}'")
            break

    path_from_url = urllib.parse.urlparse(url).path or "/"
    if not match_found and path_from_url and path_from_url != "/":
        if pattern_present_in_body(body, path_from_url):
            match_found = True
            reasons.append(f"URL path present in response: '{path_from_url}'")

    if match_found:
        score += 0.5
        if isinstance(finding.get("raw"), dict):
            raw = finding["raw"]
            if raw.get("response") and len(str(raw.get("response", ""))) > 50:
                score += 0.15
                reasons.append("Original nuclei response body present in raw results")

        if finding.get("extracted_results"):
            score += 0.05

        score = min(score, 1.0)
        if score >= 0.8:
            result["validation_result"] = "verified"
        elif score >= 0.5:
            result["validation_result"] = "likely_verified"
        else:
            result["validation_result"] = "needs_manual"
    else:
        if response["status_code"] and 200 <= response["status_code"] < 300:
            result["validation_result"] = "needs_manual"
            score = 0.3
            reasons.append("URL accessible but expected pattern NOT found in response")
        else:
            result["validation_result"] = "false_positive"
            score = 0.0
            reasons.append("Expected pattern not found — likely false positive")

    result["confidence"] = round(score, 2)
    result["details"] = "; ".join(reasons) if reasons else "No verification indicators available"

    return result


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.nuclei_jsonl):
        print(f"Error: nuclei-jsonl not found: {args.nuclei_jsonl}", file=sys.stderr)
        sys.exit(1)

    findings = load_nuclei_findings(args.nuclei_jsonl, args.sample_size)
    total = len(findings)
    print(f"Loaded {total} findings for validation (sample_size={args.sample_size or 'all'})", file=sys.stderr)

    if args.dry_run:
        print(f"DRY RUN: Would validate {total} findings via curl", file=sys.stderr)
        for f in findings:
            host = f.get("host", "")
            matched = f.get("matched_at", "")
            url = extract_url_from_matched(matched, host)
            entry = {
                "tool": "findings_validator",
                "context": args.context,
                "template_id": f.get("template_id", ""),
                "host": host,
                "matched_at": matched,
                "url_used": url,
                "dry_run": True,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "details": f"DRY RUN — would fetch: {url}" if url else "DRY RUN — no URL to verify",
            }
            print(json.dumps(entry, default=str))
        return

    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_map = {executor.submit(validate_finding, f, args): idx for idx, f in enumerate(findings)}
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({
                    "tool": "findings_validator",
                    "context": args.context,
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "validation_result": "error",
                    "confidence": 0.0,
                    "details": f"Validation thread error: {exc}",
                    "errors": [str(exc)],
                })

    results.sort(key=lambda r: r.get("template_id", ""))

    out_fh = sys.stdout
    close_out = False
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        out_fh = open(args.output, "a")
        close_out = True

    try:
        for r in results:
            out_fh.write(json.dumps(r, default=str) + "\n")
        out_fh.flush()
    finally:
        if close_out:
            out_fh.close()

    counts = {}
    for r in results:
        res = r.get("validation_result", "unknown")
        counts[res] = counts.get(res, 0) + 1

    print(f"Validation complete: {counts}", file=sys.stderr)

    verified = counts.get("verified", 0) + counts.get("likely_verified", 0)
    fp = counts.get("false_positive", 0)
    print(f"Summary: {verified} verified, {fp} false positives, {total} total", file=sys.stderr)


if __name__ == "__main__":
    main()