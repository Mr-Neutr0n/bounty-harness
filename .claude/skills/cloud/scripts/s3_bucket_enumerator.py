#!/usr/bin/env python3
"""
S3 Bucket Enumerator — generates bucket name permutations from a target domain
and tests each for existence, public access, listing, and writeability.

Uses HTTP(S) requests against the S3 REST API endpoints:
  - https://{bucket}.s3.amazonaws.com/
  - https://{bucket}.s3-{region}.amazonaws.com/

Reports: bucket_name, exists, public, listable, writable, readable, region
Outputs findings.jsonl
"""

import argparse
import json
import sys
import os
import time
import re
import hashlib
import urllib.parse
import urllib.request
import ssl
import xml.etree.ElementTree as ET
from typing import Optional


NS = ""


BUCKET_PERMUTATIONS = [
    "{domain}",
    "{domain_clean}-assets",
    "{domain_clean}-static",
    "{domain_clean}-media",
    "{domain_clean}-files",
    "{domain_clean}-uploads",
    "{domain_clean}-cdn",
    "{domain_clean}-backups",
    "{domain_clean}-logs",
    "{domain_clean}-dev",
    "{domain_clean}-staging",
    "{domain_clean}-prod",
    "{domain_clean}-production",
    "{domain_clean}-test",
    "assets.{domain_clean}",
    "static.{domain_clean}",
    "media.{domain_clean}",
    "files.{domain_clean}",
    "cdn.{domain_clean}",
    "uploads.{domain_clean}",
    "www.{domain_clean}",
    "dev-{domain_clean}",
    "staging-{domain_clean}",
    "prod-{domain_clean}",
    "test-{domain_clean}",
    "{domain_clean}-terraform",
    "{domain_clean}-tfstate",
    "{domain_clean}-cloudformation",
    "{domain_clean}-cfn",
    "{company_name}",
    "{company_name}-{domain_clean}",
    "{company_short}-{domain_clean}",
]


def _extract_company_name(domain: str) -> str:
    parts = domain.replace(".com", "").replace(".org", "").replace(".net", "").replace(".io", "").split(".")
    return parts[0] if parts else domain


def _generate_permutations(domain: str) -> list:
    domain_clean = domain.replace(".", "-")
    company_name = _extract_company_name(domain)
    company_short = company_name[:4] if len(company_name) > 4 else company_name

    names = set()
    for template in BUCKET_PERMUTATIONS:
        name = template.format(
            domain=domain,
            domain_clean=domain_clean,
            company_name=company_name,
            company_short=company_short,
        )
        name = re.sub(r"[^a-zA-Z0-9.\-]", "-", name)
        while "--" in name:
            name = name.replace("--", "-")
        name = name.strip("-")
        if 3 <= len(name) <= 63:
            names.add(name)
    return sorted(names)


def _s3_request(bucket: str, path: str = "", method: str = "GET", data: bytes = None, timeout: int = 15) -> dict:
    url = f"https://{bucket}.s3.amazonaws.com/{path.lstrip('/')}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }
    if data:
        headers["Content-Length"] = str(len(data))
        headers["Content-Type"] = "application/octet-stream"

    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return {
            "status": resp.status,
            "headers": resp_headers,
            "body": body.decode(errors="replace"),
            "raw_body": body,
            "error": None,
            "bucket_exists": True,
        }
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b""
        resp_headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        return {
            "status": e.code,
            "headers": resp_headers,
            "body": body.decode(errors="replace"),
            "raw_body": body,
            "error": None,
            "bucket_exists": e.code != 404,
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "raw_body": b"",
            "error": str(e),
            "bucket_exists": False,
        }


def _parse_list_response(xml_body: str) -> list:
    keys = []
    try:
        root = ET.fromstring(xml_body)
        ns_match = re.match(r"\{(.*?)\}", root.tag)
        ns = ns_match.group(1) if ns_match else ""
        for contents in root.findall(f"{{{ns}}}Contents"):
            key_elem = contents.find(f"{{{ns}}}Key")
            if key_elem is not None and key_elem.text:
                keys.append(key_elem.text)
    except ET.ParseError:
        pass
    return keys


def _parse_error(xml_body: str) -> dict:
    info = {"code": "", "message": ""}
    try:
        root = ET.fromstring(xml_body)
        ns_match = re.match(r"\{(.*?)\}", root.tag)
        ns = ns_match.group(1) if ns_match else ""
        code = root.find(f"{{{ns}}}Code")
        msg = root.find(f"{{{ns}}}Message")
        info["code"] = code.text if code is not None else ""
        info["message"] = msg.text if msg is not None else ""
    except ET.ParseError:
        pass
    return info


def _test_bucket(bucket: str, timeout: int) -> dict:
    result = {
        "bucket_name": bucket,
        "exists": False,
        "public": False,
        "listable": False,
        "writable": False,
        "readable": False,
        "region": "",
        "error": None,
        "keys_found": [],
    }

    root_resp = _s3_request(bucket, timeout=timeout)
    if root_resp.get("error"):
        result["error"] = root_resp["error"]
        return result

    if root_resp["status"] == 0:
        result["error"] = root_resp.get("error", "Connection failed")
        return result

    error_info = _parse_error(root_resp.get("body", ""))

    if root_resp["status"] == 404:
        return result

    result["exists"] = True

    x_amz_region = root_resp.get("headers", {}).get("x-amz-bucket-region", "")
    result["region"] = x_amz_region

    if root_resp["status"] == 403 and "AccessDenied" in error_info.get("code", ""):
        return result

    if error_info.get("code") in ("NoSuchBucket", "NotFound"):
        result["exists"] = False
        return result

    if root_resp["status"] in (200, 403) and root_resp.get("body"):
        pass

    if root_resp["status"] == 200:
        result["public"] = True
        if "<ListBucketResult" in root_resp["body"] or "<Contents>" in root_resp["body"]:
            result["listable"] = True
            result["keys_found"] = _parse_list_response(root_resp["body"])[:50]
        elif "<?xml" in root_resp.get("body", "")[:200]:
            pass
        else:
            result["readable"] = True

    if root_resp["status"] == 403:
        result["readable"] = False

    acl_resp = _s3_request(bucket, "?acl", timeout=timeout)
    if acl_resp["status"] == 200:
        pass

    policy_resp = _s3_request(bucket, "?policy", timeout=timeout)
    if policy_resp["status"] == 200:
        result["public"] = True

    put_test = _s3_request(bucket, "__s3_enum_test.txt", "PUT",
                           data=b"Bucket enumeration test - safe to delete", timeout=timeout)
    if put_test["status"] in (200, 201):
        result["writable"] = True

    if result["keys_found"]:
        test_key = result["keys_found"][0]
        get_resp = _s3_request(bucket, test_key, timeout=timeout)
        if get_resp["status"] == 200:
            result["readable"] = True

    return result


def run_enumeration(target: str, context: Optional[str], timeout: int, dry_run: bool) -> list:
    results = []
    buckets = _generate_permutations(target)

    domain_clean = target.replace(".", "-")
    company = _extract_company_name(target)
    extra = [
        company,
        f"{company}-backup",
        f"{company}-data",
    ]
    for e in extra:
        e = re.sub(r"[^a-zA-Z0-9.\-]", "-", e)
        e = e.strip("-")
        if 3 <= len(e) <= 63 and e not in buckets:
            buckets.append(e)

    sys.stderr.write(f"[*] Generated {len(buckets)} bucket name permutations\n")

    for idx, bucket in enumerate(buckets):
        if dry_run:
            results.append({
                "bucket_name": bucket,
                "exists": False,
                "public": False,
                "listable": False,
                "writable": False,
                "readable": False,
                "region": "",
                "keys_found": [],
                "dry_run": True,
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            sys.stderr.write(f"[dry-run] {idx+1}/{len(buckets)}: {bucket}\n")
            continue

        sys.stderr.write(f"[{idx+1}/{len(buckets)}] Testing: {bucket}\n")
        try:
            bucket_result = _test_bucket(bucket, timeout)
            bucket_result["context"] = context
            bucket_result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            if bucket_result["exists"]:
                severity = "HIGH"
                vuln = True
            else:
                severity = "INFO"
                vuln = False

            bucket_result["vulnerable"] = vuln
            bucket_result["severity"] = severity
            bucket_result["exploit_scenario"] = (
                f"Bucket {bucket!r} exists and is "
                + ("publicly listable" if bucket_result["listable"]
                   else ("publicly readable" if bucket_result["readable"]
                         else ("writable" if bucket_result["writable"]
                               else "accessible"))))
            results.append(bucket_result)
        except Exception as e:
            results.append({
                "bucket_name": bucket,
                "exists": False,
                "public": False,
                "listable": False,
                "writable": False,
                "readable": False,
                "region": "",
                "error": str(e),
                "vulnerable": False,
                "severity": "ERROR",
                "exploit_scenario": "",
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            sys.stderr.write(f"  [!] Error: {e}\n")

        time.sleep(0.3)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="S3 Bucket Enumerator — discover and test S3 buckets for a target domain",
    )
    parser.add_argument("--target", required=True, help="Target domain (e.g., ycombinator.com)")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Show generated bucket names without making requests")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    sys.stderr.write(f"[*] S3 Bucket Enumerator\n")
    sys.stderr.write(f"[*] Target: {args.target}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")
    sys.stderr.write(f"[*] Dry run: {args.dry_run}\n")

    results = run_enumeration(args.target, args.context, args.timeout, args.dry_run)

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    sys.stderr.write(f"\n[*] Results written to {outfile}\n")

    exists = [r for r in results if r.get("exists")]
    listable = [r for r in results if r.get("listable")]
    writable = [r for r in results if r.get("writable")]

    sys.stderr.write(f"[*] Summary: {len(exists)} buckets exist, {len(listable)} listable, {len(writable)} writable\n")
    for b in listable:
        sys.stderr.write(f"  [HIGH] {b['bucket_name']} — publicly listable ({len(b.get('keys_found',[]))} keys)\n")
    for b in writable:
        sys.stderr.write(f"  [HIGH] {b['bucket_name']} — writable by anyone\n")

    print(json.dumps({
        "total_tested": len(results),
        "exist": len(exists),
        "listable": len(listable),
        "writable": len(writable),
        "buckets": [r["bucket_name"] for r in exists],
    }, indent=2))


if __name__ == "__main__":
    main()