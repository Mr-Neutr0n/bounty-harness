#!/usr/bin/env python3
"""JWT Analyzer -- decode, inspect, and generate common test tokens."""
import argparse
import base64
import hashlib
import hmac
import json
import sys


def b64url_decode(part):
    padded = part + ("=" * ((4 - len(part) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode()).decode()


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return {"header": header, "payload": payload, "has_signature": len(parts) > 2 and bool(parts[2])}


def forge_alg_none(payload):
    header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


def forge_hs256(payload, secret):
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode()
    sig = b64url_encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def main():
    parser = argparse.ArgumentParser(description="Decode and generate JWT test tokens")
    parser.add_argument("token", nargs="?", help="JWT token to decode")
    parser.add_argument("--none", dest="none_payload", help="JSON payload for alg=none token")
    parser.add_argument("--hs256", dest="hs256_payload", help="JSON payload for HS256 token")
    parser.add_argument("--secret", default="secret", help="HS256 signing secret")
    parser.add_argument("--context", default="", help="Target context / scope description")
    parser.add_argument("--dry-run", action="store_true", help="Print planned action only")
    parser.add_argument("--output", default="", help="Optional JSONL output file")
    args = parser.parse_args()

    if args.dry_run:
        action = "decode" if args.token else "forge"
        print(json.dumps({"planned_action": action, "context": args.context}, indent=2))
        return 0

    try:
        if args.none_payload:
            result = {"type": "alg_none", "token": forge_alg_none(json.loads(args.none_payload)), "context": args.context}
        elif args.hs256_payload:
            result = {"type": "hs256", "token": forge_hs256(json.loads(args.hs256_payload), args.secret), "context": args.context}
        elif args.token:
            result = {"type": "decode", **decode_jwt(args.token), "context": args.context}
        else:
            parser.error("provide a token, --none JSON, or --hs256 JSON")
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2), file=sys.stderr)
        return 1

    line = json.dumps(result, sort_keys=True)
    if args.output:
        with open(args.output, "a") as f:
            f.write(line + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
