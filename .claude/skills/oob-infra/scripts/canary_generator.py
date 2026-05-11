#!/usr/bin/env python3
"""Canary Generator — batch create canary payloads for common test scenarios.

Usage:
    canary_generator.py --session .bb/oob/session.json --count 10 --purpose ssrf --output canaries.jsonl
"""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_canaries(session_file: str, count: int, purpose: str, output_path: str) -> dict:
    session = json.loads(Path(session_file).read_text()) if Path(session_file).exists() else {}
    base_url = session.get("url", "oast.pro")
    canaries = []
    for i in range(count):
        cid = str(uuid.uuid4())[:8]
        canary = {
            "canary_id": cid,
            "url": f"{cid}.{base_url}",
            "http_url": f"http://{cid}.{base_url}",
            "https_url": f"https://{cid}.{base_url}",
            "purpose": purpose,
            "test_id": f"{purpose}-{i+1:03d}",
            "created_at": now_iso(),
            "session_id": session.get("session_id", ""),
        }
        canaries.append(canary)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for c in canaries:
            f.write(json.dumps(c) + "\n")

    return {"status": "generated", "count": len(canaries), "output": output_path}


def main():
    parser = argparse.ArgumentParser(description="Canary Generator")
    parser.add_argument("--session", required=True, help="Session JSON file")
    parser.add_argument("--count", type=int, default=10, help="Number of canaries")
    parser.add_argument("--purpose", required=True, help="Purpose label")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    args = parser.parse_args()
    result = generate_canaries(args.session, args.count, args.purpose, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
