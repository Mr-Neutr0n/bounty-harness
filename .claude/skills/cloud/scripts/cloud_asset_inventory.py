#!/usr/bin/env python3
"""Collect cloud asset inventory when cloudlist is configured."""

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_context(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize cloudlist output for a target")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ctx = load_context(args.context)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_path = output.with_suffix(".raw.txt")
    records: list[dict] = []
    if shutil.which("cloudlist"):
        result = subprocess.run(["cloudlist", "-json"], capture_output=True, text=True, timeout=600)
        raw_path.write_text(result.stdout + result.stderr, encoding="utf-8")
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or args.target.lower() not in line.lower():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                raw = {"asset": line}
            records.append({
                "tool": "cloudlist",
                "target": args.target,
                "url": str(raw.get("url", "")),
                "host": str(raw.get("host") or raw.get("name") or raw.get("asset") or ""),
                "finding_type": "cloud_asset",
                "severity": "info",
                "confidence": 0.5,
                "evidence": raw,
                "raw": raw,
                "timestamp": now_iso(),
                "run_id": ctx.get("run_id", ""),
                "scope_status": "unknown",
            })
    with output.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
