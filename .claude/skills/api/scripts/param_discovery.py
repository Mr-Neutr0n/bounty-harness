#!/usr/bin/env python3
"""Run arjun when available and normalize discovered parameters."""

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
    parser = argparse.ArgumentParser(description="Discover API parameters with arjun")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ctx = load_context(args.context)
    input_path = Path(args.input)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_json = output.with_suffix(".raw.json")
    records: list[dict] = []
    if input_path.exists() and input_path.stat().st_size > 0 and shutil.which("arjun"):
        cmd = ["arjun", "-i", str(input_path), "-oJ", str(raw_json)]
        subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        try:
            parsed = json.loads(raw_json.read_text(encoding="utf-8"))
        except Exception:
            parsed = {}
        for url, params in (parsed.items() if isinstance(parsed, dict) else []):
            values = params if isinstance(params, list) else params.get("params", []) if isinstance(params, dict) else []
            for param in values:
                raw = {"url": url, "parameter": param}
                records.append({
                    "tool": "arjun",
                    "target": ctx.get("target", ""),
                    "url": url,
                    "host": ctx.get("target_host", ""),
                    "finding_type": "parameter_discovered",
                    "severity": "info",
                    "confidence": 0.6,
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
