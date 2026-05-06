#!/usr/bin/env python3
"""Prioritize explicit CVE IDs with cvemap when available."""

import argparse
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_context(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run cvemap for explicit CVE IDs")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--cve-ids", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ctx = load_context(args.context)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_path = output.with_suffix(".raw.jsonl")
    cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(args.cve_ids)})
    records: list[dict] = []
    if cves and shutil.which("cvemap"):
        result = subprocess.run(["cvemap", "-id", ",".join(cves), "-json"], capture_output=True, text=True, timeout=300)
        raw_path.write_text(result.stdout + result.stderr, encoding="utf-8")
        for line in result.stdout.splitlines():
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            cve_id = str(raw.get("cve_id") or raw.get("id") or "")
            records.append({
                "tool": "cvemap",
                "target": ctx.get("target", ""),
                "url": "",
                "host": ctx.get("target_host", ""),
                "finding_type": "cve_prioritized",
                "severity": str(raw.get("severity") or "info").lower(),
                "confidence": 0.7,
                "evidence": {"cve_id": cve_id},
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
