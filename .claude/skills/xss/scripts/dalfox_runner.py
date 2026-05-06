#!/usr/bin/env python3
"""Run dalfox when available and normalize its findings to JSONL."""

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


def find_urls(ctx: dict, explicit: str) -> Path | None:
    candidates = [Path(explicit)] if explicit else []
    outdir = Path(ctx.get("outdir", "."))
    candidates.extend([
        outdir / "recon/scoped/parameterized_urls.txt",
        outdir / "urls/parameterized_urls.txt",
        outdir / "recon/urls/parameterized_urls.txt",
    ])
    for path in candidates:
        if path.exists() and path.stat().st_size > 0:
            return path
    return None


def normalize(obj, ctx: dict) -> dict:
    raw = obj if isinstance(obj, dict) else {"value": obj}
    url = str(raw.get("data") or raw.get("url") or raw.get("poc") or "")
    return {
        "tool": "dalfox",
        "target": ctx.get("target", ""),
        "url": url,
        "host": ctx.get("target_host", ""),
        "finding_type": "xss_candidate",
        "severity": "medium",
        "confidence": 0.5,
        "evidence": raw,
        "raw": raw,
        "timestamp": now_iso(),
        "run_id": ctx.get("run_id", ""),
        "scope_status": "unknown",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run dalfox safely and normalize output")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--urls", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ctx = load_context(args.context)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_path = output.with_suffix(".raw.json")
    records: list[dict] = []
    urls = find_urls(ctx, args.urls)
    if urls and shutil.which("dalfox"):
        cmd = ["dalfox", "file", str(urls), "--only-poc", "--format", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        raw_path.write_text(result.stdout + result.stderr, encoding="utf-8")
        payload = result.stdout.strip()
        if payload:
            try:
                parsed = json.loads(payload)
                items = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                items = [line for line in payload.splitlines() if line.strip()]
            records = [normalize(item, ctx) for item in items]
    with output.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
