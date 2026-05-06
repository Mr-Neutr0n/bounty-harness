#!/usr/bin/env python3
"""Extract JWT-looking tokens from text files and decode them safely."""

import argparse
import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]*")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64url_decode(part: str):
    padded = part + ("=" * ((4 - len(part) % 4) % 4))
    return json.loads(base64.urlsafe_b64decode(padded.encode()).decode())


def load_context(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def candidate_files(ctx: dict, explicit: str) -> list[Path]:
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit))
    outdir = Path(ctx.get("outdir", "."))
    paths.extend([
        outdir / "recon/scoped/parameterized_urls.txt",
        outdir / "urls/parameterized_urls.txt",
        outdir / "recon/urls/all_urls.txt",
        outdir / "recon/js/js_files.txt",
    ])
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        if path not in seen:
            unique.append(path)
            seen.add(path)
    return unique


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract JWTs from recon text files")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--input", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ctx = load_context(args.context)
    records: list[dict] = []
    seen: set[str] = set()
    for path in candidate_files(ctx, args.input):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in JWT_RE.finditer(text):
            token = match.group(0)
            if token in seen:
                continue
            seen.add(token)
            parts = token.split(".")
            raw: dict = {"source_file": str(path), "token_prefix": token[:24]}
            try:
                raw["header"] = b64url_decode(parts[0])
                raw["payload"] = b64url_decode(parts[1])
                confidence = 0.8
            except Exception as exc:
                raw["decode_error"] = str(exc)
                confidence = 0.2
            records.append({
                "tool": "jwt_token_extractor",
                "target": ctx.get("target", ""),
                "url": "",
                "host": ctx.get("target_host", ""),
                "finding_type": "jwt_token_observed",
                "severity": "info",
                "confidence": confidence,
                "evidence": raw,
                "raw": raw,
                "timestamp": now_iso(),
                "run_id": ctx.get("run_id", ""),
                "scope_status": "unknown",
            })
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
