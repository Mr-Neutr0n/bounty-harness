#!/usr/bin/env python3
"""Live host discovery — httpx probe, screenshot, produce live host lists.

Usage:
    live_discovery.py --subs-file subs.txt --context output/example
    live_discovery.py --subs-file subs.txt --context output/example --screenshot --dry-run
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, cmd)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def cmd_exists(name: str) -> bool:
    return which(name) is not None


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def run(cmd: list[str], timeout: int = 300, dry_run: bool = False) -> tuple[int, str, str]:
    if dry_run:
        log(f"DRY-RUN: {' '.join(cmd)}")
        return 0, "", ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def probe_httpx(subs_file: Path, ctx: Path, dry: bool, rate_limit: int = 50) -> tuple[Path, list[dict]]:
    csv_path = ctx / "live_full.csv"
    txt_path = ctx / "live_hosts.txt"

    if not cmd_exists("httpx"):
        log("httpx not installed; writing empty outputs")
        csv_path.write_text("", encoding="utf-8")
        txt_path.write_text("", encoding="utf-8")
        return csv_path, []

    cmd = [
        "httpx", "-l", str(subs_file),
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-location",
        "-web-server",
        "-rate-limit", str(rate_limit),
        "-csv",
        "-o", str(csv_path),
    ]
    rc, out, err = run(cmd, timeout=600, dry_run=dry)
    if rc != 0 and not dry:
        log(f"httpx failed: {err.strip()}")
        return csv_path, []
    if dry:
        log("httpx dry-run skipped")
        return csv_path, []

    entries: list[dict] = []
    live_urls: list[str] = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
                url = row.get("url") or row.get("host") or row.get("input")
                if url:
                    live_urls.append(url.strip())
    except Exception as e:
        log(f"Error reading CSV: {e}")
        return csv_path, []

    txt_path.write_text("\n".join(live_urls) + "\n", encoding="utf-8")
    log(f"Probe complete: {len(live_urls)} live hosts → {txt_path}")
    return csv_path, entries


def take_screenshots(subs_file: Path, ctx: Path, dry: bool) -> Path:
    ss_dir = ctx / "screenshots"
    if not cmd_exists("httpx"):
        log("httpx not available for screenshots")
        return ss_dir

    ss_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "httpx", "-l", str(subs_file),
        "-silent",
        "-screenshot",
        "-ss-path", str(ss_dir),
    ]
    rc, out, err = run(cmd, timeout=900, dry_run=dry)
    if rc != 0 and not dry:
        log(f"Screenshot error: {err.strip()}")
    else:
        pngs = sorted(ss_dir.glob("*.png"))
        log(f"Screenshots: {len(pngs)} saved → {ss_dir}")
    return ss_dir


def csv_to_jsonl(csv_path: Path, ctx: Path, run_id: str) -> Path:
    jl_path = ctx / "findings.jsonl"
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            with open(jl_path, "w", encoding="utf-8") as out:
                for row in reader:
                    record = {
                        "url": row.get("url", ""),
                        "status_code": row.get("status_code", ""),
                        "title": row.get("title", ""),
                        "tech": (row.get("tech") or "").split(",") if row.get("tech") else [],
                        "content_length": row.get("content_length", ""),
                        "webserver": row.get("webserver", ""),
                        "location": row.get("location", ""),
                        "timestamp": now_iso(),
                        "run_id": run_id,
                    }
                    out.write(json.dumps(record) + "\n")
    except Exception as e:
        log(f"CSV→JSONL error: {e}")
    return jl_path


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Live host discovery via httpx — probe, screenshot, export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  live_hosts.txt     Live URLs (one per line)
  live_full.csv      httpx CSV with all metadata
  findings.jsonl     JSON lines with per-host metadata
  screenshots/       PNG screenshots (if --screenshot)
""",
    )
    p.add_argument("--subs-file", "-s", required=True, help="File with subdomains (one per line)")
    p.add_argument("--context", "-c", default=".", help="Output directory (default: .)")
    p.add_argument("--screenshot", action="store_true", help="Take screenshots of live hosts")
    p.add_argument("--rate-limit", type=int, default=int(os.environ.get("RATE_LIMIT", "50")), help="Requests per second (default: $RATE_LIMIT or 50)")
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    subs_file = Path(args.subs_file).resolve()
    if not subs_file.exists():
        log(f"Subs file not found: {subs_file}")
        sys.exit(1)

    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)
    dry = args.dry_run

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_ts = now_iso()

    log(f"Subs file: {subs_file}  Context: {ctx}  Screenshot: {args.screenshot}  Rate limit: {args.rate_limit}/s  Dry: {dry}")

    csv_path, entries = probe_httpx(subs_file, ctx, dry, args.rate_limit)

    ss_dir: Optional[Path] = None
    if args.screenshot:
        ss_dir = take_screenshots(subs_file, ctx, dry)

    jl_path = csv_to_jsonl(csv_path, ctx, run_id)

    metadata = {
        "run_id": run_id,
        "subs_file": str(subs_file),
        "started": start_ts,
        "completed": now_iso(),
        "live_count": len(entries),
        "screenshots_dir": str(ss_dir) if ss_dir else None,
        "files": {
            "csv": str(csv_path),
            "txt": str(ctx / "live_hosts.txt"),
            "jsonl": str(jl_path),
        },
    }

    meta_path = ctx / "live_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    log(f"Metadata → {meta_path}")

    print(json.dumps({"live_hosts": metadata["live_count"], "context": str(ctx)}))


if __name__ == "__main__":
    main()