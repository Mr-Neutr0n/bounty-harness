#!/usr/bin/env python3
"""Passive subdomain enumeration — subfinder + crt.sh + amass.

Usage:
    subdomain_enum.py --target example.com --context output/example
    subdomain_enum.py --target example.com --context output/example --dry-run
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    requests = None


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


def log_lines(title: str, lines: list[str]) -> None:
    log(f"{title} ({len(lines)} items)")


def run(cmd: list[str], timeout: int = 120, dry_run: bool = False) -> tuple[int, str, str]:
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

AMASS_TIMEOUT = int(os.environ.get("AMASS_TIMEOUT", "120"))


def enum_subfinder(target: str, dry_run: bool) -> tuple[list[str], dict]:
    entries: list[str] = []
    meta = {"tool": "subfinder", "count": 0, "error": None}
    if not cmd_exists("subfinder"):
        meta["error"] = "subfinder not installed"
        return entries, meta

    rc, out, err = run(["subfinder", "-d", target, "-all", "-silent"], timeout=180, dry_run=dry_run)
    if rc != 0:
        meta["error"] = err.strip() or f"exit code {rc}"
        return entries, meta

    entries = [line.strip().lower() for line in out.splitlines() if line.strip()]
    meta["count"] = len(entries)
    return entries, meta


def enum_crtsh(target: str, dry_run: bool) -> tuple[list[str], dict]:
    entries: list[str] = []
    meta = {"tool": "crt.sh", "count": 0, "error": None}

    if dry_run:
        log(f"DRY-RUN: GET https://crt.sh/?q=%.{target}&output=json")
        return entries, meta

    if requests is None:
        meta["error"] = "requests library not installed; pip3 install requests"
        return entries, meta

    url = f"https://crt.sh/?q=%.{target}&output=json"
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        data = resp.json()
        seen = set()
        for cert in data:
            name = (cert.get("name_value") or cert.get("common_name") or "").lower()
            for n in name.split("\n"):
                n = n.strip().replace("*.", "")
                if n and n not in seen and not n.startswith("*"):
                    seen.add(n)
                    entries.append(n)
    except Exception as e:
        meta["error"] = str(e)
        return entries, meta

    meta["count"] = len(entries)
    return entries, meta


def enum_amass(target: str, dry_run: bool) -> tuple[list[str], dict]:
    entries: list[str] = []
    meta = {"tool": "amass", "count": 0, "error": None}
    if not cmd_exists("amass"):
        meta["error"] = "amass not installed"
        return entries, meta

    rc, out, err = run(["amass", "enum", "-passive", "-d", target], timeout=AMASS_TIMEOUT, dry_run=dry_run)
    if rc != 0:
        meta["error"] = err.strip() or f"exit code {rc}"
        return entries, meta

    for line in out.splitlines():
        stripped = line.strip().lower()
        if stripped and not stripped.startswith("[") and not stripped.startswith("OWASP"):
            if "." in stripped and " " not in stripped:
                entries.append(stripped)
    meta["count"] = len(entries)
    return entries, meta


def dedup_and_merge(results: list[tuple[list[str], dict]]) -> tuple[set[str], dict]:
    all_subs: set[str] = set()
    sources: dict[str, list[str]] = {}
    for entries, meta in results:
        tool = meta["tool"]
        sources[tool] = entries
        all_subs.update(entries)
    return all_subs, sources


def write_lines(path: Path, lines: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Passive subdomain enumeration — subfinder + crt.sh + amass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  subs.txt            All unique subdomains (one per line)
  subs_metadata.json  Tool-wise sources, timestamps, errors
  findings.jsonl      Per-subdomain JSON lines with source attribution
""",
    )
    p.add_argument("--target", "-t", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("--context", "-c", default=".", help="Output directory for results (default: .)")
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    target = args.target.lower().strip()
    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)
    dry = args.dry_run

    log(f"Target: {target}  Context: {ctx}  Dry-run: {dry}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_ts = now_iso()

    results: list[tuple[list[str], dict]] = []
    subs_file = ctx / "subs.txt"
    meta_file = ctx / "subs_metadata.json"
    findings_file = ctx / "findings.jsonl"

    def _flush(all_subs: set[str], sources: dict[str, list[str]], partial: bool = False):
        write_lines(subs_file, all_subs)
        log(f"Wrote {subs_file}")
        metadata = {
            "target": target,
            "run_id": run_id,
            "started": start_ts,
            "completed": now_iso(),
            "total_unique": len(all_subs),
            "partial": partial,
            "sources": {
                tool: {
                    "count": len(entries),
                    "error": meta.get("error"),
                }
                for entries, meta in results
                for tool in [meta["tool"]]
            },
            "files": {
                "subs": str(subs_file),
                "metadata": str(meta_file),
                "findings": str(findings_file),
            },
        }
        write_json(meta_file, metadata)
        with open(findings_file, "w", encoding="utf-8") as fh:
            for sub in sorted(all_subs):
                sources_for_sub = [k for k, v in sources.items() if sub in v]
                record = {
                    "subdomain": sub,
                    "sources": sources_for_sub,
                    "timestamp": now_iso(),
                    "run_id": run_id,
                }
                fh.write(json.dumps(record) + "\n")
        log(f"Wrote {findings_file}")
        return metadata

    log("--- subfinder ---")
    results.append(enum_subfinder(target, dry))
    running_subs, running_sources = dedup_and_merge(results)
    log_lines("Subfinder + previous unique subdomains", sorted(running_subs))
    _flush(running_subs, running_sources, partial=True)

    log("--- crt.sh ---")
    results.append(enum_crtsh(target, dry))
    running_subs, running_sources = dedup_and_merge(results)
    log_lines("crt.sh + previous unique subdomains", sorted(running_subs))
    _flush(running_subs, running_sources, partial=True)

    log("--- amass ---")
    results.append(enum_amass(target, dry))
    all_subs, sources = dedup_and_merge(results)
    log_lines("Total unique subdomains", sorted(all_subs))

    metadata = _flush(all_subs, sources, partial=False)
    print(json.dumps(metadata["sources"]))


if __name__ == "__main__":
    main()