#!/usr/bin/env python3
"""
fetch_writeup_indexes.py — Clone/fetch GitHub repos referenced in sources.yaml,
extract bug type indexes, report URLs, titles, and programs.

Input:  sources.yaml (YAML config)
Output: raw/ directory with fetched indexes + _fetched_summary.json
"""

import argparse
import json
import sys
import os
import pathlib
import hashlib
import subprocess
import re
from datetime import datetime

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


GIT_CLONE_TIMEOUT = 120


def load_sources(yaml_path: pathlib.Path) -> list[dict]:
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("sources", [])


def clone_or_pull(repo_full: str, dest_dir: pathlib.Path) -> bool:
    """Clone a GitHub repo or pull if it already exists."""
    if (dest_dir / ".git").is_dir():
        print(f"    Repo already exists, pulling: {repo_full}", file=sys.stderr)
        result = subprocess.run(
            ["git", "-C", str(dest_dir), "pull", "--ff-only", "--depth=1"],
            capture_output=True, text=True, timeout=GIT_CLONE_TIMEOUT,
        )
        if result.returncode != 0:
            print(f"    Warning: git pull failed: {result.stderr.strip()[:200]}", file=sys.stderr)
            return False
        return True
    else:
        url = f"https://github.com/{repo_full}.git"
        print(f"    Cloning: {url}", file=sys.stderr)
        result = subprocess.run(
            ["git", "clone", "--depth=1", url, str(dest_dir)],
            capture_output=True, text=True, timeout=GIT_CLONE_TIMEOUT,
        )
        if result.returncode != 0:
            print(f"    Error: clone failed: {result.stderr.strip()[:300]}", file=sys.stderr)
            return False
        return True


def extract_h1_report_links(content: str, repo_name: str) -> list[dict]:
    """Extract HackerOne report URLs and metadata from content."""
    results = []

    h1_url_pattern = re.compile(
        r"https?://hackerone\.com/reports/(\d+)"
    )

    md_link_pattern = re.compile(
        r"\[([^\]]+)\]\((https?://hackerone\.com/reports/\d+)\)"
    )

    program_hints = []

    for match in md_link_pattern.finditer(content):
        title = match.group(1).strip()
        url = match.group(2)
        report_id = match.group(2).split("/")[-1]

        program = "unknown"
        for line in content.split("\n")[:30]:
            pgm = re.search(r"Program:?\s*(.+?)(?:[-–]\s*Report|\n|$)", line, re.IGNORECASE)
            if pgm:
                program = pgm.group(1).strip().lower()
                break

        results.append({
            "source_repo": repo_name,
            "report_id": report_id,
            "url": url,
            "title": title,
            "program": program,
        })

    for match in h1_url_pattern.finditer(content):
        report_id = match.group(1)
        if not any(r["report_id"] == report_id for r in results):
            results.append({
                "source_repo": repo_name,
                "report_id": report_id,
                "url": f"https://hackerone.com/reports/{report_id}",
                "title": "",
                "program": "unknown",
            })

    return results


def process_github_source(source: dict, raw_dir: pathlib.Path) -> dict:
    """Process a GitHub source entry from sources.yaml."""
    repo = source["repo"]
    name = source["name"]
    repo_dir = raw_dir / name.replace(" ", "-").lower()

    print(f"  Processing GitHub source: {repo} -> {repo_dir}", file=sys.stderr)

    if not clone_or_pull(repo, repo_dir):
        return {"name": name, "type": "github", "repo": repo, "status": "failed", "entries": 0}

    all_refs: list[dict] = []

    if "files" in source:
        for file_path in source["files"]:
            full_path = repo_dir / file_path
            if full_path.is_file():
                print(f"    Reading: {file_path}", file=sys.stderr)
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                if full_path.suffix == ".csv":
                    parsed = parse_index_csv(content, name)
                elif full_path.suffix == ".md":
                    parsed = extract_h1_report_links(content, name)
                else:
                    parsed = extract_h1_report_links(content, name)

                all_refs.extend(parsed)
                print(f"      -> {len(parsed)} entries", file=sys.stderr)
            else:
                print(f"    Warning: file not found: {file_path}", file=sys.stderr)

    if not all_refs and "files" not in source:
        for md_file in sorted(repo_dir.glob("**/*.md")):
            with open(md_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            parsed = extract_h1_report_links(content, name)
            if parsed:
                all_refs.extend(parsed)

    out_file = raw_dir / f"{name.replace(' ', '-').lower()}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_refs, f, indent=2, ensure_ascii=False)

    return {
        "name": name,
        "type": "github",
        "repo": repo,
        "status": "ok",
        "entries": len(all_refs),
        "output_file": str(out_file.name),
    }


def process_web_source(source: dict) -> dict:
    """Process a web source entry from sources.yaml."""
    name = source["name"]
    urls = source.get("urls", [])

    if source.get("url"):
        urls = [source["url"]] + urls

    print(f"  Processing web source: {name} ({len(urls)} URL(s))", file=sys.stderr)

    return {
        "name": name,
        "type": "web",
        "urls_count": len(urls),
        "status": "ok",
        "note": "Web sources not fetched automatically; add manually or use webfetch.",
        "urls": urls,
    }


def process_source(source: dict, raw_dir: pathlib.Path) -> dict:
    """Dispatch processing based on source type."""
    s_type = source.get("type", "unknown")

    if s_type == "github":
        if source.get("fetch") is False:
            print(f"  Skipping {source['name']} (fetch: false)", file=sys.stderr)
            return {
                "name": source["name"],
                "type": "github",
                "repo": source["repo"],
                "status": "skipped",
                "entries": 0,
                "note": "fetch: false in sources.yaml",
            }
        return process_github_source(source, raw_dir)

    elif s_type == "web":
        return process_web_source(source)

    return {
        "name": source.get("name", "unknown"),
        "type": s_type,
        "status": f"unknown_type: {s_type}",
    }


def parse_index_csv(content: str, source_name: str) -> list[dict]:
    """Parse a simple CSV index of reports (report_id, title, program)."""
    results = []
    lines = content.strip().split("\n")
    if len(lines) < 2:
        return results

    header = lines[0].lower()
    cols = [c.strip() for c in header.split(",")]

    id_idx = next((i for i, c in enumerate(cols) if "report_id" in c or "report" in c or "id" in c), 0)
    title_idx = next((i for i, c in enumerate(cols) if "title" in c or "name" in c), 1)
    prog_idx = next((i for i, c in enumerate(cols) if "program" in c or "handle" in c or "company" in c), 2)

    for line in lines[1:]:
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < max(id_idx, title_idx, prog_idx) + 1:
            continue
        rid = parts[id_idx] if id_idx < len(parts) else ""
        title = parts[title_idx] if title_idx < len(parts) else ""
        prog = parts[prog_idx] if prog_idx < len(parts) else "unknown"

        url = rid if rid.startswith("http") else f"https://hackerone.com/reports/{rid}"

        results.append({
            "source_repo": source_name,
            "report_id": rid,
            "url": url,
            "title": title,
            "program": prog.lower(),
        })

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Clone/fetch bug bounty writeup indexes from sources.yaml"
    )
    parser.add_argument(
        "--sources",
        required=True,
        help="Path to sources.yaml configuration file",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Directory for raw output (default: raw/ next to sources.yaml)",
    )
    args = parser.parse_args()

    sources_file = pathlib.Path(args.sources)
    if not sources_file.is_file():
        print(f"Error: sources file '{sources_file}' not found", file=sys.stderr)
        sys.exit(1)

    if args.output:
        raw_dir = pathlib.Path(args.output)
    else:
        raw_dir = sources_file.parent / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading sources from: {sources_file}", file=sys.stderr)
    print(f"Raw output directory: {raw_dir}", file=sys.stderr)

    sources = load_sources(sources_file)
    print(f"Found {len(sources)} sources in YAML", file=sys.stderr)

    results: list[dict] = []
    total_entries = 0
    success_count = 0
    fail_count = 0

    for source in sources:
        name = source.get("name", "unnamed")
        print(f"\n--- Source: {name} [{source.get('type', 'unknown')}] ---", file=sys.stderr)
        try:
            result = process_source(source, raw_dir)
            results.append(result)

            if result.get("status") == "ok":
                success_count += 1
                total_entries += result.get("entries", 0)
            elif result.get("status") == "skipped":
                success_count += 1
            else:
                fail_count += 1

            print(f"  Result: {result.get('status', 'unknown')} ({result.get('entries', 0)} entries)", file=sys.stderr)
        except Exception as e:
            print(f"  Error processing source '{name}': {e}", file=sys.stderr)
            results.append({
                "name": name,
                "type": source.get("type", "unknown"),
                "status": "error",
                "error": str(e),
            })
            fail_count += 1

    summary = {
        "sources_file": str(sources_file),
        "total_sources": len(sources),
        "successful": success_count,
        "failed": fail_count,
        "total_entries_extracted": total_entries,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "per_source": results,
    }

    summary_path = raw_dir / "_fetched_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Summary: {success_count}/{len(sources)} sources ok, {total_entries} entries extracted", file=sys.stderr)
    print(f"Summary written to: {summary_path}", file=sys.stderr)

    listed = raw_dir.glob("*.json")
    for f in sorted(listed):
        if f.name == "_fetched_summary.json":
            continue
        print(f"  Output: {f.name} ({f.stat().st_size:,} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()