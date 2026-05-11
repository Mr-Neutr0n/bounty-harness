#!/usr/bin/env python3
"""Scope Manager — structured scope definition, validation, versioning, and guardrails.

Usage:
    scope_manager.py init --target example.com --scope-file scope.txt [--wildcards] [--out-of-scope oos.txt]
    scope_manager.py validate --url https://api.example.com/v1/users --scope-file scope.txt
    scope_manager.py diff --old-scope old.txt --new-scope new.txt
    scope_manager.py guard --request-file request.txt --scope-file scope.txt
    scope_manager.py track --scope-file scope.txt --program myprogram
    scope_manager.py check-changes --program myprogram
    scope_manager.py export --program myprogram --format json
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def parse_scope_file(path: str) -> Dict[str, Any]:
    """Parse a scope file into structured data."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    scope = {
        "in_scope": [],
        "out_of_scope": [],
        "wildcards": [],
        "ips": [],
        "mobile_apps": [],
        "apis": [],
        "comments": [],
    }
    current_section = "in_scope"
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if stripped.startswith("#"):
                scope["comments"].append(stripped[1:].strip())
            continue
        lower = stripped.lower()
        if lower.startswith("out of scope") or lower.startswith("excluded"):
            current_section = "out_of_scope"
            continue
        if lower.startswith("in scope") or lower.startswith("included"):
            current_section = "in_scope"
            continue
        if lower.startswith("wildcards"):
            current_section = "wildcards"
            continue
        if lower.startswith("mobile"):
            current_section = "mobile_apps"
            continue
        if lower.startswith("api"):
            current_section = "apis"
            continue
        if lower.startswith("ip"):
            current_section = "ips"
            continue
        scope[current_section].append(stripped)
    return scope


def compile_patterns(scope_items: List[str]) -> List[re.Pattern]:
    """Convert scope items (wildcards, domains, IPs) to regex patterns."""
    patterns = []
    for item in scope_items:
        item = item.strip()
        if not item:
            continue
        # Handle wildcard domains like *.example.com
        if item.startswith("*."):
            domain = re.escape(item[2:])
            patterns.append(re.compile(rf"(^|\.){domain}$", re.I))
        # Handle plain domains
        elif "." in item and not "/" in item:
            domain = re.escape(item)
            patterns.append(re.compile(rf"^{domain}$", re.I))
            patterns.append(re.compile(rf"^[^/]+\." + domain + r"$", re.I))
        # Handle URLs with paths
        elif "/" in item:
            patterns.append(re.compile(rf"^{re.escape(item)}"))
        # Handle IP addresses / CIDR (simplified)
        else:
            patterns.append(re.compile(rf"^{re.escape(item)}"))
    return patterns


def is_in_scope(url: str, scope_file: str) -> tuple[bool, str]:
    """Check if a URL is within scope. Returns (is_valid, reason)."""
    scope = parse_scope_file(scope_file)
    in_scope_patterns = compile_patterns(scope["in_scope"] + scope["wildcards"])
    out_scope_patterns = compile_patterns(scope["out_of_scope"])

    # Extract hostname from URL
    hostname = url
    if "://" in url:
        hostname = url.split("://", 1)[1].split("/")[0]
    # Remove port
    hostname = hostname.split(":")[0]

    # Check out-of-scope first (explicit exclusions take priority)
    for pat in out_scope_patterns:
        if pat.search(hostname) or pat.search(url):
            return False, f"Explicitly out of scope: matches pattern '{pat.pattern}'"

    # Check in-scope
    for pat in in_scope_patterns:
        if pat.search(hostname) or pat.search(url):
            return True, f"Matches in-scope pattern '{pat.pattern}'"

    return False, "No matching in-scope pattern found"


def init_scope(target: str, scope_file: str, wildcards: bool, out_of_scope_file: Optional[str]) -> Dict[str, Any]:
    """Generate a default scope file for a target."""
    lines = [f"# Scope for {target}", f"# Generated: {now_iso()}", ""]
    lines.append("# In Scope")
    lines.append(f"{target}")
    if wildcards:
        lines.append(f"*.{target}")
    lines.append("")
    lines.append("# APIs")
    lines.append(f"api.{target}")
    lines.append(f"*api*.{target}")
    lines.append("")
    lines.append("# Mobile Apps")
    lines.append("# iOS: com.example.app")
    lines.append("# Android: com.example.app")
    lines.append("")

    if out_of_scope_file and Path(out_of_scope_file).exists():
        lines.append("# Out of Scope")
        oos_lines = Path(out_of_scope_file).read_text().splitlines()
        for line in oos_lines:
            lines.append(line.strip())
        lines.append("")

    lines.append("# Notes")
    lines.append("# - Do not test production payment flows")
    lines.append("# - Do not brute-force authentication endpoints")
    lines.append("# - Rate limit all automated requests")

    content = "\n".join(lines)
    Path(scope_file).parent.mkdir(parents=True, exist_ok=True)
    Path(scope_file).write_text(content, encoding="utf-8")
    log(f"Scope file created: {scope_file}")
    return {"status": "created", "file": scope_file, "target": target}


def diff_scopes(old_file: str, new_file: str) -> Dict[str, Any]:
    """Compare two scope files and show differences."""
    old_scope = parse_scope_file(old_file)
    new_scope = parse_scope_file(new_file)

    def setdiff(a: List[str], b: List[str]) -> List[str]:
        return list(set(b) - set(a))

    added = {
        "in_scope": setdiff(old_scope["in_scope"], new_scope["in_scope"]),
        "out_of_scope": setdiff(old_scope["out_of_scope"], new_scope["out_of_scope"]),
        "wildcards": setdiff(old_scope["wildcards"], new_scope["wildcards"]),
    }
    removed = {
        "in_scope": setdiff(new_scope["in_scope"], old_scope["in_scope"]),
        "out_of_scope": setdiff(new_scope["out_of_scope"], old_scope["out_of_scope"]),
        "wildcards": setdiff(new_scope["wildcards"], old_scope["wildcards"]),
    }

    result = {
        "compared_at": now_iso(),
        "old_file": old_file,
        "new_file": new_file,
        "added": added,
        "removed": removed,
        "has_changes": any(added.values()) or any(removed.values()),
    }
    return result


def track_scope(scope_file: str, program: str, db_path: str = ".bb/scope_history.jsonl") -> Dict[str, Any]:
    """Record a snapshot of the current scope file."""
    content = Path(scope_file).read_text(encoding="utf-8")
    snapshot = {
        "timestamp": now_iso(),
        "program": program,
        "file": scope_file,
        "hash": hashlib.sha256(content.encode()).hexdigest()[:16],
        "content": content,
    }
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with open(db_path, "a") as f:
        f.write(json.dumps(snapshot) + "\n")
    log(f"Scope snapshot saved for {program}")
    return {"status": "tracked", "program": program, "hash": snapshot["hash"]}


def check_changes(program: str, db_path: str = ".bb/scope_history.jsonl") -> Dict[str, Any]:
    """Check if scope has changed since last snapshot."""
    if not Path(db_path).exists():
        return {"status": "no_history", "program": program}

    entries = []
    with open(db_path, "r") as f:
        for line in f:
            entry = json.loads(line.strip())
            if entry.get("program") == program:
                entries.append(entry)

    if len(entries) < 2:
        return {"status": "insufficient_history", "program": program, "snapshots": len(entries)}

    # Compare last two snapshots
    latest = entries[-1]
    previous = entries[-2]

    old_file = f"/tmp/scope_old_{program}.txt"
    new_file = f"/tmp/scope_new_{program}.txt"
    Path(old_file).write_text(previous["content"], encoding="utf-8")
    Path(new_file).write_text(latest["content"], encoding="utf-8")

    diff = diff_scopes(old_file, new_file)
    diff["program"] = program
    diff["snapshots"] = len(entries)
    return diff


def guard_request(request_file: str, scope_file: str) -> Dict[str, Any]:
    """Check if an HTTP request is in scope before sending."""
    lines = Path(request_file).read_text(encoding="utf-8").splitlines()
    if not lines:
        return {"allowed": False, "reason": "Empty request file"}

    # Parse request line: GET /path HTTP/1.1
    req_line = lines[0]
    # Find Host header
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    if not host:
        return {"allowed": False, "reason": "No Host header found"}

    # Reconstruct URL (assume https if not specified)
    url = f"https://{host}"
    if len(req_line.split()) >= 2:
        path = req_line.split()[1]
        if path.startswith("http"):
            url = path
        else:
            url = f"https://{host}{path}"

    allowed, reason = is_in_scope(url, scope_file)
    return {
        "allowed": allowed,
        "url": url,
        "reason": reason,
        "checked_at": now_iso(),
    }


def export_scope(program: str, fmt: str, db_path: str = ".bb/scope_history.jsonl") -> Dict[str, Any]:
    """Export the latest scope for a program."""
    if not Path(db_path).exists():
        return {"status": "not_found", "program": program}

    entries = []
    with open(db_path, "r") as f:
        for line in f:
            entry = json.loads(line.strip())
            if entry.get("program") == program:
                entries.append(entry)

    if not entries:
        return {"status": "not_found", "program": program}

    latest = entries[-1]
    if fmt == "json":
        scope = parse_scope_file(latest["file"])
        scope["meta"] = {
            "program": program,
            "exported_at": now_iso(),
            "snapshot_hash": latest["hash"],
        }
        return scope
    elif fmt == "text":
        return {"content": latest["content"]}
    else:
        return {"status": "error", "reason": f"Unknown format: {fmt}"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Scope Manager")
    sub = parser.add_subparsers(dest="command", help="Commands")

    p_init = sub.add_parser("init", help="Initialize scope file")
    p_init.add_argument("--target", required=True, help="Target domain")
    p_init.add_argument("--scope-file", required=True, help="Path to write scope file")
    p_init.add_argument("--wildcards", action="store_true", help="Include *.target wildcard")
    p_init.add_argument("--out-of-scope", help="File with out-of-scope items")

    p_val = sub.add_parser("validate", help="Validate URL against scope")
    p_val.add_argument("--url", required=True, help="URL to check")
    p_val.add_argument("--scope-file", required=True, help="Scope file path")

    p_diff = sub.add_parser("diff", help="Diff two scope files")
    p_diff.add_argument("--old-scope", required=True, help="Old scope file")
    p_diff.add_argument("--new-scope", required=True, help="New scope file")

    p_guard = sub.add_parser("guard", help="Guard request against scope")
    p_guard.add_argument("--request-file", required=True, help="HTTP request file")
    p_guard.add_argument("--scope-file", required=True, help="Scope file path")

    p_track = sub.add_parser("track", help="Track scope snapshot")
    p_track.add_argument("--scope-file", required=True, help="Scope file path")
    p_track.add_argument("--program", required=True, help="Program name")

    p_check = sub.add_parser("check-changes", help="Check scope changes")
    p_check.add_argument("--program", required=True, help="Program name")

    p_export = sub.add_parser("export", help="Export latest scope")
    p_export.add_argument("--program", required=True, help="Program name")
    p_export.add_argument("--format", default="json", choices=["json", "text"], help="Export format")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "init":
        result = init_scope(args.target, args.scope_file, args.wildcards, args.out_of_scope)
        print(json.dumps(result, indent=2))

    elif args.command == "validate":
        allowed, reason = is_in_scope(args.url, args.scope_file)
        print(json.dumps({"url": args.url, "allowed": allowed, "reason": reason}, indent=2))
        sys.exit(0 if allowed else 1)

    elif args.command == "diff":
        result = diff_scopes(args.old_scope, args.new_scope)
        print(json.dumps(result, indent=2))

    elif args.command == "guard":
        result = guard_request(args.request_file, args.scope_file)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["allowed"] else 1)

    elif args.command == "track":
        result = track_scope(args.scope_file, args.program)
        print(json.dumps(result, indent=2))

    elif args.command == "check-changes":
        result = check_changes(args.program)
        print(json.dumps(result, indent=2))

    elif args.command == "export":
        result = export_scope(args.program, args.format)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
