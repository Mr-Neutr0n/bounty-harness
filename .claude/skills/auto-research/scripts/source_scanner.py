#!/usr/bin/env python3
"""
source_scanner.py — Checks all sources for new content since last check.

Uses a file-based cache (JSON) to track last-seen commithash / release tag /
last-modified header for each source. Compares current state to cached state
and outputs the list of sources that have changed.

Does NOT download any content — only compares identifiers.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_yaml_sources(path):
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_cache(cache_dir):
    cache_path = Path(cache_dir) / "source_state.json"
    if cache_path.exists():
        with open(cache_path, "r") as f:
            return json.load(f)
    return {
        "last_full_scan": None,
        "sources": {}
    }


def save_cache(cache_dir, data):
    cache_path = Path(cache_dir) / "source_state.json"
    data["last_full_scan"] = datetime.now(timezone.utc).isoformat()
    with open(cache_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def get_current_state(feed):
    feed_type = feed.get("type", "unknown")
    url = feed["url"]
    feed_id = feed["id"]

    if feed_type == "github_repo":
        branch = feed.get("branch", "HEAD")
        cmd = ["git", "ls-remote", url, f"refs/heads/{branch}"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split()[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    elif feed_type == "github_release":
        repo_path = url.replace("https://github.com/", "").rstrip("/")
        cmd = ["gh", "release", "list", "--repo", repo_path, "--limit", "1", "--json", "tagName", "-q", ".[0].tagName"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    elif feed_type == "git_repo":
        cmd = ["git", "ls-remote", url, "HEAD"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split()[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    elif feed_type in ("json_url", "web_page"):
        cmd = ["curl", "-sI", "--max-time", "15", url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.lower().startswith("last-modified:"):
                        return line.split(":", 1)[1].strip()
                    if line.lower().startswith("etag:"):
                        return line.split(":", 1)[1].strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    return None


def normalize_state(state):
    if state is None:
        return None
    return state.strip()[:200]


def scan_sources(sources_path, cache_dir):
    config = load_yaml_sources(sources_path)
    cache = load_cache(cache_dir)
    feeds = config.get("feeds", [])

    changed = []
    unchanged = []
    errors = []
    current_states = {}

    old_sources = cache.get("sources", {})

    for feed in feeds:
        feed_id = feed["id"]
        feed_type = feed.get("type", "unknown")

        try:
            current = get_current_state(feed)
            current_normalized = normalize_state(current)

            if current_normalized is None:
                errors.append({
                    "id": feed_id,
                    "reason": "could_not_fetch_state",
                    "type": feed_type
                })
                continue

            current_states[feed_id] = {
                "state": current_normalized,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "type": feed_type
            }

            previous = old_sources.get(feed_id, {}).get("state")

            if previous is None:
                changed.append({
                    "id": feed_id,
                    "reason": "first_check",
                    "current_state": current_normalized,
                    "type": feed_type,
                    "priority": feed.get("priority", "medium")
                })
            elif previous != current_normalized:
                changed.append({
                    "id": feed_id,
                    "reason": "state_changed",
                    "previous_state": previous,
                    "current_state": current_normalized,
                    "type": feed_type,
                    "priority": feed.get("priority", "medium")
                })
            else:
                unchanged.append({
                    "id": feed_id,
                    "current_state": current_normalized,
                    "type": feed_type
                })

        except Exception as exc:
            errors.append({
                "id": feed_id,
                "reason": str(exc),
                "type": feed_type
            })

    for feed_id, state_info in current_states.items():
        cache["sources"][feed_id] = state_info

    save_cache(cache_dir, cache)

    result = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_sources": len(feeds),
        "changed": changed,
        "unchanged": len(unchanged),
        "errors": errors,
        "changed_count": len(changed)
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Scan security knowledge sources for new content since last check"
    )
    parser.add_argument(
        "--sources",
        required=True,
        help="Path to sources.yaml"
    )
    parser.add_argument(
        "--cache-dir",
        required=True,
        help="Directory for cache files"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to write JSON output (default: stdout)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.sources):
        print(f"ERROR: sources file not found: {args.sources}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.cache_dir, exist_ok=True)

    result = scan_sources(args.sources, args.cache_dir)

    output = json.dumps(result, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
            f.write("\n")
        print(f"Results written to {args.output}")
        print(f"Changed: {result['changed_count']}/{result['total_sources']} sources")
        for c in result["changed"]:
            print(f"  CHANGED [{c['priority']}] {c['id']}: {c['reason']}")
    else:
        print(output)

    if result["errors"]:
        for e in result["errors"]:
            print(f"  ERROR {e['id']}: {e['reason']}", file=sys.stderr)

    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())