#!/usr/bin/env python3
"""Scope Validator Helper — batch validate URLs against scope file.

Usage:
    scope_validator.py --urls-file urls.txt --scope-file scope.txt --output results.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_batch(urls_file: str, scope_file: str, output_path: str) -> dict:
    urls = [l.strip() for l in Path(urls_file).read_text().splitlines() if l.strip()]
    results = []
    for url in urls:
        # Simple check: run scope_manager.py validate
        import subprocess
        result = subprocess.run(
            [sys.executable, ".claude/skills/scope-manager/scripts/scope_manager.py",
             "validate", "--url", url, "--scope-file", scope_file],
            capture_output=True, text=True, timeout=10,
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            data = {"url": url, "allowed": False, "reason": "validation error"}
        results.append(data)

    allowed = [r for r in results if r.get("allowed")]
    blocked = [r for r in results if not r.get("allowed")]

    report = {
        "validated_at": now_iso(),
        "total": len(results),
        "allowed": len(allowed),
        "blocked": len(blocked),
        "results": results,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description="Scope Validator Helper")
    parser.add_argument("--urls-file", required=True, help="File with URLs to validate")
    parser.add_argument("--scope-file", required=True, help="Scope file path")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()
    result = validate_batch(args.urls_file, args.scope_file, args.output)
    print(json.dumps({"allowed": result["allowed"], "blocked": result["blocked"], "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
