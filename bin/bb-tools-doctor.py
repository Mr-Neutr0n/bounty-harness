#!/usr/bin/env python3
"""bb-tools-doctor.py — core doctor logic, called by bin/bb-tools.

Env vars:
  DOCTOR_TOOLS_FILE  — path to temp file with newline-separated tool names
  DOCTOR_JSON        — "true" or "false"
  DOCTOR_FILTER_TYPE — "all", "skill", "workflow", or "profile"
  DOCTOR_FILTER_VALUE  — string value (skill name, profile name, etc.)
  DOCTOR_FILTER_VALUE2 — second value (workflow name, for workflow filter)

Reads registry JSON from stdin, outputs text or JSON to stdout.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone


def _version(text: str) -> str:
    """Select the most likely version line from tool output."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    hits = [line for line in lines if "version" in line.lower() or "current" in line.lower()]
    return (hits or lines or ["unknown"])[0]


def get_tool_version(binary: str, vcmd: str) -> str:
    """Return version string for an installed tool, or 'unknown'."""
    if vcmd:
        try:
            r = subprocess.run(vcmd, shell=True, capture_output=True, text=True, timeout=5)
            combined = (r.stdout or "") + (r.stderr or "")
            return _version(combined)
        except Exception:
            pass
    for flag in ("--version", "-version", "-V", "version"):
        try:
            r = subprocess.run([binary, flag], capture_output=True, text=True, timeout=5)
            combined = (r.stdout or "") + (r.stderr or "")
            v = _version(combined)
            if v and v != "unknown":
                return v
        except Exception:
            pass
    return "unknown"


def run():
    tools_file = os.environ.get("DOCTOR_TOOLS_FILE", "")
    json_out = os.environ.get("DOCTOR_JSON", "false") == "true"
    filter_type = os.environ.get("DOCTOR_FILTER_TYPE", "all")
    filter_val = os.environ.get("DOCTOR_FILTER_VALUE", "")
    filter_val2 = os.environ.get("DOCTOR_FILTER_VALUE2", "")

    registry = json.load(sys.stdin)

    tool_names = []
    if tools_file and os.path.isfile(tools_file):
        with open(tools_file) as f:
            tool_names = [line.strip() for line in f if line.strip()]

    if not tool_names:
        tool_names = sorted(registry.keys())

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    filter_display_val = filter_val
    if filter_type == "workflow" and filter_val2:
        filter_display_val = f"{filter_val}/{filter_val2}"

    results = []
    ok_count = 0
    missing_count = 0
    unhealthy_count = 0

    for name in tool_names:
        if not name:
            continue
        info = registry.get(name, {})
        binary = info.get("binary", name)
        method = info.get("install_method", "unknown")
        if method == "pipx":
            method = "pip"
        vcmd = info.get("version_cmd", "")
        installed = shutil.which(binary) is not None
        version = ""
        health = "ok"

        if installed:
            version = get_tool_version(binary, vcmd)
        else:
            if method == "system":
                health = "system_missing"
            else:
                health = "missing"

        if health == "ok":
            ok_count += 1
        elif health == "missing":
            missing_count += 1
        else:
            unhealthy_count += 1

        entry = {
            "name": name,
            "binary": binary,
            "method": method,
            "installed": installed,
            "version": version,
            "health": health,
        }
        if not installed and method not in ("system", "manual"):
            entry["fix"] = f"bin/bb-tools install {name}"
        results.append(entry)

    if json_out:
        output = {
            "timestamp": ts,
            "filter": {
                "type": filter_type,
                "value": filter_display_val,
            },
            "tools": results,
            "summary": {
                "total": len(results),
                "ok": ok_count,
                "missing": missing_count,
                "unhealthy": unhealthy_count,
            },
        }
        print(json.dumps(output, indent=2))
    else:
        col_fmt = "{:22s}  {:10s}  {:7s}  {}"
        print(col_fmt.format("Tool", "Method", "Status", "Version/Info"))
        has_missing = False
        for r in results:
            s = r["health"].upper()
            info_col = r.get("version", "") if r["installed"] else f'run: bin/bb-tools install {r["name"]}'
            print(col_fmt.format(r["name"], r["method"], s, info_col))
            if r["health"] != "ok":
                has_missing = True

        if has_missing:
            print()
            print("Some tools are missing or unhealthy.")
            sys.exit(1)
        print()
        print("All checked tools are healthy.")


if __name__ == "__main__":
    run()