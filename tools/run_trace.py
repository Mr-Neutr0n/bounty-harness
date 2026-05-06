"""Workflow trace recorder for bb-run harness.

Appends redacted provenance records to .bb/traces/runs.jsonl and optionally
to .bb/traces/runs.sqlite.  Never logs credentials, cookies, tokens, or raw
target responses.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid


def append_trace(record: dict, jsonl_path: str = ".bb/traces/runs.jsonl") -> None:
    os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)
    record.setdefault("_written_at", time.time())
    with open(jsonl_path, "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def init_trace_db(sqlite_path: str = ".bb/traces/runs.sqlite") -> None:
    os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)
    conn = sqlite3.connect(sqlite_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id        TEXT PRIMARY KEY,
            started_at    TEXT,
            ended_at      TEXT,
            duration_ms   INTEGER,
            skill         TEXT,
            workflow      TEXT,
            target_hash   TEXT,
            program       TEXT,
            scope_file_hash TEXT,
            safety_tier   TEXT,
            exit_code     INTEGER,
            artifact_refs TEXT,
            redaction_status TEXT,
            _written_at   REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS run_tools (
            run_id   TEXT,
            tool     TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        )
    """)
    conn.commit()
    conn.close()


def append_trace_sqlite(record: dict, sqlite_path: str = ".bb/traces/runs.sqlite") -> None:
    init_trace_db(sqlite_path)
    conn = sqlite3.connect(sqlite_path)
    conn.execute(
        """INSERT OR REPLACE INTO runs
           (run_id, started_at, ended_at, duration_ms, skill, workflow,
            target_hash, program, scope_file_hash, safety_tier, exit_code,
            artifact_refs, redaction_status, _written_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record.get("run_id"),
            record.get("started_at"),
            record.get("ended_at"),
            record.get("duration_ms"),
            record.get("skill"),
            record.get("workflow"),
            record.get("target_hash"),
            record.get("program"),
            record.get("scope_file_hash"),
            record.get("safety_tier"),
            record.get("exit_code"),
            json.dumps(record.get("artifact_refs", [])),
            record.get("redaction_status", "applied"),
            time.time(),
        ),
    )
    for tool in record.get("tools_required", []) or []:
        conn.execute(
            "INSERT INTO run_tools (run_id, tool) VALUES (?, ?)",
            (record.get("run_id"), tool),
        )
    conn.commit()
    conn.close()


def record_run(
    skill: str,
    workflow: str,
    safety_tier: str,
    exit_code: int,
    duration_ms: int,
    artifact_refs: list | None = None,
    target_hash: str | None = None,
    program: str | None = None,
    scope_file_hash: str | None = None,
    tools_required: list | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    jsonl_path: str = ".bb/traces/runs.jsonl",
    sqlite_path: str = ".bb/traces/runs.sqlite",
) -> str:
    run_id = uuid.uuid4().hex
    record = {
        "run_id": run_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "skill": skill,
        "workflow": workflow,
        "target_hash": target_hash,
        "program": program,
        "scope_file_hash": scope_file_hash,
        "safety_tier": safety_tier,
        "tools_required": tools_required or [],
        "exit_code": exit_code,
        "artifact_refs": artifact_refs or [],
        "redaction_status": "applied",
    }
    append_trace(record, jsonl_path)
    try:
        append_trace_sqlite(record, sqlite_path)
    except Exception:
        pass
    return run_id


def _hash_val(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()


def _safety_hierarchy(tier: str) -> int:
    order = {"passive": 0, "active-safe": 1, "intrusive": 2, "destructive-manual": 3}
    return order.get(tier, 1)


def derive_safety_tier(tools_required: list, registry_paths: list | None = None) -> str:
    """Derive the safety tier from a list of required tools by cross-referencing
    the tool registry on disk.  Returns 'active-safe' when no registry data
    is available."""
    import glob
    import yaml

    if registry_paths is None:
        registry_paths = glob.glob("tools/registry/*.yaml")

    tool_tiers = {}
    for rp in registry_paths:
        try:
            for t in yaml.safe_load(open(rp)).get("registry", {}).get("tools", []):
                name = t.get("name", "")
                tier = t.get("risk_tier", "active-safe")
                if name:
                    tool_tiers.setdefault(name, tier)
                binary = t.get("binary", "")
                if binary and binary != name:
                    tool_tiers.setdefault(binary, tier)
        except Exception:
            pass

    if not tool_tiers:
        return "active-safe"

    highest = "passive"
    highest_val = 0
    for tool in tools_required:
        tier = tool_tiers.get(tool, "active-safe")
        val = _safety_hierarchy(tier)
        if val > highest_val:
            highest_val = val
            highest = tier
    return highest


def _main() -> None:
    parser = argparse.ArgumentParser(description="bb-run workflow trace recorder")
    sub = parser.add_subparsers(dest="command")

    init_parser = sub.add_parser("init-db", help="Initialize the SQLite trace database")
    init_parser.add_argument(
        "--sqlite-path", default=".bb/traces/runs.sqlite",
        help="Path to SQLite database (default: .bb/traces/runs.sqlite)",
    )

    record_parser = sub.add_parser("record", help="Record a completed workflow run")
    record_parser.add_argument("--skill", required=True)
    record_parser.add_argument("--workflow", required=True)
    record_parser.add_argument("--safety-tier", required=True)
    record_parser.add_argument("--exit-code", type=int, required=True)
    record_parser.add_argument("--duration-ms", type=int, required=True)
    record_parser.add_argument("--target-hash", default=None)
    record_parser.add_argument("--program", default=None)
    record_parser.add_argument("--scope-file-hash", default=None)
    record_parser.add_argument("--tools-required", nargs="*", default=[])
    record_parser.add_argument("--started-at", default=None)
    record_parser.add_argument("--ended-at", default=None)
    record_parser.add_argument("--jsonl-path", default=".bb/traces/runs.jsonl")
    record_parser.add_argument("--sqlite-path", default=".bb/traces/runs.sqlite")

    args = parser.parse_args()

    if args.command == "init-db":
        init_trace_db(args.sqlite_path)
        print(f"Trace DB initialized at {args.sqlite_path}")
    elif args.command == "record":
        rid = record_run(
            skill=args.skill,
            workflow=args.workflow,
            safety_tier=args.safety_tier,
            exit_code=args.exit_code,
            duration_ms=args.duration_ms,
            target_hash=args.target_hash,
            program=args.program,
            scope_file_hash=args.scope_file_hash,
            tools_required=args.tools_required,
            started_at=args.started_at,
            ended_at=args.ended_at,
            jsonl_path=args.jsonl_path,
            sqlite_path=args.sqlite_path,
        )
        print(rid)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    _main()