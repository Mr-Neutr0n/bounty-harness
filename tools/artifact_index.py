#!/usr/bin/env python3
"""Artifact registry — stable, deterministic, content-addressed artifact IDs for agent citation."""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    producer_run_id TEXT,
    skill TEXT,
    workflow TEXT,
    sensitivity TEXT DEFAULT 'public',
    summary TEXT,
    redacted_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_kind ON artifacts(kind);
CREATE INDEX IF NOT EXISTS idx_artifacts_skill ON artifacts(skill);
"""

URI_KINDS = {"run", "asset", "traffic", "finding", "evidence", "memory", "plan"}


def init_db(db_path=".bb/artifacts.sqlite"):
    db = Path(db_path)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def _shorthash(data):
    return hashlib.sha256(data.encode()).hexdigest()[:12]


def _file_hash(path):
    if not Path(path).exists():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _compute_artifact_id(kind, path=None, run_id=None, corpus_id=None,
                         request_id=None, program=None, fact_id=None,
                         plan_id=None, step_id=None, finding_id=None):
    if kind == "run":
        return f"bb://run/{run_id}" if run_id else None
    elif kind == "asset":
        raw = f"asset:{path or ''}"
        return f"bb://asset/{_shorthash(raw)}"
    elif kind == "traffic":
        cid = corpus_id or "unknown"
        rid = request_id or _shorthash(path or "")
        return f"bb://traffic/{cid}/{rid}"
    elif kind == "finding":
        raw = f"finding:{path or ''}"
        return f"bb://finding/{_shorthash(raw)}"
    elif kind == "evidence":
        fid = finding_id or "unknown"
        raw = f"evidence:{fid}:{path or ''}"
        return f"bb://evidence/{fid}/{_shorthash(raw)}"
    elif kind == "memory":
        prog = program or "unknown"
        fid = fact_id or _shorthash(path or "")
        return f"bb://memory/{prog}/{fid}"
    elif kind == "plan":
        pid = plan_id or "unknown"
        sid = step_id or "unknown"
        return f"bb://plan/{pid}/{sid}"
    return None


def register_artifact(kind, path, run_id=None, skill=None, workflow=None,
                      sensitivity="public", summary="", sha256=None,
                      db_path=".bb/artifacts.sqlite",
                      corpus_id=None, request_id=None,
                      program=None, fact_id=None,
                      plan_id=None, step_id=None, finding_id=None):
    if kind not in URI_KINDS:
        raise ValueError(f"Unknown artifact kind: {kind}")

    artifact_id = _compute_artifact_id(
        kind, path=path, run_id=run_id,
        corpus_id=corpus_id, request_id=request_id,
        program=program, fact_id=fact_id,
        plan_id=plan_id, step_id=step_id, finding_id=finding_id
    )
    file_hash = sha256 or _file_hash(path)
    created_at = datetime.now(timezone.utc).isoformat()
    redacted_path = path

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT OR REPLACE INTO artifacts (artifact_id, kind, path, sha256, created_at, producer_run_id, skill, workflow, sensitivity, summary, redacted_path) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (artifact_id, kind, path, file_hash, created_at, run_id, skill, workflow, sensitivity, summary, redacted_path)
    )
    conn.commit()
    conn.close()
    return artifact_id


def get_artifact(artifact_id, db_path=".bb/artifacts.sqlite"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def list_artifacts(kind=None, skill=None, limit=100, db_path=".bb/artifacts.sqlite"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM artifacts WHERE 1=1"
    params = []
    if kind:
        query += " AND kind = ?"
        params.append(kind)
    if skill:
        query += " AND skill = ?"
        params.append(skill)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def export_manifest(kind=None, output_path=".bb/artifacts.jsonl", db_path=".bb/artifacts.sqlite"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    query = "SELECT artifact_id, kind, path, sha256, created_at, skill, workflow, sensitivity, summary FROM artifacts WHERE 1=1"
    params = []
    if kind:
        query += " AND kind = ?"
        params.append(kind)
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for row in rows:
            f.write(json.dumps(dict(row)) + "\n")
    return len(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Artifact registry — stable, deterministic artifact IDs for agent citation"
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    p_init = sub.add_parser("init", help="Create the artifact registry database")
    p_init.add_argument("--db", default=".bb/artifacts.sqlite",
                       help="Path to artifact DB")

    p_register = sub.add_parser("register", help="Register an artifact")
    p_register.add_argument("--kind", required=True, choices=list(URI_KINDS),
                            help="Artifact kind (asset, traffic, finding, etc.)")
    p_register.add_argument("--path", default="", help="File path to the artifact")
    p_register.add_argument("--run-id", help="Producer run ID")
    p_register.add_argument("--corpus-id", help="Corpus ID (for traffic artifacts)")
    p_register.add_argument("--request-id", help="Request ID within a corpus (for traffic artifacts)")
    p_register.add_argument("--program", help="Program name (for memory artifacts)")
    p_register.add_argument("--fact-id", help="Fact ID (for memory artifacts)")
    p_register.add_argument("--plan-id", help="Plan ID (for plan artifacts)")
    p_register.add_argument("--step-id", help="Step ID within a plan (for plan artifacts)")
    p_register.add_argument("--finding-id", help="Finding ID (for evidence artifacts)")
    p_register.add_argument("--skill", help="Producing skill name")
    p_register.add_argument("--workflow", help="Producing workflow name")
    p_register.add_argument("--sensitivity", default="public",
                            help="Sensitivity level (default: public)")
    p_register.add_argument("--summary", default="", help="Short human-readable summary")
    p_register.add_argument("--sha256", help="Pre-computed SHA-256 hash")
    p_register.add_argument("--db", default=".bb/artifacts.sqlite",
                            help="Path to artifact DB")

    p_list = sub.add_parser("list", help="List registered artifacts")
    p_list.add_argument("--kind", choices=list(URI_KINDS), help="Filter by kind")
    p_list.add_argument("--skill", help="Filter by skill")
    p_list.add_argument("--limit", type=int, default=100, help="Max results (default: 100)")
    p_list.add_argument("--db", default=".bb/artifacts.sqlite",
                        help="Path to artifact DB")

    p_get = sub.add_parser("get", help="Look up an artifact by ID")
    p_get.add_argument("artifact_id", help="Artifact ID (e.g. bb://asset/abc123)")
    p_get.add_argument("--db", default=".bb/artifacts.sqlite",
                       help="Path to artifact DB")

    p_export = sub.add_parser("export", help="Export artifact manifest as JSONL")
    p_export.add_argument("--kind", choices=list(URI_KINDS), help="Filter by kind")
    p_export.add_argument("--output", default=".bb/artifacts.jsonl",
                          help="Output path (default: .bb/artifacts.jsonl)")
    p_export.add_argument("--db", default=".bb/artifacts.sqlite",
                          help="Path to artifact DB")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    db_path = getattr(args, "db", ".bb/artifacts.sqlite")

    if not Path(db_path).exists() and args.command != "init":
        init_db(db_path)

    if args.command == "init":
        init_db(db_path)
        print(json.dumps({"status": "initialized", "db": db_path}))

    elif args.command == "register":
        aid = register_artifact(
            kind=args.kind, path=args.path, run_id=args.run_id,
            corpus_id=args.corpus_id, request_id=args.request_id,
            program=args.program, fact_id=args.fact_id,
            plan_id=args.plan_id, step_id=args.step_id,
            finding_id=args.finding_id,
            skill=args.skill, workflow=args.workflow,
            sensitivity=args.sensitivity, summary=args.summary,
            sha256=args.sha256, db_path=args.db
        )
        print(json.dumps({"status": "registered", "artifact_id": aid}))

    elif args.command == "list":
        results = list_artifacts(kind=args.kind, skill=args.skill,
                                 limit=args.limit, db_path=args.db)
        print(json.dumps(results, indent=2))

    elif args.command == "get":
        result = get_artifact(args.artifact_id, db_path=args.db)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps({"status": "not_found", "artifact_id": args.artifact_id}))
            sys.exit(1)

    elif args.command == "export":
        count = export_manifest(kind=args.kind, output_path=args.output, db_path=args.db)
        print(json.dumps({"status": "exported", "count": count, "path": args.output}))


if __name__ == "__main__":
    main()