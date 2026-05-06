#!/usr/bin/env python3
"""Program memory store --- governed, evidence-aware facts with corrections, confidence, decay, and strict program isolation."""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import textwrap
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

VALID_CATEGORIES = [
    "program_fact", "tech_fact", "false_positive", "accepted_finding",
    "credential_note", "rate_limit_note", "scope_note", "decision", "correction"
]
VALID_CONFIDENCE = ["low", "medium", "high"]
VALID_SENSITIVITY = ["program-private", "report-safe", "high-sensitivity"]
STATUSES = ["active", "stale", "superseded", "deleted"]

SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey|api_secret|secret[_-]?key|access[_-]?key)\s*[:=]\s*[\w\-+/=]{20,}', re.IGNORECASE),
     "possible API key in content"),
    (re.compile(r'(?:sk|pk)-(?:live|test)-[\w\-]{20,}'),
     "Stripe-style API key"),
    (re.compile(r'eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{16,}'),
     "JWT token detected"),
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS access key detected"),
    (re.compile(r'(?:Bearer|Basic)\s+[\w\-._~+/=]{20,}'),
     "Authorization header token"),
    (re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
     "private key block detected"),
    (re.compile(r'(?:password|passwd|pwd|secret)\s*[:=]\s*\S{4,}', re.IGNORECASE),
     "possible credential in content"),
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
     "GitHub personal access token"),
    (re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'),
     "Slack bot token"),
]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _fact_id():
    return f"f-{uuid.uuid4().hex[:16]}"


def _check_secrets(content):
    """Return list of violations found in content."""
    violations = []
    for pattern, msg in SECRET_PATTERNS:
        if pattern.search(content):
            violations.append(msg)
    return violations


def _get_db(db_path=".bb/memory.sqlite"):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_memory(program, db_path=".bb/memory.sqlite"):
    """Initialize memory for a program. Creates the SQLite DB if needed. Idempotent."""
    conn = _get_db(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS facts (
            fact_id TEXT PRIMARY KEY,
            program TEXT NOT NULL,
            category TEXT NOT NULL,
            content TEXT NOT NULL,
            confidence TEXT DEFAULT 'medium',
            source_artifact TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            sensitivity TEXT DEFAULT 'program-private',
            status TEXT DEFAULT 'active',
            correction_of TEXT,
            reviewed_by_human INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_program ON facts(program)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_category ON facts(program, category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_status ON facts(program, status)")
    conn.commit()
    conn.close()
    return {"status": "initialized", "program": program, "db_path": db_path}


def record_fact(program, category, content, confidence="medium", source_artifact=None,
                expires_at=None, sensitivity="program-private", reviewed=False,
                db_path=".bb/memory.sqlite", allow_secrets=False):
    """Record a fact. Returns dict with fact_id. Rejects content with secrets by default."""
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}'. Valid: {', '.join(VALID_CATEGORIES)}")
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"Invalid confidence '{confidence}'. Valid: {', '.join(VALID_CONFIDENCE)}")
    if sensitivity not in VALID_SENSITIVITY:
        raise ValueError(f"Invalid sensitivity '{sensitivity}'. Valid: {', '.join(VALID_SENSITIVITY)}")
    if not content or not content.strip():
        raise ValueError("Content must not be empty")

    if not allow_secrets:
        violations = _check_secrets(content)
        if violations:
            raise ValueError(f"Content contains possible secrets: {'; '.join(violations)}. Use --allow-secrets to override.")

    fid = _fact_id()
    conn = _get_db(db_path)
    conn.execute("""
        INSERT INTO facts (fact_id, program, category, content, confidence, source_artifact,
                           created_at, expires_at, sensitivity, status, reviewed_by_human)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
    """, (fid, program, category, content, confidence, source_artifact, _now_iso(), expires_at, sensitivity, 1 if reviewed else 0))
    conn.commit()
    conn.close()
    return {"status": "recorded", "fact_id": fid, "program": program, "category": category}


def get_fact(fact_id, db_path=".bb/memory.sqlite"):
    """Retrieve one fact by ID."""
    conn = _get_db(db_path)
    row = conn.execute("SELECT * FROM facts WHERE fact_id = ?", (fact_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return dict(row)


def search_facts(program, category=None, status="active", query=None,
                 db_path=".bb/memory.sqlite", cross_program=False):
    """Search facts for a program. Use cross_program=True to search all programs."""
    conn = _get_db(db_path)
    clauses = []
    params = []
    if not cross_program:
        clauses.append("program = ?")
        params.append(program)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if status:
        clauses.append("status = ?")
        params.append(status)
    sql = "SELECT * FROM facts"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    if query:
        sql += " AND content LIKE ?" if clauses else " WHERE content LIKE ?"
        params.append(f"%{query}%")
    sql += " ORDER BY created_at DESC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def record_correction(original_fact_id, new_content, reason, db_path=".bb/memory.sqlite",
                      allow_secrets=False):
    """Record a correction that supersedes an existing fact."""
    original = get_fact(original_fact_id, db_path)
    if original is None:
        raise ValueError(f"Original fact '{original_fact_id}' not found")

    if not allow_secrets:
        violations = _check_secrets(new_content)
        if violations:
            raise ValueError(f"New content contains possible secrets: {'; '.join(violations)}. Use --allow-secrets to override.")

    conn = _get_db(db_path)
    conn.execute("UPDATE facts SET status = 'superseded' WHERE fact_id = ?", (original_fact_id,))

    correction_content = f"CORRECTION (reason: {reason}): {new_content}"
    fid = _fact_id()
    conn.execute("""
        INSERT INTO facts (fact_id, program, category, content, confidence, created_at,
                           sensitivity, status, correction_of, reviewed_by_human)
        VALUES (?, ?, 'correction', ?, ?, ?, 'program-private', 'active', ?, 0)
    """, (fid, original["program"], correction_content, original.get("confidence", "medium"),
          _now_iso(), original_fact_id))
    conn.commit()
    conn.close()
    return {"status": "corrected", "fact_id": fid, "original_fact_id": original_fact_id, "program": original["program"]}


def decay_facts(program, db_path=".bb/memory.sqlite"):
    """Mark expired facts as stale. Called periodically."""
    conn = _get_db(db_path)
    now = _now_iso()
    result = conn.execute("""
        UPDATE facts SET status = 'stale'
        WHERE program = ? AND status = 'active' AND expires_at IS NOT NULL AND expires_at < ?
    """, (program, now))
    count = result.rowcount
    conn.commit()
    conn.close()
    return {"status": "decayed", "program": program, "stale_count": count}


def summarize_memory(program, db_path=".bb/memory.sqlite"):
    """Produce a redacted summary suitable for planner context consumption."""
    conn = _get_db(db_path)
    total = conn.execute("SELECT COUNT(*) as c FROM facts WHERE program = ? AND status = 'active'", (program,)).fetchone()["c"]
    stale = conn.execute("SELECT COUNT(*) as c FROM facts WHERE program = ? AND status = 'stale'", (program,)).fetchone()["c"]
    superseded = conn.execute("SELECT COUNT(*) as c FROM facts WHERE program = ? AND status = 'superseded'", (program,)).fetchone()["c"]
    categories = conn.execute("""
        SELECT category, COUNT(*) as c FROM facts WHERE program = ? AND status = 'active' GROUP BY category ORDER BY c DESC
    """, (program,)).fetchall()

    lines = [f"# Program Memory: {program}\n"]
    lines.append(f"- **Active facts**: {total}")
    lines.append(f"- **Stale facts**: {stale}")
    lines.append(f"- **Superseded facts**: {superseded}\n")
    lines.append("## Category Breakdown\n")
    for row in categories:
        lines.append(f"- **{row['category']}**: {row['c']}")

    tech_facts = conn.execute(
        "SELECT content FROM facts WHERE program = ? AND category = 'tech_fact' AND status = 'active' AND sensitivity != 'high-sensitivity'",
        (program,)).fetchall()
    if tech_facts:
        lines.append("\n## Technology Facts\n")
        for r in tech_facts:
            lines.append(f"- {r['content']}")

    scope_notes = conn.execute(
        "SELECT content FROM facts WHERE program = ? AND category = 'scope_note' AND status = 'active'",
        (program,)).fetchall()
    if scope_notes:
        lines.append("\n## Scope Notes\n")
        for r in scope_notes:
            lines.append(f"- {r['content']}")

    fps = conn.execute(
        "SELECT content FROM facts WHERE program = ? AND category = 'false_positive' AND status = 'active'",
        (program,)).fetchall()
    if fps:
        lines.append(f"\n## Known False Positives ({len(fps)})\n")
        for r in fps:
            lines.append(f"- {r['content']}")

    decisions = conn.execute(
        "SELECT content FROM facts WHERE program = ? AND category = 'decision' AND status = 'active'",
        (program,)).fetchall()
    if decisions:
        lines.append("\n## Past Decisions\n")
        for r in decisions:
            lines.append(f"- {r['content']}")

    corrections = conn.execute(
        "SELECT content FROM facts WHERE program = ? AND category = 'correction' AND status = 'active'",
        (program,)).fetchall()
    if corrections:
        lines.append("\n## Corrections\n")
        for r in corrections:
            lines.append(f"- {r['content']}")

    rate_notes = conn.execute(
        "SELECT content FROM facts WHERE program = ? AND category = 'rate_limit_note' AND status = 'active'",
        (program,)).fetchall()
    if rate_notes:
        lines.append("\n## Rate Limit Notes\n")
        for r in rate_notes:
            lines.append(f"- {r['content']}")

    pending_review = conn.execute(
        "SELECT COUNT(*) as c FROM facts WHERE program = ? AND category IN ('decision','false_positive','accepted_finding') AND reviewed_by_human = 0 AND status = 'active'",
        (program,)).fetchone()["c"]
    if pending_review > 0:
        lines.append(f"\n- **Facts pending human review**: {pending_review}")

    conn.close()
    return {"status": "summarized", "program": program, "summary": "\n".join(lines)}


def export_safe(program, output_path, db_path=".bb/memory.sqlite"):
    """Export report-safe facts (no raw credentials or PII)."""
    conn = _get_db(db_path)
    rows = conn.execute("""
        SELECT * FROM facts
        WHERE program = ? AND sensitivity = 'report-safe' AND status = 'active'
        ORDER BY created_at ASC
    """, (program,)).fetchall()
    conn.close()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for r in rows:
            entry = {
                "fact_id": r["fact_id"],
                "category": r["category"],
                "content": r["content"],
                "confidence": r["confidence"],
                "created_at": r["created_at"],
                "reviewed_by_human": bool(r["reviewed_by_human"])
            }
            f.write(json.dumps(entry) + "\n")
    return {"status": "exported", "program": program, "count": len(rows), "output": output_path}


def check_contradictions(program, db_path=".bb/memory.sqlite"):
    """Detect contradictory facts for human review. Uses simple keyword-based heuristics."""
    conn = _get_db(db_path)
    rows = conn.execute("""
        SELECT * FROM facts WHERE program = ? AND status = 'active' AND category != 'correction'
        ORDER BY created_at DESC
    """, (program,)).fetchall()
    conn.close()

    contradictions = []
    facts = [dict(r) for r in rows]
    contradiction_keywords = [
        (re.compile(r'\b(not|never|no|isnt|doesnt|cannot)\b', re.IGNORECASE),
         re.compile(r'\b(is|has|was|does|can|supports|uses)\b', re.IGNORECASE)),
        (re.compile(r'\b(absent|missing|lacks)\b', re.IGNORECASE),
         re.compile(r'\b(present|found|detected|exists)\b', re.IGNORECASE)),
        (re.compile(r'\b(in.scope|in scope)\b', re.IGNORECASE),
         re.compile(r'\b(out.of.scope|out of scope|oos)\b', re.IGNORECASE)),
    ]
    for i, f1 in enumerate(facts):
        for j, f2 in enumerate(facts):
            if i >= j:
                continue
            if f1["category"] != f2["category"]:
                continue
            for neg_pat, pos_pat in contradiction_keywords:
                f1_neg = neg_pat.search(f1["content"])
                f1_pos = pos_pat.search(f1["content"])
                f2_neg = neg_pat.search(f2["content"])
                f2_pos = pos_pat.search(f2["content"])
                if (f1_neg and f2_pos) or (f1_pos and f2_neg):
                    contradictions.append({
                        "fact_a_id": f1["fact_id"],
                        "fact_b_id": f2["fact_id"],
                        "category": f1["category"],
                        "a_content": f1["content"],
                        "b_content": f2["content"],
                        "signal": f"negation mismatch: '{f1_neg.group(0) if f1_neg else f1_pos.group(0)}' vs '{f2_neg.group(0) if f2_neg else f2_pos.group(0)}'"
                    })
    return {"status": "checked", "program": program, "contradictions": len(contradictions), "pairs": contradictions}


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Governed program memory store with corrections, confidence, decay, and program isolation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Hard Rules:
              Per-program isolation enforced (use --cross-program to override)
              Raw secrets in content: FORBIDDEN (detected by regex patterns)
              Auto-import from output: preview first, explicit --apply needed
              Human review for high-impact facts: use --reviewed to mark as reviewed
              Decay: facts with expires_at in the past become 'stale'
              Contradictions surfaced via 'contradictions' subcommand, never silently merged
        """)
    )
    sub = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    init_p = sub.add_parser("init", help="Initialize memory for a program")
    init_p.add_argument("--program", required=True)
    init_p.add_argument("--db", default=".bb/memory.sqlite")

    record_p = sub.add_parser("record", help="Record a fact")
    record_p.add_argument("--program", required=True)
    record_p.add_argument("--category", required=True)
    record_p.add_argument("--content", required=True)
    record_p.add_argument("--confidence", default="medium")
    record_p.add_argument("--source-artifact")
    record_p.add_argument("--expires-at")
    record_p.add_argument("--sensitivity", default="program-private")
    record_p.add_argument("--reviewed", action="store_true")
    record_p.add_argument("--allow-secrets", action="store_true")
    record_p.add_argument("--db", default=".bb/memory.sqlite")

    get_p = sub.add_parser("get", help="Retrieve one fact by ID")
    get_p.add_argument("--fact-id", required=True)
    get_p.add_argument("--db", default=".bb/memory.sqlite")

    search_p = sub.add_parser("search", help="Search facts for a program")
    search_p.add_argument("--program", required=True)
    search_p.add_argument("--category")
    search_p.add_argument("--status", default="active")
    search_p.add_argument("--query")
    search_p.add_argument("--cross-program", action="store_true")
    search_p.add_argument("--db", default=".bb/memory.sqlite")

    correct_p = sub.add_parser("correct", help="Record a correction that supersedes an existing fact")
    correct_p.add_argument("--fact-id", required=True)
    correct_p.add_argument("--new-content", required=True)
    correct_p.add_argument("--reason", required=True)
    correct_p.add_argument("--allow-secrets", action="store_true")
    correct_p.add_argument("--db", default=".bb/memory.sqlite")

    decay_p = sub.add_parser("decay", help="Mark expired facts as stale")
    decay_p.add_argument("--program", required=True)
    decay_p.add_argument("--db", default=".bb/memory.sqlite")

    summarize_p = sub.add_parser("summarize", help="Produce a redacted summary for planner context")
    summarize_p.add_argument("--program", required=True)
    summarize_p.add_argument("--output")
    summarize_p.add_argument("--db", default=".bb/memory.sqlite")

    export_p = sub.add_parser("export", help="Export report-safe facts")
    export_p.add_argument("--program", required=True)
    export_p.add_argument("--output", required=True)
    export_p.add_argument("--db", default=".bb/memory.sqlite")

    contra_p = sub.add_parser("contradictions", help="Find contradictory facts for human review")
    contra_p.add_argument("--program", required=True)
    contra_p.add_argument("--db", default=".bb/memory.sqlite")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.subcommand is None:
        parser.print_help()
        sys.exit(1)

    try:
        if args.subcommand == "init":
            result = init_memory(args.program, args.db)
        elif args.subcommand == "record":
            result = record_fact(
                args.program, args.category, args.content, args.confidence,
                args.source_artifact, args.expires_at, args.sensitivity,
                args.reviewed, args.db, args.allow_secrets
            )
        elif args.subcommand == "get":
            result = get_fact(args.fact_id, args.db)
            if result is None:
                print(json.dumps({"error": "fact not found", "fact_id": args.fact_id}))
                sys.exit(0)
        elif args.subcommand == "search":
            result = search_facts(args.program, args.category, args.status, args.query, args.db, args.cross_program)
            result = {"status": "ok", "program": args.program, "count": len(result), "facts": result}
        elif args.subcommand == "correct":
            result = record_correction(args.fact_id, args.new_content, args.reason, args.db, args.allow_secrets)
        elif args.subcommand == "decay":
            result = decay_facts(args.program, args.db)
        elif args.subcommand == "summarize":
            result = summarize_memory(args.program, args.db)
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(args.output).write_text(result["summary"])
        elif args.subcommand == "export":
            result = export_safe(args.program, args.output, args.db)
        elif args.subcommand == "contradictions":
            result = check_contradictions(args.program, args.db)
        else:
            parser.print_help()
            sys.exit(1)

        print(json.dumps(result, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()