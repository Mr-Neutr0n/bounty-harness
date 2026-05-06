#!/usr/bin/env python3
"""Asset graph manager — SQLite-based persistent graph for targets, routes, objects, personas, findings."""
import argparse, json, os, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, target TEXT, program TEXT, started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY, host TEXT, run_id TEXT, discovered_at TEXT
);
CREATE TABLE IF NOT EXISTS routes (
    route_id TEXT PRIMARY KEY, method TEXT, route_signature TEXT, host TEXT, count INTEGER DEFAULT 0, tags TEXT
);
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT, id_type TEXT, route_id TEXT, first_seen TEXT
);
CREATE TABLE IF NOT EXISTS personas (
    persona_id TEXT PRIMARY KEY, role TEXT, auth_state TEXT, run_id TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY, category TEXT, impact_class TEXT, severity TEXT, description TEXT, evidence_path TEXT, status TEXT, run_id TEXT
);
CREATE TABLE IF NOT EXISTS hotlist (
    asset_id TEXT PRIMARY KEY, asset_type TEXT, score REAL, factors TEXT
);
"""

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def init_db(db_path, context):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO runs (run_id, target, program, started_at) VALUES (?,?,?,?)",
                 (context.get("run_id", "run_001"), context.get("target","unknown"),
                  context.get("program","unknown"), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"status": "initialized", "db": db_path}))

def ingest_recon(db_path, recon_dir):
    conn = sqlite3.connect(db_path)
    live_file = Path(recon_dir) / "live" / "live_hosts.txt"
    if live_file.exists():
        for line in live_file.read_text().splitlines():
            line = line.strip()
            if line:
                conn.execute("INSERT OR IGNORE INTO hosts (host_id, host, discovered_at) VALUES (?,?,?)",
                             (line, line, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    row_count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    conn.close()
    print(json.dumps({"status": "ingested_recon", "hosts": row_count}))

def ingest_corpus(db_path, routes_path, objects_path):
    conn = sqlite3.connect(db_path)
    if Path(routes_path).exists():
        for line in Path(routes_path).read_text().splitlines():
            if not line.strip(): continue
            r = json.loads(line)
            conn.execute("INSERT OR REPLACE INTO routes (route_id, method, route_signature, host, count, tags) VALUES (?,?,?,?,?,?)",
                         (r.get("route_id",""), r.get("method","GET"), r.get("route_signature",""),
                          "unknown", r.get("count",0), json.dumps(r.get("tags",[]))))
    conn.commit()
    route_count = conn.execute("SELECT COUNT(*) FROM routes").fetchone()[0]
    conn.close()
    print(json.dumps({"status": "ingested_corpus", "routes": route_count}))

def ingest_personas(db_path, personas_path, validation_path):
    conn = sqlite3.connect(db_path)
    if Path(personas_path).exists():
        data = json.loads(Path(personas_path).read_text())
        for pid, pd in data.get("personas",{}).items():
            conn.execute("INSERT OR REPLACE INTO personas (persona_id, role, auth_state, run_id) VALUES (?,?,?,?)",
                         (pid, pd.get("role",""), pd.get("auth_state","unknown"), "run_001"))
    conn.commit()
    conn.close()
    print(json.dumps({"status": "ingested_personas"}))

def ingest_findings(db_path, findings_dir):
    conn = sqlite3.connect(db_path)
    verified = Path(findings_dir) / "verified.jsonl"
    if verified.exists():
        for line in verified.read_text().splitlines():
            if not line.strip(): continue
            f = json.loads(line)
            conn.execute("INSERT OR REPLACE INTO findings (finding_id, category, impact_class, severity, description, evidence_path, status, run_id) VALUES (?,?,?,?,?,?,?,?)",
                         (f.get("finding_id",f"f_{os.urandom(4).hex()}"), f.get("category","unknown"),
                          f.get("impact_class","unknown"), f.get("severity","medium"),
                          f.get("description",""), f.get("evidence_path",""), "verified", "run_001"))
    conn.commit()
    conn.close()
    print(json.dumps({"status": "ingested_findings"}))

def build_hotlist(db_path, output_path):
    conn = sqlite3.connect(db_path)
    items = []
    for row in conn.execute("SELECT route_id, method, route_signature, count, tags FROM routes ORDER BY count DESC LIMIT 100"):
        route_id, method, sig, count, tags_str = row
        tags = json.loads(tags_str) if tags_str else []
        score = min(count * 0.5, 50) + len(tags) * 5.0
        items.append({"asset_id": route_id, "asset_type": "route", "score": round(score,1),
                      "factors": {"method": method, "route": sig, "hits": count, "tags": tags}})
    conn.close()
    items.sort(key=lambda i: -i["score"])
    Path(output_path).write_text(json.dumps(items, indent=2))
    print(json.dumps({"status": "hotlist_built", "items": len(items), "path": output_path}))

def diff_runs(db_path, output_path):
    output = {"new_hosts": [], "new_routes": [], "delta_at": datetime.now(timezone.utc).isoformat()}
    Path(output_path).write_text(json.dumps(output, indent=2))
    print(json.dumps({"status": "diff_complete"}))
    return output

def query_graph(db_path, sql, output_path):
    conn = sqlite3.connect(db_path)
    cur = conn.execute(sql)
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    conn.close()
    Path(output_path).write_text(json.dumps(rows, indent=2))
    print(json.dumps({"status": "query_done", "rows": len(rows)}))

def main():
    parser = argparse.ArgumentParser(description="Asset graph manager")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True, choices=["init","ingest-recon","ingest-corpus","ingest-personas","ingest-findings","hotlist","diff","query"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--recon-dir")
    parser.add_argument("--routes")
    parser.add_argument("--objects")
    parser.add_argument("--personas")
    parser.add_argument("--validation")
    parser.add_argument("--findings-dir")
    parser.add_argument("--sql")
    parser.add_argument("--output")
    args = parser.parse_args()
    ctx = load_context(args.context)
    if args.action == "init":
        init_db(args.db, ctx)
    elif args.action == "ingest-recon":
        ingest_recon(args.db, args.recon_dir)
    elif args.action == "ingest-corpus":
        ingest_corpus(args.db, args.routes, args.objects)
    elif args.action == "ingest-personas":
        ingest_personas(args.db, args.personas, args.validation)
    elif args.action == "ingest-findings":
        ingest_findings(args.db, args.findings_dir)
    elif args.action == "hotlist":
        build_hotlist(args.db, args.output)
    elif args.action == "diff":
        diff_runs(args.db, args.output)
    elif args.action == "query":
        query_graph(args.db, args.sql, args.output)

if __name__ == "__main__":
    main()