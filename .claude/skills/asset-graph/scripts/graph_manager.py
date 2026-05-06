#!/usr/bin/env python3
"""Asset graph manager — SQLite-based persistent graph for targets, routes, objects, personas, findings."""
import argparse, json, os, sqlite3, subprocess, sys
from collections import defaultdict
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
CREATE TABLE IF NOT EXISTS js_files (
    js_id TEXT PRIMARY KEY, url TEXT, host TEXT, discovered_at TEXT
);
CREATE TABLE IF NOT EXISTS api_endpoints (
    endpoint_id TEXT PRIMARY KEY, method TEXT, path TEXT, host TEXT, discovered_at TEXT
);
"""

SENSITIVE_FIELDS = {"description", "evidence_path", "auth_state"}


def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)


def _register_artifact_cmd(kind, path, run_id=None, skill="asset-graph", summary=""):
    try:
        script = Path(__file__).resolve().parent.parent.parent.parent.parent / "tools" / "artifact_index.py"
        cmd = [
            sys.executable, str(script), "register",
            "--kind", kind, "--path", path,
            "--skill", skill, "--summary", summary
        ]
        if run_id:
            cmd.extend(["--run-id", run_id])
        subprocess.run(cmd, capture_output=True, timeout=10)
    except Exception:
        pass


def init_db(db_path, context, register_artifacts=False):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO runs (run_id, target, program, started_at) VALUES (?,?,?,?)",
                 (context.get("run_id", "run_001"), context.get("target","unknown"),
                  context.get("program","unknown"), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    if register_artifacts:
        _register_artifact_cmd("run", str(db_path), run_id=context.get("run_id", "run_001"),
                               summary=f"Asset graph for {context.get('target','unknown')}")
    print(json.dumps({"status": "initialized", "db": db_path}))


def ingest_recon(db_path, recon_dir, register_artifacts=False):
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
    if register_artifacts and live_file.exists():
        _register_artifact_cmd("asset", str(live_file),
                               summary=f"Recon hosts ({row_count} live)")
    print(json.dumps({"status": "ingested_recon", "hosts": row_count}))


def ingest_corpus(db_path, routes_path, objects_path, register_artifacts=False):
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
    if register_artifacts and Path(routes_path).exists():
        _register_artifact_cmd("asset", str(routes_path),
                               summary=f"Traffic routes ({route_count} routes)")
    print(json.dumps({"status": "ingested_corpus", "routes": route_count}))


def ingest_personas(db_path, personas_path, validation_path, register_artifacts=False):
    conn = sqlite3.connect(db_path)
    if Path(personas_path).exists():
        data = json.loads(Path(personas_path).read_text())
        for pid, pd in data.get("personas",{}).items():
            conn.execute("INSERT OR REPLACE INTO personas (persona_id, role, auth_state, run_id) VALUES (?,?,?,?)",
                         (pid, pd.get("role",""), pd.get("auth_state","unknown"), "run_001"))
    conn.commit()
    conn.close()
    if register_artifacts and Path(personas_path).exists():
        _register_artifact_cmd("asset", str(personas_path),
                               summary="Persona definitions")
    print(json.dumps({"status": "ingested_personas"}))


def ingest_findings(db_path, findings_dir, register_artifacts=False):
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
    if register_artifacts and verified.exists():
        _register_artifact_cmd("finding", str(verified),
                               summary="Verified findings ingested into asset graph")
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


def graph_summary(db_path, output_json):
    conn = sqlite3.connect(db_path)
    tables = ["hosts", "routes", "objects", "personas", "findings", "js_files", "api_endpoints"]
    counts = {}
    for t in tables:
        try:
            counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except Exception:
            counts[t] = 0

    js_count = counts.get("js_files", 0)
    api_count = counts.get("api_endpoints", 0)
    if "js_files" not in counts:
        js_count = 0
    if "api_endpoints" not in counts:
        api_count = 0

    severity_dist = {}
    try:
        for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"):
            severity_dist[row[0]] = row[1]
    except Exception:
        pass

    status_dist = {}
    try:
        for row in conn.execute("SELECT status, COUNT(*) as cnt FROM findings GROUP BY status"):
            status_dist[row[0]] = row[1]
    except Exception:
        pass

    target_info = {}
    try:
        row = conn.execute("SELECT target, program FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        if row:
            target_info = {"target": row[0], "program": row[1]}
    except Exception:
        pass

    conn.close()

    result = {
        "status": "ok",
        "target": target_info.get("target", "unknown"),
        "program": target_info.get("program", "unknown"),
        "host_count": counts.get("hosts", 0),
        "route_count": counts.get("routes", 0),
        "object_count": counts.get("objects", 0),
        "persona_count": counts.get("personas", 0),
        "finding_count": counts.get("findings", 0),
        "js_file_count": js_count,
        "api_endpoint_count": api_count,
        "finding_severity_distribution": severity_dist,
        "finding_status_distribution": status_dist,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Asset Graph Summary ===")
        print(f"  Target: {result['target']} ({result['program']})")
        print(f"  Hosts:            {result['host_count']}")
        print(f"  Routes:           {result['route_count']}")
        print(f"  Objects:          {result['object_count']}")
        print(f"  Personas:         {result['persona_count']}")
        print(f"  Findings:         {result['finding_count']}")
        print(f"  JS Files:         {result['js_file_count']}")
        print(f"  API Endpoints:    {result['api_endpoint_count']}")
        if severity_dist:
            print(f"  Severity dist:    {severity_dist}")
        if status_dist:
            print(f"  Status dist:      {status_dist}")
    return result


def graph_search(db_path, query, output_json):
    conn = sqlite3.connect(db_path)
    results = []

    for row in conn.execute(
        "SELECT route_id, method, route_signature, count FROM routes WHERE route_signature LIKE ? OR method LIKE ? LIMIT 200",
        (f"%{query}%", f"%{query}%")
    ):
        results.append({
            "asset_type": "route",
            "asset_id": row[0],
            "method": row[1],
            "route_signature": row[2],
            "count": row[3],
        })

    for row in conn.execute(
        "SELECT host_id, host FROM hosts WHERE host LIKE ? LIMIT 50",
        (f"%{query}%",)
    ):
        results.append({
            "asset_type": "host",
            "asset_id": row[0],
            "host": row[1],
        })

    for row in conn.execute(
        "SELECT finding_id, category, severity, impact_class FROM findings WHERE category LIKE ? OR description LIKE ? OR finding_id LIKE ? LIMIT 50",
        (f"%{query}%", f"%{query}%", f"%{query}%")
    ):
        results.append({
            "asset_type": "finding",
            "asset_id": row[0],
            "category": row[1],
            "severity": row[2],
            "impact_class": row[3],
        })

    conn.close()

    result = {"status": "ok", "query": query, "results": results, "count": len(results)}
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Search: '{query}' ({len(results)} matches) ===")
        for r in results:
            if r["asset_type"] == "route":
                print(f"  [route]  {r['asset_id']}  {r['method']} {r['route_signature']} ({r['count']} hits)")
            elif r["asset_type"] == "host":
                print(f"  [host]   {r['asset_id']}  {r['host']}")
            elif r["asset_type"] == "finding":
                print(f"  [finding] {r['asset_id']}  {r['category']} [{r['severity']}] {r['impact_class']}")
    return result


def _neighbors_of(conn, table, id_col, asset_id, label):
    try:
        rows = conn.execute(f"SELECT * FROM {table} WHERE {id_col} = ?", (asset_id,)).fetchall()
        if rows:
            cols = [d[0] for d in conn.execute(f"SELECT * FROM {table} LIMIT 0").description]
            return dict(zip(cols, rows[0]))
    except Exception:
        pass
    return None


def graph_get_node(db_path, asset_id, output_json, include_sensitive=False):
    conn = sqlite3.connect(db_path)
    node = None

    tables_to_check = [
        ("routes", "route_id"),
        ("hosts", "host_id"),
        ("personas", "persona_id"),
        ("findings", "finding_id"),
    ]

    for table, id_col in tables_to_check:
        node = _neighbors_of(conn, table, id_col, asset_id, table)
        if node:
            break

    if node is None:
        result = {"status": "not_found", "asset_id": asset_id}
        if output_json:
            print(json.dumps(result))
        conn.close()
        return result

    neighbors = []
    if "route_id" in node:
        for row in conn.execute("SELECT object_id, id_type FROM objects WHERE route_id = ?", (asset_id,)):
            neighbors.append({"asset_type": "object", "id": row[0], "type": row[1], "relationship": "belongs_to"})

    if "host" in node:
        host = node["host"]
        for row in conn.execute("SELECT route_id, method, route_signature FROM routes WHERE host = ?", (host,)):
            neighbors.append({"asset_type": "route", "id": row[0], "method": row[1], "route": row[2], "relationship": "hosted_at"})

    conn.close()

    if not include_sensitive:
        for field in SENSITIVE_FIELDS:
            node.pop(field, None)
        if "auth_state" in node:
            node["auth_state"] = "REDACTED"

    result = {"status": "ok", "asset_id": asset_id, "node": node, "neighbors": neighbors, "neighbor_count": len(neighbors)}
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Node: {asset_id} ===")
        print(json.dumps(node, indent=2, default=str))
        if neighbors:
            print(f"  Neighbors ({len(neighbors)}):")
            for n in neighbors:
                print(f"    [{n['asset_type']}] {n['id']}  ({n.get('relationship','')})")
    return result


def _collect_neighborhood(conn, start_id, depth):
    visited = set()
    queue = [(start_id, 0)]
    result = {"nodes": [], "edges": []}
    node_cache = {}

    def resolve(node_id):
        if node_id in node_cache:
            return node_cache[node_id]
        for table, id_col in [("routes", "route_id"), ("hosts", "host_id"),
                              ("personas","persona_id"), ("findings","finding_id")]:
            n = _neighbors_of(conn, table, id_col, node_id, table)
            if n:
                node_cache[node_id] = {"type": table, "data": n}
                return node_cache[node_id]
        node_cache[node_id] = None
        return None

    while queue:
        current, d = queue.pop(0)
        if current in visited or d > depth:
            continue
        visited.add(current)

        node_info = resolve(current)
        if node_info is None:
            continue
        result["nodes"].append({"id": current, "type": node_info["type"], "depth": d, "data": node_info["data"]})

        ntype = node_info["type"]
        if ntype == "routes":
            for row in conn.execute("SELECT object_id FROM objects WHERE route_id = ?", (current,)):
                nid = row[0]
                if nid not in visited:
                    queue.append((nid, d + 1))
                    result["edges"].append({"from": current, "to": nid, "relationship": "contains"})
        elif ntype == "hosts":
            host_name = node_info["data"].get("host", "")
            for row in conn.execute("SELECT route_id FROM routes WHERE host = ?", (host_name,)):
                nid = row[0]
                if nid not in visited:
                    queue.append((nid, d + 1))
                    result["edges"].append({"from": current, "to": nid, "relationship": "hosts"})

    return result


def graph_get_neighborhood(db_path, asset_id, depth, output_json):
    conn = sqlite3.connect(db_path)
    hood = _collect_neighborhood(conn, asset_id, depth)
    conn.close()

    hood["status"] = "ok"
    hood["asset_id"] = asset_id
    hood["depth"] = depth
    hood["node_count"] = len(hood["nodes"])
    hood["edge_count"] = len(hood["edges"])

    if output_json:
        print(json.dumps(hood))
    else:
        print(f"=== Neighborhood: {asset_id} (depth {depth}) ===")
        print(f"  Nodes: {hood['node_count']}, Edges: {hood['edge_count']}")
        for node in hood["nodes"]:
            print(f"  [{node['type']}] {node['id']} (depth {node['depth']})")
        if hood["edges"]:
            print("  Edges:")
            for edge in hood["edges"]:
                print(f"    {edge['from']} --[{edge['relationship']}]--> {edge['to']}")
    return hood


def main():
    parser = argparse.ArgumentParser(description="Asset graph manager")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True, choices=["init","ingest-recon","ingest-corpus","ingest-personas","ingest-findings","hotlist","diff","query",
                                                            "summary","search","get-node","get-neighborhood"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--recon-dir")
    parser.add_argument("--routes")
    parser.add_argument("--objects")
    parser.add_argument("--personas")
    parser.add_argument("--validation")
    parser.add_argument("--findings-dir")
    parser.add_argument("--sql")
    parser.add_argument("--output")
    parser.add_argument("--query", dest="search_query", help="Search query for assets by name/URL")
    parser.add_argument("--id", help="Asset ID for get-node / get-neighborhood")
    parser.add_argument("--depth", type=int, default=1, help="Neighborhood depth (default: 1)")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output in JSON format")
    parser.add_argument("--include-sensitive", action="store_true", help="Include sensitive fields in node output")
    parser.add_argument("--register-artifacts", action="store_true", default=False,
                        help="Register each asset node in the artifact registry")
    args = parser.parse_args()
    ctx = load_context(args.context)
    if args.action == "init":
        init_db(args.db, ctx, args.register_artifacts)
    elif args.action == "ingest-recon":
        ingest_recon(args.db, args.recon_dir, args.register_artifacts)
    elif args.action == "ingest-corpus":
        ingest_corpus(args.db, args.routes, args.objects, args.register_artifacts)
    elif args.action == "ingest-personas":
        ingest_personas(args.db, args.personas, args.validation, args.register_artifacts)
    elif args.action == "ingest-findings":
        ingest_findings(args.db, args.findings_dir, args.register_artifacts)
    elif args.action == "hotlist":
        build_hotlist(args.db, args.output)
    elif args.action == "diff":
        diff_runs(args.db, args.output)
    elif args.action == "query":
        query_graph(args.db, args.sql, args.output)
    elif args.action == "summary":
        graph_summary(args.db, args.output_json)
    elif args.action == "search":
        if not args.search_query:
            print(json.dumps({"error": "--query is required for search"}), file=sys.stderr)
            sys.exit(1)
        graph_search(args.db, args.search_query, args.output_json)
    elif args.action == "get-node":
        if not args.id:
            print(json.dumps({"error": "--id is required for get-node"}), file=sys.stderr)
            sys.exit(1)
        graph_get_node(args.db, args.id, args.output_json, args.include_sensitive)
    elif args.action == "get-neighborhood":
        if not args.id:
            print(json.dumps({"error": "--id is required for get-neighborhood"}), file=sys.stderr)
            sys.exit(1)
        graph_get_neighborhood(args.db, args.id, args.depth, args.output_json)

if __name__ == "__main__":
    main()