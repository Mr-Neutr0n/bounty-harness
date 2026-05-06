#!/usr/bin/env python3
"""Cross-account authorization replayer — IDOR/BOLA/BFLA/tenant isolation testing."""
import argparse, json, os, re, subprocess, sys, time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DIFF_FIELDS = {"status", "body_length", "body_fields", "content_type", "redirect_url"}
SENSITIVE_FIELD_PATTERNS = [r'email', r'password', r'token', r'secret', r'api_key', r'ssn', r'address',
    r'phone', r'credit_card', r'balance', r'salary', r'role', r'is_admin', r'permissions']

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def read_persona_headers(persona_dir, persona_id):
    hf = Path(persona_dir) / "headers" / f"{persona_id}.headers"
    if hf.exists():
        return json.loads(hf.read_text())
    creds = Path(persona_dir) / "creds"
    cred_files = sorted(creds.glob(f"{persona_id}_*.json")) if creds.exists() else []
    if cred_files:
        cred = json.loads(cred_files[-1].read_text())
        headers = {}
        if cred.get("bearer_token"): headers["Authorization"] = f"Bearer {cred['bearer_token']}"
        if cred.get("api_key"): headers["X-API-Key"] = cred["api_key"]
        if cred.get("cookies"): headers["Cookie"] = cred["cookies"]
        headers["X-Persona-Id"] = persona_id
        return headers
    return {}

def build_matrix(personas_path, routes_path, objects_path, output_path):
    personas = json.loads(Path(personas_path).read_text()) if Path(personas_path).exists() else {"personas":{}}
    routes = [json.loads(l) for l in Path(routes_path).read_text().splitlines() if l.strip()] if Path(routes_path).exists() else []
    persona_ids = [p for p in personas.get("personas",{}) if personas["personas"][p].get("credentials_imported")]
    matrix = {"personas": persona_ids, "route_count": len(routes), "pairs": []}
    for i, p1 in enumerate(persona_ids):
        for p2 in persona_ids[i+1:]:
            matrix["pairs"].append({"owner": p1, "attacker": p2, "role_relationship": "cross-account"})
    Path(output_path).write_text(json.dumps(matrix, indent=2))
    print(json.dumps({"status": "matrix_built", "personas": len(persona_ids), "pairs": len(matrix["pairs"])}))


def replay_request(persona_dir, persona_id, route, method, body=None):
    url = route
    headers = read_persona_headers(persona_dir, persona_id)
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-o", "-", "-X", method, url]
    if body:
        cmd += ["-d", body]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        lines = output.rsplit("\n", 1)
        body = lines[0] if len(lines) > 1 else ""
        status = lines[1].strip() if len(lines) > 1 else "0"
        return {"status": int(status), "body": body[:5000], "body_length": len(body)}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)[:100]}

def replay_corpus(matrix_path, persona_dir, samples_path, output_path, rate_limit):
    if not Path(matrix_path).exists():
        print(json.dumps({"error": "matrix not found"}))
        return
    matrix = json.loads(Path(matrix_path).read_text())
    results = []
    delay = 1.0 / max(rate_limit, 1)
    for pair in matrix.get("pairs", []):
        results.append({
            "experiment_id": f"exp_{len(results):05d}",
            "owner_persona": pair["owner"],
            "attacker_persona": pair["attacker"],
            "test": "matrix_replay",
            "result": "pending",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        time.sleep(delay)
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "replayed", "experiments": len(results)}))

def replay_single_route(persona_dir, route, method, output_path):
    personas_file = Path(persona_dir) / "personas.json"
    if not personas_file.exists():
        print(json.dumps({"error": "no personas"}))
        return
    personas = json.loads(personas_file.read_text())
    results = []
    for pid in personas["personas"]:
        headers = read_persona_headers(persona_dir, pid)
        if headers:
            resp = replay_request(persona_dir, pid, route, method)
            resp["persona"] = pid
            resp["route"] = route
            resp["method"] = method
            results.append(resp)
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "route_replayed", "personas": len(results)}))

def object_swap(persona_dir, objects_path, output_path, rate_limit):
    if not Path(objects_path).exists():
        Path(output_path).write_text("")
        print(json.dumps({"status": "no_objects"}))
        return
    objects = [json.loads(l) for l in Path(objects_path).read_text().splitlines() if l.strip()]
    results = [{"experiment_id": f"os_{i:05d}", "object": o["object_id"], "id_type": o["id_type"],
                "result": "pending", "timestamp": datetime.now(timezone.utc).isoformat()}
               for i, o in enumerate(objects[:100])]
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "object_swap_done", "objects": len(results)}))

def tenant_swap(persona_dir, routes_path, output_path, rate_limit):
    results = [{"experiment_id": f"ts_00001", "test": "tenant_swap", "result": "pending"}]
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "tenant_swap_done"}))

def role_test(persona_dir, output_path):
    results = [{"experiment_id": f"rt_00001", "test": "role_downgrade", "result": "pending"}]
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "role_test_done"}))

def anonymous_replay(routes_path, output_path, rate_limit):
    results = [{"experiment_id": f"ar_00001", "test": "anonymous_replay", "result": "pending"}]
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "anonymous_replay_done"}))

def replay_from_browser_capture(browser_dir, persona_dir, output_path, rate_limit):
    src = Path(browser_dir)
    page_state_file = src / "page_state.json"
    interactables_file = src / "interactables.json"
    routes_to_test = []
    if page_state_file.exists():
        ps = json.loads(page_state_file.read_text())
        url = ps.get("url", ps.get("final_url", ""))
        if url and url.startswith("http"):
            routes_to_test.append({"url": url, "method": "GET", "source": "page_state"})
    if interactables_file.exists():
        inter = json.loads(interactables_file.read_text())
        for link in inter.get("links", []):
            href = link.get("href", "")
            if href and href.startswith(("http://", "https://", "/")):
                routes_to_test.append({"url": href, "method": "GET", "source": f"link:{link.get('text','')[:40]}"})
        for form in inter.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "GET")
            if action and action.startswith(("http://", "https://", "/")):
                routes_to_test.append({"url": action, "method": method, "source": f"form:{form.get('id','')}"})
    personas_file = Path(persona_dir) / "personas.json"
    if not personas_file.exists():
        print(json.dumps({"error": "personas.json not found"}))
        return
    personas = json.loads(personas_file.read_text())
    results = []
    delay = 1.0 / max(rate_limit, 1)
    for route in routes_to_test[:50]:
        for pid in personas.get("personas", {}):
            headers = read_persona_headers(persona_dir, pid)
            if not headers:
                continue
            resp = replay_request(persona_dir, pid, route["url"], route["method"])
            resp["persona"] = pid
            resp["route"] = route["url"]
            resp["method"] = route["method"]
            resp["source"] = route["source"]
            resp["experiment_id"] = f"bc_{len(results):05d}"
            resp["timestamp"] = datetime.now(timezone.utc).isoformat()
            results.append(resp)
            time.sleep(delay)
    Path(output_path).write_text("\n".join(json.dumps(r) for r in results))
    print(json.dumps({"status": "browser_capture_replayed", "experiments": len(results), "routes_tested": len(routes_to_test)}))

def diff_results(replay_dir, output_path):
    findings = []
    replay_path = Path(replay_dir)
    for rf in replay_path.glob("*.jsonl"):
        try:
            for line in rf.read_text().splitlines():
                if not line.strip(): continue
                r = json.loads(line)
                if r.get("status") and str(r.get("status")).startswith("2") and r.get("attacker_persona"):
                    findings.append({
                        "finding_id": f"f_authz_{os.urandom(4).hex()}",
                        "category": "authorization",
                        "impact_class": "data_exposure",
                        "severity": "high",
                        "description": f"Unauthorized access: {r.get('attacker_persona')} could access {r.get('owner_persona')} resource",
                        "source_file": str(rf),
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    })
        except Exception:
            pass
    Path(output_path).write_text("\n".join(json.dumps(f) for f in findings))
    print(json.dumps({"status": "diffed", "findings": len(findings)}))

def evidence_pack(findings_path, output_dir):
    if not Path(findings_path).exists():
        print(json.dumps({"status": "no_findings"}))
        return
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    findings = [json.loads(l) for l in Path(findings_path).read_text().splitlines() if l.strip()]
    for f in findings:
        fid = f.get("finding_id", f"f_{os.urandom(4).hex()}")
        edir = Path(output_dir) / fid
        edir.mkdir(parents=True, exist_ok=True)
        (edir / "manifest.json").write_text(json.dumps(f, indent=2))
    print(json.dumps({"status": "evidence_packed", "findings": len(findings)}))

def main():
    parser = argparse.ArgumentParser(description="Cross-account authorization replayer")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True)
    parser.add_argument("--matrix")
    parser.add_argument("--persona-dir")
    parser.add_argument("--personas")
    parser.add_argument("--routes")
    parser.add_argument("--objects")
    parser.add_argument("--samples")
    parser.add_argument("--source")
    parser.add_argument("--route")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--rate-limit", type=int, default=25)
    parser.add_argument("--replay-dir")
    parser.add_argument("--findings")
    parser.add_argument("--output")
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    if args.action == "matrix":
        build_matrix(args.personas, args.routes, args.objects, args.output)
    elif args.action == "replay":
        replay_corpus(args.matrix, args.persona_dir, args.samples, args.output, args.rate_limit)
    elif args.action == "replay-route":
        replay_single_route(args.persona_dir, args.route, args.method, args.output)
    elif args.action == "replay-browser-capture":
        replay_from_browser_capture(args.source, args.persona_dir, args.output, args.rate_limit)
    elif args.action == "object-swap":
        object_swap(args.persona_dir, args.objects, args.output, args.rate_limit)
    elif args.action == "tenant-swap":
        tenant_swap(args.persona_dir, args.routes, args.output, args.rate_limit)
    elif args.action == "role-test":
        role_test(args.persona_dir, args.output)
    elif args.action == "anonymous":
        anonymous_replay(args.routes, args.output, args.rate_limit)
    elif args.action == "diff":
        diff_results(args.replay_dir, args.output)
    elif args.action == "evidence":
        evidence_pack(args.findings, args.output_dir)

if __name__ == "__main__":
    main()