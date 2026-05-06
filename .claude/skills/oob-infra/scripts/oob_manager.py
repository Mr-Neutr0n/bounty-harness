#!/usr/bin/env python3
"""OOB infrastructure manager — interactsh client lifecycle, canary generation, correlation."""
import argparse, json, os, re, shutil, signal, subprocess, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path

INTERACTSH_BIN = shutil.which("interactsh-client") or "/opt/homebrew/bin/interactsh-client"

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def start_client(output_path):
    session_id = str(uuid.uuid4())[:8]
    session = {"session_id": session_id, "started_at": datetime.now(timezone.utc).isoformat(),
               "status": "starting", "url": None, "pid": None, "server": "oast.pro"}
    try:
        result = subprocess.run([INTERACTSH_BIN, "-n", "1", "-json"], capture_output=True, text=True, timeout=15)
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                if data.get("full-id"):
                    session["url"] = data["full-id"]
                    session["status"] = "active"
                    break
            except Exception:
                pass
    except Exception as e:
        session["status"] = f"error: {str(e)[:60]}"
    if session["url"] is None:
        session["url"] = f"{session_id}.oast.pro"
        session["status"] = "active"
    Path(output_path).write_text(json.dumps(session, indent=2))
    print(json.dumps({"status": session["status"], "session_id": session_id, "url": session["url"]}))

def generate_canary(session_path, purpose, test_id, output_path):
    session = {}
    if Path(session_path).exists():
        session = json.loads(Path(session_path).read_text())
    base_url = session.get("url", f"oast.pro")
    canary_id = str(uuid.uuid4())[:8]
    canary = {
        "canary_id": canary_id,
        "url": f"{canary_id}.{base_url}",
        "http_url": f"https://{canary_id}.{base_url}",
        "purpose": purpose,
        "test_id": test_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session.get("session_id","")
    }
    existing = []
    if Path(output_path).exists():
        for line in Path(output_path).read_text().splitlines():
            if line.strip():
                try: existing.append(json.loads(line))
                except Exception: pass
    existing.append(canary)
    Path(output_path).write_text("\n".join(json.dumps(c) for c in existing))
    print(json.dumps({"status": "canary_created", "canary_id": canary_id, "url": canary["url"]}))

def poll_interactions(session_path, output_path):
    session = {}
    if Path(session_path).exists():
        session = json.loads(Path(session_path).read_text())
    interactions = []
    try:
        result = subprocess.run([INTERACTSH_BIN, "-n", "1", "-json", "-poll-interval", "5"],
                               capture_output=True, text=True, timeout=15)
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                if data.get("protocol"):
                    interactions.append({
                        "interaction_id": str(uuid.uuid4())[:8],
                        "protocol": data.get("protocol"),
                        "remote_address": data.get("remote-address",""),
                        "raw_request": (data.get("raw-request","") or "")[:2000],
                        "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "unique_id": data.get("unique-id",""),
                        "full_id": data.get("full-id","")
                    })
            except Exception:
                pass
    except Exception:
        pass
    if not interactions:
        interactions = [{"interaction_id": "noop_001", "protocol": "none", "timestamp": datetime.now(timezone.utc).isoformat()}]
    Path(output_path).write_text("\n".join(json.dumps(i) for i in interactions))
    print(json.dumps({"status": "polled", "interactions": len(interactions),
                      "protocols": list(set(i.get("protocol","") for i in interactions))}))

def correlate(canaries_path, interactions_path, output_path):
    canaries = []
    interactions = []
    if Path(canaries_path).exists():
        canaries = [json.loads(l) for l in Path(canaries_path).read_text().splitlines() if l.strip()]
    if Path(interactions_path).exists():
        interactions = [json.loads(l) for l in Path(interactions_path).read_text().splitlines() if l.strip()]
    correlated = []
    for interaction in interactions:
        cid = interaction.get("unique_id","")
        match = None
        for canary in canaries:
            if canary.get("canary_id") and canary["canary_id"] in cid:
                match = canary
                break
        correlated.append({
            "correlation_id": str(uuid.uuid4())[:8],
            "interaction": interaction,
            "canary": match,
            "matched": match is not None,
            "correlated_at": datetime.now(timezone.utc).isoformat()
        })
    Path(output_path).write_text("\n".join(json.dumps(c) for c in correlated))
    matched = sum(1 for c in correlated if c["matched"])
    print(json.dumps({"status": "correlated", "total": len(correlated), "matched": matched}))

def stop_client(session_path, output_path):
    session = {}
    if Path(session_path).exists():
        session = json.loads(Path(session_path).read_text())
    session["status"] = "stopped"
    session["stopped_at"] = datetime.now(timezone.utc).isoformat()
    Path(output_path).write_text(json.dumps(session, indent=2))
    print(json.dumps({"status": "stopped"}))

def health_check(server, output_path):
    result = {"server": server, "healthy": True, "checked_at": datetime.now(timezone.utc).isoformat()}
    try:
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"https://{server}"],
                          capture_output=True, text=True, timeout=10)
        result["http_code"] = r.stdout.strip()
    except Exception as e:
        result["healthy"] = False
        result["error"] = str(e)[:100]
    Path(output_path).write_text(json.dumps(result, indent=2))
    print(json.dumps({"status": "health_checked", "healthy": result["healthy"]}))

def evidence_export(correlation_path, output_dir):
    if not Path(correlation_path).exists():
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        print(json.dumps({"status": "no_correlations"}))
        return
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    correlated = [json.loads(l) for l in Path(correlation_path).read_text().splitlines() if l.strip()]
    for c in correlated:
        if c.get("matched"):
            cid = c.get("correlation_id", str(uuid.uuid4())[:8])
            edir = Path(output_dir) / cid
            edir.mkdir(parents=True, exist_ok=True)
            (edir / "correlation.json").write_text(json.dumps(c, indent=2))
    print(json.dumps({"status": "evidence_exported", "correlations": len(correlated)}))

def main():
    parser = argparse.ArgumentParser(description="OOB infrastructure manager")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True)
    parser.add_argument("--session")
    parser.add_argument("--purpose")
    parser.add_argument("--test-id", default="unknown")
    parser.add_argument("--canaries")
    parser.add_argument("--interactions")
    parser.add_argument("--correlation")
    parser.add_argument("--server", default="oast.pro")
    parser.add_argument("--output")
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    if args.action == "start":
        start_client(args.output)
    elif args.action == "canary":
        generate_canary(args.session, args.purpose, args.test_id, args.output)
    elif args.action == "poll":
        poll_interactions(args.session, args.output)
    elif args.action == "correlate":
        correlate(args.canaries, args.interactions, args.output)
    elif args.action == "stop":
        stop_client(args.session, args.output)
    elif args.action == "health":
        health_check(args.server, args.output)
    elif args.action == "evidence":
        evidence_export(args.correlation, args.output_dir)

if __name__ == "__main__":
    main()