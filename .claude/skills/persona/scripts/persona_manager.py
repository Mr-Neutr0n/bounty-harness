#!/usr/bin/env python3
"""Persona manager — init, import, validate, redact, export credentials for authenticated testing."""
import argparse, json, hashlib, os, re, shutil, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

PERSONA_ROLES = [
    "anonymous", "attacker", "victim", "same_tenant_member",
    "different_tenant_member", "org_admin", "readonly",
    "billing_admin", "expired_user", "downgraded_user", "deleted_user"
]
SECRET_FIELDS = {"cookie", "token", "api_key", "bearer", "secret", "password", "authorization"}


def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)


def init_personas(persona_dir, context):
    personas = {
        "program": context.get("program", "unknown"),
        "target": context.get("target", "unknown"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "personas": {}
    }
    for role in PERSONA_ROLES:
        personas["personas"][role] = {
            "role": role,
            "description": "",
            "credentials_imported": False,
            "auth_state": "unknown",
            "metadata": {}
        }
    personas_path = Path(persona_dir) / "personas.json"
    personas_path.write_text(json.dumps(personas, indent=2))
    print(json.dumps({"status": "initialized", "roles": len(PERSONA_ROLES), "path": str(personas_path)}))
    return personas


def import_credential(persona_dir, persona_id, source, value):
    p = Path(persona_dir) / "personas.json"
    if not p.exists():
        print(json.dumps({"error": "personas.json not found, run init first"}))
        sys.exit(1)
    personas = json.loads(p.read_text())
    if persona_id not in personas["personas"]:
        print(json.dumps({"error": f"unknown persona {persona_id}"}))
        sys.exit(1)
    cred_id = str(uuid.uuid4())[:8]
    cred_file = Path(persona_dir) / "creds" / f"{persona_id}_{cred_id}.json"
    cred_file.parent.mkdir(parents=True, exist_ok=True)
    cred_data = {
        "persona": persona_id,
        "source": source,
        "credential_id": cred_id,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "value_hash": hashlib.sha256(value.encode()).hexdigest()[:16]
    }
    if source == "cookie":
        cred_data["cookies"] = value
    elif source == "token":
        cred_data["bearer_token"] = value
    elif source == "apikey":
        cred_data["api_key"] = value
    else:
        cred_data["raw_value"] = value
    cred_file.write_text(json.dumps(cred_data, indent=2))
    personas["personas"][persona_id]["credentials_imported"] = True
    personas["personas"][persona_id]["source"] = source
    p.write_text(json.dumps(personas, indent=2))
    print(json.dumps({"status": "imported", "persona": persona_id, "source": source, "hash": cred_data["value_hash"]}))


def validate_sessions(persona_dir, context, output_path):
    p = Path(persona_dir) / "personas.json"
    if not p.exists():
        print(json.dumps({"error": "personas.json not found"}))
        sys.exit(1)
    personas = json.loads(p.read_text())
    target_url = context.get("target_url", f"https://{context.get('target','localhost')}")
    results = []
    for pid, pdata in personas["personas"].items():
        if not pdata.get("credentials_imported"):
            results.append({"persona": pid, "role": pdata["role"], "auth_state": "not_configured"})
            continue
        creds_dir = Path(persona_dir) / "creds"
        cred_files = sorted(creds_dir.glob(f"{pid}_*.json"))
        if not cred_files:
            results.append({"persona": pid, "role": pdata["role"], "auth_state": "not_configured"})
            continue
        cred = json.loads(cred_files[-1].read_text())
        cookie = cred.get("cookies", "")
        token = cred.get("bearer_token", "")
        try:
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", target_url]
            if token:
                cmd += ["-H", f"Authorization: Bearer {token}"]
            elif cookie:
                cmd += ["-H", f"Cookie: {cookie}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            code = result.stdout.strip()
            state = "active" if code.startswith("2") else ("expired" if code in ("401","403") else "unknown")
        except Exception as e:
            state = f"error: {str(e)[:40]}"
        results.append({"persona": pid, "role": pdata["role"], "auth_state": state, "http_status": code})
        personas["personas"][pid]["auth_state"] = state
    p.write_text(json.dumps(personas, indent=2))
    Path(output_path).write_text(json.dumps({"sessions": results, "validated_at": datetime.now(timezone.utc).isoformat()}, indent=2))
    active = sum(1 for r in results if r["auth_state"] == "active")
    print(json.dumps({"status": "validated", "total": len(results), "active": active, "path": output_path}))


def redact_secrets(persona_dir, output_path):
    p = Path(persona_dir) / "personas.json"
    if not p.exists():
        print(json.dumps({"error": "personas.json not found"}))
        sys.exit(1)
    personas = json.loads(p.read_text())
    redacted = json.loads(json.dumps(personas))
    for pid in redacted["personas"]:
        redacted["personas"][pid]["credentials_imported"] = "[REDACTED]"
        redacted["personas"][pid]["metadata"] = {"redacted": True}
    Path(output_path).write_text(json.dumps(redacted, indent=2))
    print(json.dumps({"status": "redacted", "path": output_path}))


def export_headers(persona_dir, output_dir):
    p = Path(persona_dir) / "personas.json"
    if not p.exists():
        print(json.dumps({"error": "personas.json not found"}))
        sys.exit(1)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    personas = json.loads(p.read_text())
    for pid, pdata in personas["personas"].items():
        if not pdata.get("credentials_imported"):
            continue
        creds_dir = Path(persona_dir) / "creds"
        cred_files = sorted(creds_dir.glob(f"{pid}_*.json"))
        if not cred_files:
            continue
        cred = json.loads(cred_files[-1].read_text())
        headers = {}
        if cred.get("bearer_token"):
            headers["Authorization"] = f"Bearer {cred['bearer_token']}"
        if cred.get("api_key"):
            headers["X-API-Key"] = cred["api_key"]
        if cred.get("cookies"):
            headers["Cookie"] = cred["cookies"]
        headers["X-Persona-Id"] = pid
        headers["X-Persona-Role"] = pdata["role"]
        (out / f"{pid}.headers").write_text(json.dumps(headers, indent=2))
    print(json.dumps({"status": "exported", "dir": str(out), "personas": len(personas["personas"])}))


def main():
    parser = argparse.ArgumentParser(description="Persona credential manager")
    parser.add_argument("--context", default=".bb/context.json", help="Context JSON file")
    parser.add_argument("--action", required=True, choices=["init","import","validate","redact","export"])
    parser.add_argument("--persona-dir", default=".", help="Persona output directory")
    parser.add_argument("--persona", help="Persona ID for import")
    parser.add_argument("--source", help="Credential source type")
    parser.add_argument("--value", help="Credential value")
    parser.add_argument("--output", help="Output JSON path")
    parser.add_argument("--output-dir", help="Output directory for exports")
    args = parser.parse_args()
    ctx = load_context(args.context)
    if args.action == "init":
        init_personas(args.persona_dir, ctx)
    elif args.action == "import":
        import_credential(args.persona_dir, args.persona, args.source, args.value)
    elif args.action == "validate":
        validate_sessions(args.persona_dir, ctx, args.output)
    elif args.action == "redact":
        redact_secrets(args.persona_dir, args.output)
    elif args.action == "export":
        export_headers(args.persona_dir, args.output_dir)


if __name__ == "__main__":
    main()