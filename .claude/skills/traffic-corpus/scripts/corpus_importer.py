#!/usr/bin/env python3
"""Traffic corpus importer — import HAR/Burp/mitmproxy traffic, normalize routes, extract objects."""
import argparse, hashlib, json, os, re, sys, uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ID_PATTERNS = {
    "uuid": re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    "numeric": re.compile(r'(?<=/)\d{4,}(?=/|\.|$)'),
    "stripe": re.compile(r'(?:ch|pi|sub|in|cus|si|evt)_[A-Za-z0-9]{14,}'),
    "slug": re.compile(r'(?<=/)[a-z0-9]+(?:-[a-z0-9]+){2,}(?=/|$)'),
    "hex": re.compile(r'(?<=/)[0-9a-f]{16,}(?=/|\.|$)'),
}

SECURITY_TAGS = {
    "auth": ["authorization", "cookie", "bearer", "x-api-key", "session", "token"],
    "billing": ["payment", "invoice", "checkout", "billing", "subscription", "charge", "refund", "coupon", "pricing"],
    "admin": ["admin", "dashboard", "staff", "moderator", "internal", "settings/system"],
    "graphql": ["graphql", "gql"],
    "websocket": ["ws:", "wss:", "websocket"],
    "file": ["upload", "download", "file", "attachment", "media"],
    "share": ["share", "invite", "collab", "team", "workspace"],
    "ai": ["chat/completions", "embeddings", "assistants", "threads", "runs", "mcp", "models"],
}

ROUTE_SIG_RE = re.compile(r'(/\d+/|/[0-9a-f]{8,}/|/[a-z]+_[A-Za-z0-9]{10,}/|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def load_har(filepath):
    with open(filepath) as f:
        data = json.load(f)
    entries = data.get("log", {}).get("entries", [])
    samples = []
    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "GET")
        headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        resp_headers = {h["name"].lower(): h["value"] for h in resp.get("headers", [])}
        body = req.get("postData", {}).get("text", "") if req.get("postData") else ""
        samples.append({"method": method, "url": url, "request_headers": headers,
                        "request_body": body, "response_status": resp.get("status", 0),
                        "response_headers": resp_headers, "content_type": resp.get("content",{}).get("mimeType",""),
                        "response_body": resp.get("content", {}).get("text", "")[:5000],
                        "source": "har", "source_file": str(filepath)})
    return samples

def load_burp(filepath):
    from xml.etree import ElementTree as ET
    tree = ET.parse(filepath)
    root = tree.getroot()
    samples = []
    for item in root.findall(".//item"):
        url_elem = item.find("url")
        if url_elem is None:
            continue
        url = url_elem.text or ""
        req_elem = item.find("request")
        resp_elem = item.find("response")
        resp_status = int(item.find("status").text or "0") if item.find("status") is not None else 0
        samples.append({"method": "GET", "url": url, "request_body": "",
                        "response_status": resp_status, "response_body": (resp_elem.text or "")[:5000],
                        "content_type": "text/html", "source": "burp", "source_file": str(filepath),
                        "request_headers": {}, "response_headers": {}})
    return samples

def load_raw_curl(filepath):
    samples = []
    try:
        with open(filepath) as f:
            text = f.read()
        cmd_match = re.search(r'curl\s+.*?(?:https?://[^\s"\']+)', text)
        url_match = re.search(r'(https?://[^\s"\']+)', text)
        url = url_match.group(1) if url_match else ""
        method = "GET"
        if "--data" in text or "-d " in text:
            method = "POST"
        if "-X " in text:
            m = re.search(r'-X\s+(\w+)', text)
            if m: method = m.group(1)
        samples.append({"method": method, "url": url, "request_body": "",
                        "response_status": 0, "response_body": "", "content_type": "",
                        "source": "curl", "source_file": str(filepath),
                        "request_headers": {}, "response_headers": {}})
    except Exception:
        pass
    return samples

def import_traffic(sources_dir, output_path):
    samples = []
    src = Path(sources_dir)
    if src.is_dir():
        for f in src.iterdir():
            if f.suffix in (".har", ".json"):
                try:
                    samples.extend(load_har(f))
                except Exception as e:
                    print(f"WARN: failed to load {f}: {e}", file=sys.stderr)
            elif f.suffix == ".xml":
                try:
                    samples.extend(load_burp(f))
                except Exception as e:
                    print(f"WARN: failed to load {f}: {e}", file=sys.stderr)
            elif f.suffix in (".txt", ".sh"):
                try:
                    samples.extend(load_raw_curl(f))
                except Exception as e:
                    print(f"WARN: failed to load {f}: {e}", file=sys.stderr)
    for i, s in enumerate(samples):
        s["sample_id"] = f"s_{i:05d}"
        s["imported_at"] = datetime.now(timezone.utc).isoformat()
    Path(output_path).write_text("\n".join(json.dumps(s) for s in samples))
    print(json.dumps({"status": "imported", "samples": len(samples), "path": output_path}))

def normalize_route(url):
    u = url
    u = ROUTE_SIG_RE.sub("/{param}", u)
    u = re.sub(r'(?<=[?&])([^=&]+)=[^&]+', r'\1={param}', u)
    return u

def normalize_corpus(samples_path, output_path):
    if not Path(samples_path).exists():
        print(json.dumps({"status": "empty", "routes": 0}))
        Path(output_path).write_text("")
        return
    samples = [json.loads(l) for l in Path(samples_path).read_text().strip().splitlines() if l.strip()]
    seen = {}
    routes = []
    for s in samples:
        sig = normalize_route(s.get("url",""))
        key = f"{s.get('method','GET')}:{sig}"
        if key not in seen:
            seen[key] = {"method": s.get("method","GET"), "route_signature": sig,
                         "count": 0, "sample_ids": [], "tags": []}
        seen[key]["count"] += 1
        seen[key]["sample_ids"].append(s.get("sample_id",""))
    for key, route in seen.items():
        tags = set()
        lower_key = key.lower()
        for tag, keywords in SECURITY_TAGS.items():
            if any(k in lower_key for k in keywords):
                tags.add(tag)
        route["tags"] = sorted(tags)
        route["route_id"] = f"r_{hashlib.md5(key.encode()).hexdigest()[:12]}"
        routes.append(route)
    routes.sort(key=lambda r: -r["count"])
    Path(output_path).write_text("\n".join(json.dumps(r) for r in routes))
    print(json.dumps({"status": "normalized", "routes": len(routes), "total_samples": len(samples)}))

def extract_objects(samples_path, output_path):
    if not Path(samples_path).exists():
        Path(output_path).write_text("")
        print(json.dumps({"status": "empty", "objects": 0}))
        return
    samples = [json.loads(l) for l in Path(samples_path).read_text().strip().splitlines() if l.strip()]
    objects = []
    seen = set()
    for s in samples:
        url = s.get("url","")
        for id_type, pattern in ID_PATTERNS.items():
            for match in pattern.finditer(url):
                val = match.group(0)
                key = f"{id_type}:{val}"
                if key not in seen:
                    seen.add(key)
                    objects.append({
                        "object_id": val, "id_type": id_type,
                        "source_url": normalize_route(url),
                        "method": s.get("method","GET"),
                        "sample_id": s.get("sample_id","")
                    })
    Path(output_path).write_text("\n".join(json.dumps(o) for o in objects))
    print(json.dumps({"status": "extracted", "objects": len(objects), "types": list(set(o["id_type"] for o in objects))}))

def extract_graphql(samples_path, output_path):
    if not Path(samples_path).exists():
        Path(output_path).write_text("")
        print(json.dumps({"status": "empty", "operations": 0}))
        return
    samples = [json.loads(l) for l in Path(samples_path).read_text().strip().splitlines() if l.strip()]
    ops = []
    for s in samples:
        url = s.get("url","").lower()
        if "graphql" not in url:
            continue
        try:
            body = json.loads(s.get("request_body","") or "{}")
            query = body.get("query","")
            op_name = body.get("operationName","")
            if "mutation" in query:
                op_type = "mutation"
            elif "subscription" in query:
                op_type = "subscription"
            else:
                op_type = "query"
            ops.append({"url": url, "operation_name": op_name, "operation_type": op_type,
                       "sample_id": s.get("sample_id","")})
        except Exception:
            pass
    Path(output_path).write_text("\n".join(json.dumps(o) for o in ops))
    print(json.dumps({"status": "extracted", "graphql_operations": len(ops)}))

def extract_websockets(samples_path, output_path):
    if not Path(samples_path).exists():
        Path(output_path).write_text("")
        print(json.dumps({"status": "empty", "messages": 0}))
        return
    samples = [json.loads(l) for l in Path(samples_path).read_text().strip().splitlines() if l.strip()]
    ws = []
    for s in samples:
        url = s.get("url","").lower()
        if any(k in url for k in ("ws:/","wss:/","websocket")):
            ws.append({"url": url, "sample_id": s.get("sample_id",""),
                      "method": s.get("method","GET")})
    Path(output_path).write_text("\n".join(json.dumps(w) for w in ws))
    print(json.dumps({"status": "extracted", "websocket_entries": len(ws)}))

def summarize(input_path, routes_path, objects_path, output_path):
    samples = len([l for l in Path(input_path).read_text().splitlines() if l.strip()]) if Path(input_path).exists() else 0
    routes = len([l for l in Path(routes_path).read_text().splitlines() if l.strip()]) if Path(routes_path).exists() else 0
    objects = len([l for l in Path(objects_path).read_text().splitlines() if l.strip()]) if Path(objects_path).exists() else 0
    md = f"""# Traffic Corpus Summary

- **Total samples**: {samples}
- **Unique routes**: {routes}
- **Extracted objects**: {objects}
- **Generated**: {datetime.now(timezone.utc).isoformat()}
"""
    Path(output_path).write_text(md)
    print(json.dumps({"status": "summarized", "samples": samples, "routes": routes, "objects": objects}))

def main():
    parser = argparse.ArgumentParser(description="Traffic corpus importer and normalizer")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", choices=["import","normalize","routes","objects","graphql","websockets","summary"])
    parser.add_argument("--sources", help="Directory containing traffic files")
    parser.add_argument("--input", help="Input samples JSONL")
    parser.add_argument("--routes", help="Routes JSONL for summary")
    parser.add_argument("--objects", help="Objects JSONL for summary")
    parser.add_argument("--output", help="Output path")
    args = parser.parse_args()
    ctx = load_context(args.context)
    if args.action == "import":
        import_traffic(args.sources, args.output)
    elif args.action == "normalize":
        normalize_corpus(args.input, args.output)
    elif args.action == "routes":
        normalize_corpus(args.input, args.output)
    elif args.action == "objects":
        extract_objects(args.input, args.output)
    elif args.action == "graphql":
        extract_graphql(args.input, args.output)
    elif args.action == "websockets":
        extract_websockets(args.input, args.output)
    elif args.action == "summary":
        summarize(args.input, args.routes, args.objects, args.output)

if __name__ == "__main__":
    main()