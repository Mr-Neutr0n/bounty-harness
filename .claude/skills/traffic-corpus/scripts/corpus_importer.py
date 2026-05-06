#!/usr/bin/env python3
"""Traffic corpus importer — import HAR/Burp/mitmproxy traffic, normalize routes, extract objects."""
import argparse, hashlib, json, os, re, subprocess, sys
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

SENSITIVE_HEADERS = {"cookie", "authorization", "bearer", "x-api-key", "session", "token",
                     "x-auth-token", "x-csrf-token", "proxy-authorization", "set-cookie",
                     "x-forwarded-for", "x-real-ip"}
EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
API_KEY_RE = re.compile(r'(api[_-]?key|apikey|api[_-]?secret)[=:]\s*[^\s&,;]+', re.I)
BEARER_RE = re.compile(r'bearer\s+[^\s,;]+', re.I)

def redact_headers(headers, include_sensitive=False):
    if include_sensitive:
        return dict(headers)
    redacted = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            redacted[k] = "REDACTED"
        else:
            redacted[k] = v
    return redacted

def redact_body(body, include_sensitive=False):
    if include_sensitive:
        return body
    if not body:
        return body
    text = str(body)
    text = EMAIL_RE.sub("MASKED", text)
    text = API_KEY_RE.sub(r'\1=REDACTED', text)
    text = BEARER_RE.sub("Bearer REDACTED", text)
    return text

def redact_url(url, include_sensitive=False):
    if include_sensitive:
        return url
    text = str(url)
    text = re.sub(r'([?&])(token|api[_-]?key|apikey|auth|secret|password|access_token|refresh_token|session)=[^&]+',
                  r'\1\2=REDACTED', text, flags=re.I)
    return text

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def _register_artifact_cmd(kind, path, run_id=None, skill="traffic-corpus", summary=""):
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

def _register_traffic_requests(samples_path, register_artifacts, run_id=None):
    if not register_artifacts or not Path(samples_path).exists():
        return
    try:
        for line in Path(samples_path).read_text().splitlines():
            if not line.strip():
                continue
            s = json.loads(line)
            sid = s.get("sample_id", "")
            if sid:
                _register_artifact_cmd("traffic", str(samples_path), run_id=run_id,
                    summary=f"Traffic sample {sid} ({s.get('method','GET')} {s.get('url','')[:80]})")
    except Exception:
        pass

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

def load_browser_capture(sources_dir):
    src = Path(sources_dir)
    samples = []
    page_state_file = src / "page_state.json"
    if page_state_file.exists():
        ps = json.loads(page_state_file.read_text())
        samples.append({
            "method": "GET",
            "url": ps.get("url", ps.get("final_url", "")),
            "request_body": "",
            "response_status": ps.get("http_status", 0),
            "response_body": "",
            "content_type": "text/html",
            "source": "browser",
            "source_file": str(src / "page_state.json"),
            "request_headers": {},
            "response_headers": {},
        })
    har_file = src / "traffic.har"
    if har_file.exists():
        try:
            har_samples = load_har(har_file)
            for s in har_samples:
                s["source"] = "browser"
                s["source_file"] = str(har_file)
            samples.extend(har_samples)
        except Exception as e:
            print(f"WARN: failed to load browser HAR {har_file}: {e}", file=sys.stderr)
    interactables_file = src / "interactables.json"
    if interactables_file.exists():
        try:
            inter = json.loads(interactables_file.read_text())
            for link in inter.get("links", []):
                href = link.get("href", "")
                if href and href.startswith(("http://", "https://", "/")):
                    samples.append({
                        "method": "GET",
                        "url": href,
                        "request_body": "",
                        "response_status": 0,
                        "response_body": "",
                        "content_type": "",
                        "source": "browser",
                        "source_file": str(interactables_file),
                        "request_headers": {},
                        "response_headers": {},
                    })
            for form in inter.get("forms", []):
                action = form.get("action", "")
                method = form.get("method", "GET")
                if action and action.startswith(("http://", "https://", "/")):
                    samples.append({
                        "method": method,
                        "url": action,
                        "request_body": "",
                        "response_status": 0,
                        "response_body": "",
                        "content_type": "",
                        "source": "browser",
                        "source_file": str(interactables_file),
                        "request_headers": {},
                        "response_headers": {},
                    })
        except Exception as e:
            print(f"WARN: failed to load browser interactables {interactables_file}: {e}", file=sys.stderr)
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

def import_traffic(sources_dir, output_path, register_artifacts=False, source_type=None):
    samples = []
    src = Path(sources_dir)
    if src.is_dir():
        if source_type == "browser":
            samples.extend(load_browser_capture(sources_dir))
        else:
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
    if register_artifacts:
        _register_artifact_cmd("traffic", str(output_path),
                               summary=f"Imported traffic corpus ({len(samples)} samples)")
        _register_traffic_requests(str(output_path), register_artifacts)
    print(json.dumps({"status": "imported", "samples": len(samples), "path": output_path}))

def normalize_route(url):
    u = url
    u = ROUTE_SIG_RE.sub("/{param}", u)
    u = re.sub(r'(?<=[?&])([^=&]+)=[^&]+', r'\1={param}', u)
    return u

def normalize_corpus(samples_path, output_path, register_artifacts=False):
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
    if register_artifacts:
        _register_artifact_cmd("traffic", str(output_path),
                               summary=f"Normalized routes ({len(routes)} routes, {len(samples)} samples)")
    print(json.dumps({"status": "normalized", "routes": len(routes), "total_samples": len(samples)}))

def extract_objects(samples_path, output_path, register_artifacts=False):
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
    if register_artifacts:
        _register_artifact_cmd("traffic", str(output_path),
                               summary=f"Extracted objects ({len(objects)} objects)")
    print(json.dumps({"status": "extracted", "objects": len(objects), "types": list(set(o["id_type"] for o in objects))}))

def extract_graphql(samples_path, output_path, register_artifacts=False):
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
    if register_artifacts:
        _register_artifact_cmd("traffic", str(output_path),
                               summary=f"GraphQL operations ({len(ops)} ops)")
    print(json.dumps({"status": "extracted", "graphql_operations": len(ops)}))

def extract_websockets(samples_path, output_path, register_artifacts=False):
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
    if register_artifacts:
        _register_artifact_cmd("traffic", str(output_path),
                               summary=f"WebSocket entries ({len(ws)} entries)")
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


def _load_corpus_samples(corpus_path):
    sp = Path(corpus_path)
    samples_file = sp / "samples.jsonl"
    if not samples_file.exists():
        if sp.suffix == ".jsonl":
            samples_file = sp
        else:
            print(json.dumps({"error": "corpus not found", "corpus": corpus_path}), file=sys.stderr)
            return []
    if not samples_file.exists():
        return []
    return [json.loads(l) for l in samples_file.read_text().strip().splitlines() if l.strip()]


def _corpus_dir(corpus_path):
    sp = Path(corpus_path)
    if sp.suffix == ".jsonl":
        return sp.parent
    return sp


def corpus_list_index(corpus_dir, output_json):
    base = Path(corpus_dir)
    if not base.is_dir():
        result = {"status": "error", "error": f"corpus-dir not found: {corpus_dir}"}
        print(json.dumps(result))
        return result
    indices = []
    for subdir in sorted(base.iterdir()):
        if subdir.is_dir():
            samples_file = subdir / "samples.jsonl"
            if samples_file.exists():
                samples = [json.loads(l) for l in samples_file.read_text().strip().splitlines() if l.strip()]
                hosts = set()
                methods = defaultdict(int)
                statuses = defaultdict(int)
                for s in samples:
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(s.get("url","")).hostname or "unknown"
                        hosts.add(host)
                    except Exception:
                        pass
                    methods[s.get("method","GET")] += 1
                    statuses[str(s.get("response_status",0))] += 1
                indices.append({
                    "corpus_id": subdir.name,
                    "path": str(subdir),
                    "total_samples": len(samples),
                    "host_count": len(hosts),
                    "methods": dict(methods),
                    "status_codes": dict(statuses),
                })
    result = {"status": "ok", "corpora": indices, "count": len(indices)}
    if output_json:
        print(json.dumps(result))
    return result


def corpus_summary(corpus_path, include_sensitive, output_json):
    samples = _load_corpus_samples(corpus_path)
    if not samples:
        return {"status": "empty", "samples": 0}
    hosts = set()
    methods = defaultdict(int)
    statuses = defaultdict(int)
    content_types = defaultdict(int)
    graphql_count = 0
    ws_count = 0
    for s in samples:
        try:
            from urllib.parse import urlparse
            host = urlparse(s.get("url","")).hostname or "unknown"
            hosts.add(host)
        except Exception:
            pass
        methods[s.get("method","GET")] += 1
        statuses[s.get("response_status",0)] += 1
        ct = s.get("content_type","") or "unknown"
        content_types[ct.split(";")[0] if ct else "unknown"] += 1
        url = s.get("url","").lower()
        if "graphql" in url:
            graphql_count += 1
        if any(k in url for k in ("ws:/","wss:/","websocket")):
            ws_count += 1
    top_statuses = sorted(statuses.items(), key=lambda x: -x[1])[:10]
    top_ct = sorted(content_types.items(), key=lambda x: -x[1])[:10]
    result = {
        "status": "ok",
        "corpus_id": _corpus_dir(corpus_path).name,
        "total_samples": len(samples),
        "host_count": len(hosts),
        "hosts": sorted(hosts) if not output_json else list(hosts),
        "method_counts": dict(methods),
        "status_code_counts": {str(k): v for k, v in top_statuses},
        "content_type_counts": dict(top_ct),
        "graphql_requests": graphql_count,
        "websocket_requests": ws_count,
    }
    if output_json:
        print(json.dumps(result))
    else:
        summary_lines = [
            f"=== Corpus: {result['corpus_id']} ===",
            f"  Total requests: {result['total_samples']}",
            f"  Hosts: {result['host_count']}",
            f"  Methods: {result['method_counts']}",
            f"  Top statuses: {dict(top_statuses)}",
            f"  Top content types: {dict(top_ct)}",
            f"  GraphQL requests: {graphql_count}",
            f"  WebSocket requests: {ws_count}",
        ]
        print("\n".join(summary_lines))
    return result


def corpus_search(corpus_path, query, include_sensitive, output_json):
    samples = _load_corpus_samples(corpus_path)
    if not samples:
        result = {"status": "empty", "results": []}
        if output_json:
            print(json.dumps(result))
        return result
    query_lower = query.lower()
    tokens = query_lower.split()
    results = []
    for s in samples:
        method = s.get("method","")
        url = s.get("url","")
        status = str(s.get("response_status",""))
        combined = f"{method} {url} {status}".lower()
        matches = True
        for t in tokens:
            if t not in combined:
                matches = False
                break
        if not matches:
            continue
        results.append({
            "sample_id": s.get("sample_id",""),
            "method": method,
            "url": redact_url(url, include_sensitive) if not include_sensitive else url,
            "response_status": s.get("response_status",0),
        })
    results.sort(key=lambda x: x["sample_id"])
    result = {"status": "ok", "query": query, "results": results, "count": len(results)}
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Search: '{query}' ({len(results)} matches) ===")
        for r in results[:20]:
            print(f"  {r['sample_id']} [{r['response_status']}] {r['method']} {r['url']}")
        if len(results) > 20:
            print(f"  ... and {len(results) - 20} more results")
    return result


def corpus_peek(corpus_path, limit, include_sensitive, output_json):
    samples = _load_corpus_samples(corpus_path)
    subset = samples[:limit]
    redacted = []
    for s in subset:
        redacted.append({
            "sample_id": s.get("sample_id",""),
            "method": s.get("method","GET"),
            "url": redact_url(s.get("url",""), include_sensitive),
            "response_status": s.get("response_status",0),
            "source": s.get("source",""),
        })
    result = {"status": "ok", "limit": limit, "shown": len(redacted), "total": len(samples), "samples": redacted}
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Peek ({len(redacted)}/{len(samples)} requests) ===")
        for r in redacted:
            print(f"  {r['sample_id']} [{r['response_status']}] {r['method']} {r['url']}")
    return result


def corpus_read(corpus_path, offset, limit, include_sensitive, output_json):
    samples = _load_corpus_samples(corpus_path)
    subset = samples[offset:offset+limit]
    redacted = []
    for s in subset:
        redacted.append({
            "sample_id": s.get("sample_id",""),
            "method": s.get("method","GET"),
            "url": redact_url(s.get("url",""), include_sensitive),
            "response_status": s.get("response_status",0),
            "source": s.get("source",""),
        })
    next_offset = offset + limit if offset + limit < len(samples) else None
    result = {
        "status": "ok",
        "offset": offset,
        "limit": limit,
        "shown": len(redacted),
        "total": len(samples),
        "next_offset": next_offset,
        "samples": redacted,
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Read (offset={offset}, limit={limit}, {len(redacted)}/{len(samples)}) ===")
        for r in redacted:
            print(f"  {r['sample_id']} [{r['response_status']}] {r['method']} {r['url']}")
        if next_offset is not None:
            print(f"  next offset: {next_offset}")
        else:
            print(f"  (end of corpus)")
    return result


def corpus_get_request(corpus_path, request_id, include_sensitive, output_json):
    samples = _load_corpus_samples(corpus_path)
    target = None
    for s in samples:
        if s.get("sample_id") == request_id:
            target = s
            break
    if target is None:
        result = {"status": "not_found", "request_id": request_id}
        if output_json:
            print(json.dumps(result))
        return result
    result = {
        "status": "ok",
        "request_id": request_id,
        "method": target.get("method","GET"),
        "url": redact_url(target.get("url",""), include_sensitive),
        "request_headers": redact_headers(target.get("request_headers",{}), include_sensitive),
        "request_body": redact_body(target.get("request_body",""), include_sensitive) if include_sensitive else "HIDDEN",
        "content_type": target.get("content_type",""),
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Request: {request_id} ===")
        print(f"  Method: {result['method']}")
        print(f"  URL: {result['url']}")
        print(f"  Headers: {json.dumps(result['request_headers'], indent=2)}")
        print(f"  Body: {result['request_body']}")
    return result


def corpus_get_response(corpus_path, request_id, include_sensitive, body_limit, output_json):
    samples = _load_corpus_samples(corpus_path)
    target = None
    for s in samples:
        if s.get("sample_id") == request_id:
            target = s
            break
    if target is None:
        result = {"status": "not_found", "request_id": request_id}
        if output_json:
            print(json.dumps(result))
        return result
    raw_body = target.get("response_body","")
    body = raw_body[:body_limit] if include_sensitive else "HIDDEN"
    if include_sensitive:
        body = redact_body(body, include_sensitive)
    result = {
        "status": "ok",
        "request_id": request_id,
        "response_status": target.get("response_status",0),
        "response_headers": redact_headers(target.get("response_headers",{}), include_sensitive),
        "body": body,
        "body_truncated": len(raw_body) > body_limit if include_sensitive else False,
        "body_limit": body_limit,
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Response: {request_id} ===")
        print(f"  Status: {result['response_status']}")
        print(f"  Headers: {json.dumps(result['response_headers'], indent=2)}")
        print(f"  Body ({min(len(raw_body), body_limit) if include_sensitive else 0} bytes):")
        print(result['body'])
    return result


def main():
    parser = argparse.ArgumentParser(description="Traffic corpus importer and normalizer")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", choices=["import","normalize","routes","objects","graphql","websockets","summary",
                                             "list-index","corpus-summary","search","peek","read","get-request","get-response"])
    parser.add_argument("--sources", help="Directory containing traffic files")
    parser.add_argument("--source", help="Source type override (e.g. browser, har, burp)")
    parser.add_argument("--input", help="Input samples JSONL")
    parser.add_argument("--routes", help="Routes JSONL for summary")
    parser.add_argument("--objects", help="Objects JSONL for summary")
    parser.add_argument("--output", help="Output path")
    parser.add_argument("--corpus-dir", help="Base directory containing corpora (for list-index)")
    parser.add_argument("--corpus", help="Path to corpus directory or samples file")
    parser.add_argument("--query", help="Search query (method, path, status)")
    parser.add_argument("--limit", type=int, default=20, help="Limit for peek/read (default: 20)")
    parser.add_argument("--offset", type=int, default=0, help="Offset for paged read")
    parser.add_argument("--request-id", help="Specific request ID to retrieve")
    parser.add_argument("--body-limit", type=int, default=5000, help="Response body size limit (default: 5000)")
    parser.add_argument("--include-sensitive", action="store_true", help="Include sensitive data (cookies, tokens, API keys, email)")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output in JSON format")
    parser.add_argument("--register-artifacts", action="store_true", default=False,
                        help="Register each request in the artifact registry")
    args = parser.parse_args()
    if args.action == "import":
        import_traffic(args.sources, args.output, args.register_artifacts, source_type=args.source)
    elif args.action == "normalize":
        normalize_corpus(args.input, args.output, args.register_artifacts)
    elif args.action == "routes":
        normalize_corpus(args.input, args.output, args.register_artifacts)
    elif args.action == "objects":
        extract_objects(args.input, args.output, args.register_artifacts)
    elif args.action == "graphql":
        extract_graphql(args.input, args.output, args.register_artifacts)
    elif args.action == "websockets":
        extract_websockets(args.input, args.output, args.register_artifacts)
    elif args.action == "summary":
        summarize(args.input, args.routes, args.objects, args.output)
    elif args.action == "list-index":
        corpus_list_index(args.corpus_dir, args.output_json)
    elif args.action == "corpus-summary":
        if not args.corpus:
            print(json.dumps({"error": "--corpus is required for corpus-summary"}), file=sys.stderr)
            sys.exit(1)
        corpus_summary(args.corpus, args.include_sensitive, args.output_json)
    elif args.action == "search":
        if not args.corpus:
            print(json.dumps({"error": "--corpus is required for search"}), file=sys.stderr)
            sys.exit(1)
        if not args.query:
            print(json.dumps({"error": "--query is required for search"}), file=sys.stderr)
            sys.exit(1)
        corpus_search(args.corpus, args.query, args.include_sensitive, args.output_json)
    elif args.action == "peek":
        if not args.corpus:
            print(json.dumps({"error": "--corpus is required for peek"}), file=sys.stderr)
            sys.exit(1)
        corpus_peek(args.corpus, args.limit, args.include_sensitive, args.output_json)
    elif args.action == "read":
        if not args.corpus:
            print(json.dumps({"error": "--corpus is required for read"}), file=sys.stderr)
            sys.exit(1)
        corpus_read(args.corpus, args.offset, args.limit, args.include_sensitive, args.output_json)
    elif args.action == "get-request":
        if not args.corpus:
            print(json.dumps({"error": "--corpus is required for get-request"}), file=sys.stderr)
            sys.exit(1)
        if not args.request_id:
            print(json.dumps({"error": "--request-id is required for get-request"}), file=sys.stderr)
            sys.exit(1)
        corpus_get_request(args.corpus, args.request_id, args.include_sensitive, args.output_json)
    elif args.action == "get-response":
        if not args.corpus:
            print(json.dumps({"error": "--corpus is required for get-response"}), file=sys.stderr)
            sys.exit(1)
        if not args.request_id:
            print(json.dumps({"error": "--request-id is required for get-response"}), file=sys.stderr)
            sys.exit(1)
        corpus_get_response(args.corpus, args.request_id, args.include_sensitive, args.body_limit, args.output_json)

if __name__ == "__main__":
    main()