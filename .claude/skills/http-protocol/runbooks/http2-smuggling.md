# HTTP/2 Downgrade Smuggling Runbook

## Purpose
Detect HTTP/2 downgrade smuggling where an HTTP/2 frontend rewrites requests to HTTP/1.1 for the backend, and injectable headers like Content-Length or Transfer-Encoding survive the downgrade conversion.

## Prerequisites
- Target supports HTTP/2 (check with `curl --http2 -sI https://TARGET`)
- Python 3.9+ with `requests` library
- `h2load` (optional, for timing-based detection)
- `curl` with HTTP/2 support (modern builds)

## Variables
| Variable | Description |
|----------|-------------|
| `TARGET` | Target hostname/URL |
| `OUTDIR` | Output directory |

## Commands

### 1. H2.CL Test (HTTP/2 with Content-Length: 0 injection)
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode h2-cl \
  --output $OUTDIR/http-protocol/smuggling/h2cl_findings.jsonl
```

### 2. H2.TE Test (HTTP/2 with Transfer-Encoding: chunked injection)
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode h2-te \
  --output $OUTDIR/http-protocol/smuggling/h2te_findings.jsonl
```

### 3. Both H2 Modes
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode h2 \
  --output $OUTDIR/http-protocol/smuggling/http2_findings.jsonl
```

### 4. Timing-Based Detection with h2load
```bash
timeout 30 h2load -n 50 -c 10 -m 1 "https://TARGET/" 2>&1 | tee $OUTDIR/http-protocol/smuggling/h2load_baseline.txt
```

### 5. Curl H2 Smuggling Test
```bash
curl -sS -o /dev/null -w 'HTTP %{http_code} — Time: %{time_total}s\n' \
  --http2-prior-knowledge \
  -H "Content-Length: 0" \
  "https://TARGET/"
```

### 6. ALPN Negotiation Check
```bash
curl -sI --http2 -v "https://TARGET/" 2>&1 | grep -i "alpn\|HTTP/2\|h2"
```

## Expected Output

### Successful H2.CL:
```json
{
  "smuggling_type": "H2.CL",
  "frontend_parser": "HTTP/2",
  "backend_parser": "HTTP/1.1",
  "success": true,
  "time_differential": 9.5,
  "evidence": "Request hung for 9.5s — possible H2.CL smuggling"
}
```

### Successful H2.TE:
```json
{
  "smuggling_type": "H2.TE",
  "frontend_parser": "HTTP/2",
  "backend_parser": "HTTP/1.1",
  "success": true,
  "status_code": 400,
  "evidence": "Status 400 with injected TE headers"
}
```

## Triage Guide

| Result | Action |
|--------|--------|
| Request hangs > 5s with `Content-Length: 0` | H2.CL confirmed — backend consumed body as next request |
| 400 or 502 with TE injection | H2.TE likely — TE header survived downgrade |
| Normal response time with injected headers | No H2 smuggling — headers stripped |
| ALPN shows `h2` but curl fails | Intermediary may be handling H2 differently |
| Server uses HTTP/3 (QUIC) | H2 downgrade not applicable directly — try alt protocols |

## Severity: Critical (CVSS 9.5+)
HTTP/2 downgrade smuggling affects ALL users behind the frontend and is persistent. Enables complete request hijacking across sessions. Frontend may be shared across many backends.