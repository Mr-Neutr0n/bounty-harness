# Surface Discovery Runbook

## Purpose
Map the LLM attack surface: discover LLM API endpoints, chatbot widgets, MCP servers, and AI integrations across the target infrastructure.

## Prerequisites
- `OUTDIR/live_hosts.txt` — file with live host URLs from recon workflow
- Python 3.10+ with `requests` library
- `curl` and `rg` (ripgrep) available on PATH

## Variables
| Variable | Source | Description |
|----------|--------|-------------|
| `OUTDIR` | `.bb/context.env` | Output directory from recon |
| `CONTEXT` | `.bb/context.json` | Run context and auth configuration |
| `TARGET` | User input | Primary target domain |

## Command

### Step 1 — Basic path probing
```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

for path in /v1/chat/completions /api/generate /chat /completions /api/ask /api/llm /ai /copilot /api/v1/chat /v1/completions /api/v1/llm /query /ask; do
  while read host; do
    resp=$(curl -s -o /dev/null -w '%{http_code}' "${host}${path}" --max-time 5 2>/dev/null)
    if [ "$resp" != "000" ] && [ "$resp" != "404" ]; then
      echo "${host}${path} | $resp" >> $OUTDIR/ai-llm/llm_api_paths.txt
    fi
  done < $OUTDIR/live_hosts.txt
done
```

### Step 2 — Deep surface mapping
```bash
python3 .claude/skills/ai-llm/scripts/llm_surface_mapper.py \
  --urls $OUTDIR/live_hosts.txt \
  --context .bb/context.json \
  --output $OUTDIR/ai-llm/surface_findings.jsonl
```

### Step 3 — MCP endpoint discovery
```bash
for host in $(cat $OUTDIR/live_hosts.txt); do
  for mcp_path in /.well-known/mcp /mcp /api/mcp /v1/mcp; do
    resp=$(curl -s -X POST "${host}${mcp_path}" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
      --max-time 5 2>/dev/null)
    if echo "$resp" | rg -q '"tools"|"result"'; then
      echo "${host}${mcp_path}" >> $OUTDIR/ai-llm/mcp_endpoints.txt
    fi
  done
done
```

## Expected Output

| File | Contents |
|------|----------|
| `$OUTDIR/ai-llm/llm_api_paths.txt` | URL + HTTP status for each LLM path probe |
| `$OUTDIR/ai-llm/surface_findings.jsonl` | Structured findings: detected endpoints, LLM indicators, response analysis |
| `$OUTDIR/ai-llm/surface.json` | Aggregated surface map with endpoint types and detection evidence |
| `$OUTDIR/ai-llm/mcp_endpoints.txt` | Confirmed MCP server endpoints |

Each JSONL finding line includes: `url`, `llm_indicator`, `detection_type`, `endpoint_type`, `response_indicators`, `suggested_workflow`.

## Triage Guide

| Observation | Meaning | Action |
|-------------|---------|--------|
| Endpoint returns 200 with JSON body containing `choices` | OpenAI-compatible API found | Proceed to W2.1 for direct injection |
| Endpoint returns 200 with `content` field (Anthropic-style) | Anthropic-compatible API found | Proceed to W2.2 for Anthropic-style injection |
| HTML page containing "chatbot" or "assistant" widget | Chatbot UI detected | Check for API endpoints in JS, proceed to W2.3 |
| MCP endpoint returns valid JSON-RPC response | MCP server found | Proceed to W6 for MCP abuse |
| All paths return 404/000 | No obvious LLM surface | Try POST-based discovery or skip to output-handling if chatbot widget exists |
| Response body contains "as an AI language model" | LLM response pattern detected | High confidence — mark endpoint as confirmed LLM |
| `text/event-stream` content-type returned | Streaming/SSE endpoint | Check for `data: [DONE]` streaming pattern |
| 403/401 returned on API paths | Auth-gated LLM | Document auth mechanism, attempt key leakage via other endpoints |