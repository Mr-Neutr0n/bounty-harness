# Ai Llm

## Overview
AI/LLM Security Testing — prompt injection, tool abuse, output handling, RAG poisoning, MCP server attacks, training data extraction

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `ai-llm`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `curl`, `jq`, `python3`, `httpx`
- Expected input files: `live_hosts.txt`, `llm_api_paths.txt`, `mcp_endpoints.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `surface-discovery` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `surface-discovery` | Discover LLM endpoints, MCP servers, and chatbot surfaces | `.claude/skills/ai-llm/scripts/llm_surface_mapper.py` | `$OUTDIR/ai-llm/surface_findings.jsonl`<br>`$OUTDIR/ai-llm/surface.json`<br>`$OUTDIR/ai-llm/mcp_endpoints.txt` | `$OUTDIR/ai-llm/surface/evidence/` |
| `prompt-injection` | Test direct and indirect prompt injection, jailbreak attempts | `.claude/skills/ai-llm/scripts/prompt_injection_runner.py` | `$OUTDIR/ai-llm/prompt_injection_findings.jsonl` | `$OUTDIR/ai-llm/prompt_injection/evidence/` |
| `tool-abuse` | Test excessive agency, tool/function calling abuse, plugin exploitation | `.claude/skills/ai-llm/scripts/tool_abuse_tester.py` | `$OUTDIR/ai-llm/tool_abuse_findings.jsonl` | `$OUTDIR/ai-llm/tool_abuse/evidence/` |
| `output-handling` | Test if LLM output is rendered unsanitized (XSS, SSRF via injection) | `.claude/skills/ai-llm/scripts/output_handling_tester.py` | `$OUTDIR/ai-llm/output_handling_findings.jsonl` | `$OUTDIR/ai-llm/output_handling/evidence/` |
| `rag-poison` | Test RAG pipeline poisoning via document upload or URL injection | `.claude/skills/ai-llm/scripts/rag_poison_tester.py` | `$OUTDIR/ai-llm/rag_poison_findings.jsonl` | `$OUTDIR/ai-llm/rag_poison/evidence/` |
| `mcp-abuse` | Test MCP server for tool discovery, auth bypass, argument injection | `.claude/skills/ai-llm/scripts/mcp_fuzzer.py` | `$OUTDIR/ai-llm/mcp_findings.jsonl` | `$OUTDIR/ai-llm/mcp/evidence/` |
| `data-extraction` | Extract system prompts, training data, PII from LLM | `.claude/skills/ai-llm/scripts/data_extraction.py` | `$OUTDIR/ai-llm/data_extraction_findings.jsonl` | `$OUTDIR/ai-llm/data_extraction/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `llm_response_dump`: Full LLM response body saved as JSON
- `baseline_comparison`: Diff between baseline and injected response
- `curl_poc`: Reproducible curl command with payload
- `screenshot`: Screenshot of chat widget showing injected output

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INPV-14`, `WSTG-CLNT-01`
