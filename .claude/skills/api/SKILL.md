# Api

## Overview
API security testing — REST/GraphQL/WebSocket/gRPC/SOAP, mass assignment, rate limiting, BOLA/BFLA, swagger/OpenAPI discovery

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `api`
- Severity range: `low`, `medium`, `high`, `critical`
- Required tools: `curl`, `ffuf`, `python3`, `arjun`, `jq`, `katana`, `dalfox`, `sqlmap`
- Expected input files: `api_endpoints.txt`, `all_urls.txt`, `js_files.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `rate-limit` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `rate-limit` | Test API rate limiting on a selected endpoint. | `.claude/skills/api/scripts/rate_limit_tester.py` | `$OUTDIR/api/ratelimit/findings.jsonl` | `$OUTDIR/api/ratelimit/evidence/` |
| `bola-bfla` | Fuzz object IDs on an API resource path with optional cross-account credentials. | `.claude/skills/api/scripts/bola_fuzzer.py` | `$OUTDIR/api/bola/findings.jsonl` | `$OUTDIR/api/bola/evidence/` |
| `graphql` | Map GraphQL schema and run safe introspection/depth checks. | `.claude/skills/api/scripts/graphql_mapper.py` | `$OUTDIR/api/graphql/schema.json`<br>`$OUTDIR/api/graphql/findings.jsonl` | `$OUTDIR/api/graphql/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `mass_assignment`: Registration response showing elevated role assignment
- `bola_response`: API response containing another user's sensitive data
- `swagger_doc`: Discovered swagger/OpenAPI document exposing internal endpoints

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-APIT-01`, `WSTG-APIT-02`, `WSTG-APIT-03`
- OWASP API Top 10: `API1:2023`, `API2:2023`, `API3:2023`, `API4:2023`, `API5:2023`, `API6:2023`, `API7:2023`, `API8:2023`, `API9:2023`, `API10:2023`
