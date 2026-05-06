# Cors Csrf

## Overview
CORS misconfiguration and CSRF testing — origin reflection, cross-origin attacks, SameSite bypass, postMessage validation

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `cors-csrf`
- Severity range: `low`, `medium`, `high`
- Required tools: `curl`, `ffuf`, `python3`, `playwright`
- Expected input files: `live_urls.txt`, `all_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `cors-matrix` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `cors-matrix` | Test CORS origin reflection, credentialed CORS, and null-origin cases. | `.claude/skills/cors-csrf/scripts/cors_matrix_tester.py` | `$OUTDIR/cors/findings.jsonl` | `$OUTDIR/cors/evidence/` |
| `csrf-poc` | Generate a CSRF proof-of-concept for a known state-changing endpoint. | `.claude/skills/cors-csrf/scripts/csrf_poc_generator.py` | `$OUTDIR/csrf/poc.html` | `$OUTDIR/csrf/evidence/` |
| `samesite-bypass` | Analyze SameSite cookie attributes and bypass scenarios. | `.claude/skills/cors-csrf/scripts/samesite_bypass_tester.py` | `$OUTDIR/samesite/findings.jsonl` | `$OUTDIR/samesite/evidence/` |
| `postmessage` | Audit postMessage handlers for missing origin checks and dangerous sinks. | `.claude/skills/cors-csrf/scripts/postmessage_auditor.py` | `$OUTDIR/postmessage/findings.jsonl` | `$OUTDIR/postmessage/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `cors_poc`: CORS exploit HTML demonstrating cross-origin data theft
- `csrf_poc`: CSRF exploit HTML auto-submitting state-changing request
- `postmessage_poc`: HTML page exploiting missing origin check in postMessage listener

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-CLNT-07`, `WSTG-SESS-05`
