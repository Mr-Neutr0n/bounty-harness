# Xss

## Overview
Cross-Site Scripting detection — reflected, stored, DOM, blind, CSP bypass, mXSS, and WAF bypass

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `xss`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `curl`, `ffuf`, `dalfox`, `arjun`, `nuclei`, `python3`, `playwright`, `wafw00f`
- Expected input files: `parameterized_urls.txt`, `all_urls.txt`, `js_files.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `reflected` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `reflected` | Detect reflected XSS in parameterized URLs. | `.claude/skills/xss/scripts/xss_reflected_probe.py` | `$OUTDIR/xss/reflected/findings.jsonl` | `$OUTDIR/xss/reflected/evidence/` |
| `dom` | Scan downloaded JavaScript for DOM XSS sources and sinks. | `.claude/skills/xss/scripts/xss_dom_sink_scanner.py` | `$OUTDIR/xss/dom/findings.jsonl` | `$OUTDIR/xss/dom/evidence/` |
| `csp-analysis` | Fetch and analyze the target page Content-Security-Policy. | `.claude/skills/xss/scripts/csp_analyzer.py` | `$OUTDIR/xss/csp/analysis.txt` | `$OUTDIR/xss/csp/evidence/` |
| `context-encoder` | Generate encoded variants for an operator-supplied XSS payload. | `.claude/skills/xss/scripts/xss_context_encoder.py` | `$OUTDIR/xss/encoder/payloads.txt` | `$OUTDIR/xss/encoder/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `xss_screenshot`: Playwright screenshot showing alert/script execution
- `poc_html`: HTML PoC page reproducing the XSS
- `dalfox_output`: Dalfox automated XSS scanner findings

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-CLNT-01`, `WSTG-CLNT-02`
