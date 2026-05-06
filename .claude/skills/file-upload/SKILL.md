# File Upload

## Overview
File upload vulnerabilities — extension bypass, content-type spoofing, magic byte bypass, path traversal, polyglot files, SVG injection

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `file-upload`
- Severity range: `medium`, `high`, `critical`
- Required tools: `curl`, `ffuf`, `python3`, `nuclei`, `playwright`, `openssl`
- Expected input files: `all_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `upload-fuzz` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `upload-fuzz` | Fuzz a known upload endpoint with extension, magic-byte, and MIME variants. | `.claude/skills/file-upload/scripts/upload_fuzzer.py` | `$OUTDIR/file-upload/fuzz/findings.jsonl` | `$OUTDIR/file-upload/fuzz/evidence/` |
| `svg-payloads` | Generate SVG XSS, XXE, and SSRF payload files for manual upload testing. | `.claude/skills/file-upload/scripts/svg_xxe_generator.py` | `$OUTDIR/file-upload/svg/findings.jsonl`<br>`$OUTDIR/file-upload/svg/` | `$OUTDIR/file-upload/svg/evidence/` |
| `polyglot-payload` | Generate one polyglot file with an operator-supplied payload string. | `.claude/skills/file-upload/scripts/polyglot_factory.py` | `$OUTDIR/file-upload/polyglot/payload.*` | `$OUTDIR/file-upload/polyglot/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `webshell_access`: Curl response showing PHP shell command execution
- `svg_xss`: Playwright screenshot showing SVG script alert popup
- `traversal_write`: ls output showing file written outside uploads dir

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-BUSL-08`
