# Modern Browser

## Overview
Modern browser security testing — WebGPU, WASM, XS-Leaks, COOP/COEP/CORP, browser fingerprinting

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `modern-browser`
- Severity range: `info`, `low`, `medium`
- Required tools: `curl`, `python3`, `playwright`, `nuclei`
- Expected input files: `live_urls.txt`, `js_files.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `webgpu-exposure` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `webgpu-exposure` | Detect WebGPU availability and fingerprinting surface | `.claude/skills/modern-browser/scripts/webgpu_probe.py` | `$OUTDIR/modern-browser/webgpu.json` | `$OUTDIR/modern-browser/evidence/` |
| `wasm-audit` | Audit WebAssembly modules for exposed capabilities | `.claude/skills/modern-browser/scripts/wasm_analyzer.py` | `$OUTDIR/modern-browser/wasm.jsonl` | `$OUTDIR/modern-browser/evidence/` |
| `cross-origin-isolation` | Check COOP/COEP/CORP headers and SharedArrayBuffer status | `.claude/skills/modern-browser/scripts/cross_origin_auditor.py` | `$OUTDIR/modern-browser/coi.jsonl` | `$OUTDIR/modern-browser/evidence/` |
| `xsleak-probe` | Test for cross-site leak vulnerabilities | `.claude/skills/modern-browser/scripts/xsleak_probe.py` | `$OUTDIR/modern-browser/xsleak.jsonl` | `$OUTDIR/modern-browser/evidence/` |
| `browser-fingerprint` | Identify browser fingerprinting surface from target headers | No script reference in `skill.yaml` command. | `$OUTDIR/modern-browser/headers.txt` | `$OUTDIR/modern-browser/evidence/` |
| `evidence` | Collect evidence for modern browser findings | No script reference in `skill.yaml` command. | `$EVIDENCE_DIR/modern-browser/` | `$EVIDENCE_DIR/modern-browser/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `webgpu`: Screenshot of navigator.gpu and adapter info
- `wasm_audit`: List of WASM imports/exports with suspicious flags

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-CLNT-01`, `WSTG-CLNT-02`, `WSTG-CLNT-03`, `WSTG-CLNT-12`, `WSTG-CLNT-13`
