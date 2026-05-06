# Rce

## Overview
Remote Code Execution — command injection, SSTI, insecure deserialization, LFI to RCE, eval injection, expression language injection

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `rce`
- Severity range: `high`, `critical`
- Required tools: `curl`, `ffuf`, `python3`, `nuclei`, `sqlmap`, `openssl`, `jq`
- Expected input files: `parameterized_urls.txt`, `all_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `command-injection` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `command-injection` | Detect command injection across URL parameters with optional OAST callbacks. | `.claude/skills/rce/scripts/cmd_injection_fuzzer.py` | `$OUTDIR/rce/cmdi/findings.jsonl` | `$OUTDIR/rce/cmdi/evidence/` |
| `ssti-detection` | Detect server-side template injection in parameterized URLs. | `.claude/skills/rce/scripts/ssti_detector.py` | `$OUTDIR/rce/ssti/findings.jsonl` | `$OUTDIR/rce/ssti/evidence/` |
| `lfi-probe` | Probe parameterized URLs for local file inclusion and wrapper exposure. | `.claude/skills/rce/scripts/lfi_probe.py` | `$OUTDIR/rce/lfi/findings.jsonl` | `$OUTDIR/rce/lfi/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `cmdi_poc`: Single curl one-liner executing id/whoami
- `ssti_proof`: Payload and response showing template code execution
- `lfi_rce`: Log poisoning trace with PHP code execution

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-INPV-12`, `WSTG-INPV-14`
