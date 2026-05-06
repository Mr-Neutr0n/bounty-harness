# Nuclei Scanner

## Overview
Nuclei template-based vulnerability scanning — severity profiles, category scans, authenticated scanning, DAST mode, custom templates

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `nuclei-scanner`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `nuclei`, `httpx`, `curl`, `python3`, `jq`
- Expected input files: `live_urls.txt`, `all_urls.txt`, `parameterized_urls.txt`, `js_files.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `standard-scan` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `standard-scan` | Run the nuclei wrapper against a live target list with a bounded standard profile. | `.claude/skills/nuclei-scanner/scripts/nuclei_runner.py` | `$OUTDIR/nuclei/findings.jsonl` | `$OUTDIR/nuclei/evidence/` |
| `validate-findings` | Validate nuclei JSONL findings with curl-based verification. | `.claude/skills/nuclei-scanner/scripts/findings_validator.py` | `$OUTDIR/nuclei/validated_findings.jsonl` | `$OUTDIR/nuclei/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `nuclei_jsonl`: Full nuclei JSONL output for all findings
- `validation_curl`: Curl output confirming the nucleus-detected vulnerability

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP mappings: none listed in `skill.yaml`.
