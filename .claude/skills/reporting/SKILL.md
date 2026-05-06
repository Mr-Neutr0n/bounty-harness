# Reporting

## Overview
Bug bounty report generation, CVSS scoring, evidence packaging, platform-specific exports

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `reporting`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `python3`, `curl`, `jq`, `date`
- Expected input files: `findings.jsonl`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `generate-single` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `generate-single` | Generate a single finding report from evidence | `.claude/skills/reporting/scripts/report_generator.py` | `$OUTDIR/reports/report.md` | `$OUTDIR/reports/evidence/` |
| `cvss-score` | Calculate CVSS v3.1 score for a finding | `.claude/skills/reporting/scripts/cvss_calc.py` | `$OUTDIR/reports/cvss.json` | `$OUTDIR/reports/evidence/` |
| `batch-generate` | Generate reports from nuclei/skill JSONL output | `.claude/skills/reporting/scripts/batch_reporter.py` | `$OUTDIR/reports/summary.md`<br>`$OUTDIR/reports/findings/` | `$OUTDIR/reports/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `cvss`: CVSS vector string and breakdown
- `report`: Markdown report with all required sections
- `evidence_package`: Tar.gz with evidence + reports

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP mappings: none listed in `skill.yaml`.
