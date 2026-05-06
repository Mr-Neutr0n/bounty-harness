# Coverage

## Overview
Tracks what the bug bounty toolkit covers and what is missing. The coverage ledger maps every standard testing item (WSTG, ASVS, API Top 10, Bugcrowd VRT) to existing skills, scripts, and workflows — then produces a measurable coverage report. No more vibes.

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `coverage`
- Severity range: `info`
- Required tools: `python3`
- Expected input files: `coverage_matrix.yaml`
- Scope check: not applicable — read-only coverage analysis.

## Workflow Selection
- Start with `calculate` for raw coverage percentages.
- Run `find-gaps` to identify highest-priority missing coverage.
- Run `report` for a full markdown dashboard.
- Runbooks: use `runbooks/`.
- If a workflow has no script reference, treat it as a manual or tool-native workflow.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `calculate` | Compute coverage percentages from matrix. | `.claude/skills/coverage/scripts/coverage_calculator.py` | `$OUTDIR/coverage/stats.json` | `$OUTDIR/coverage/evidence/` |
| `find-gaps` | Identify highest-priority missing coverage. | `.claude/skills/coverage/scripts/gap_finder.py` | `$OUTDIR/coverage/gaps.json` | `$OUTDIR/coverage/evidence/` |
| `report` | Generate full markdown coverage dashboard. | `.claude/skills/coverage/scripts/coverage_report.py` | `$OUTDIR/coverage/coverage_report.md` | `$OUTDIR/coverage/evidence/` |

## Evidence Required
- No runtime evidence needed. Coverage reports are self-contained artifacts.
- Timestamps are embedded in generated files via ISO 8601 UTC.
- Matrix includes last_updated date for provenance tracking.

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG v5.0 — Web Security Testing Guide
- OWASP ASVS v5.0 — Application Security Verification Standard
- OWASP API Security Top 10 (2023)
- Bugcrowd Vulnerability Rating Taxonomy (VRT)
- `.claude/skills/*/skill.yaml` — actual implemented workflows