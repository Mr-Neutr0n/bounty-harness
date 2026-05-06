# Race Condition

## Overview
Race condition detection — coupon/voucher bypass, TOCTOU, multi-step race, rate limit race, database race conditions

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `race-condition`
- Severity range: `medium`, `high`, `critical`
- Required tools: `curl`, `python3`, `ffuf`
- Expected input files: `all_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `concurrent-requests` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `concurrent-requests` | Send concurrent requests to a selected endpoint to detect race windows. | `.claude/skills/race-condition/scripts/race_engine.py` | `$OUTDIR/race/concurrent/results.json` | `$OUTDIR/race/concurrent/evidence/` |
| `timing-token` | Detect timestamp-based token collisions via concurrent generation requests. | `.claude/skills/race-condition/scripts/timing_token_exploit.py` | `$OUTDIR/race/timing/findings.jsonl` | `$OUTDIR/race/timing/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `coupon_race`: Response showing duplicate coupon applications
- `double_spend`: Balance change showing double spend per single cart
- `inventory_race`: Negative inventory count after concurrent purchases

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP WSTG: `WSTG-BUSL-05`
