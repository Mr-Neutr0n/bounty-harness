# Evaluation Harness

## Overview
Lab fixture framework for validating bug bounty skills. Each fixture is a minimal vulnerable-by-design application that a fat skill must detect. Every fixture has a positive control (must detect) and a negative control (must not fire). Skills become measurable: precision, recall, false-positive rate, evidence completeness, runtime. The quality gate for all skill improvements.

## Quick Reference
- Skill: `evaluation-harness`
- Severity range: `info`
- Required tools: `python3`, `jq`, `docker`, `curl`
- Expected input files: none

## Workflow Selection
- Start with `run-skill-test` to test a specific skill against its fixtures.
- Run `generate-matrix` periodically to get a full health dashboard.
- Run `benchmark-runner` to compare performance before/after skill changes.
- Runbooks: use `runbooks/`.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `run-skill-test` | Test a specific skill against its lab fixtures. | `.claude/skills/evaluation-harness/scripts/run_skill_test.py` | `$OUTDIR/recon/eval/results_manifest.json` | `$OUTDIR/recon/eval/evidence/` |
| `generate-matrix` | Generate a full evaluation matrix across all skills and fixtures. | `.claude/skills/evaluation-harness/scripts/generate_matrix.py` | `$OUTDIR/recon/eval/eval_matrix.json` | `$OUTDIR/recon/eval/evidence/` |
| `benchmark-runner` | Run benchmark comparing current skill performance to previous baseline. | `.claude/skills/evaluation-harness/scripts/benchmark_runner.py` | `$OUTDIR/recon/eval/benchmark.json` | `$OUTDIR/recon/eval/evidence/` |

## Evidence Required
- Every test run has timestamp, skill version, fixture version.
- Positive control must trigger detection.
- Negative control must not trigger detection.
- Evidence completeness is scored per fixture.

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- Inspired by OpenAI Evals, UK AISI Inspect, OWASP testing guides