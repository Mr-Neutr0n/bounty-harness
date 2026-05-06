# Skill Scientist

## Overview
AI Scientist pattern adapted for bug bounty skill improvement. End-to-end automated pipeline: Hypothesize -> Design -> Run in lab -> Review -> Promote. Generates and validates improvements to existing fat skills by identifying coverage gaps, designing controlled experiments with positive/negative controls, executing against evaluation fixtures, scoring results, and producing promotion proposals. Never modifies production skills without explicit approval.

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `skill-scientist`
- Severity range: `info`
- Required tools: `python3`, `jq`, `bash`
- Expected input files: `.claude/skills/skill-scientist/payloads/coverage_matrix.yaml`
- Scope check: confirm authorization before running experiments or fixture creation.

## Workflow Selection
- Start with `generate-hypothesis` unless a hypothesis file already exists from a prior run.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated outputs.
- If a fixture does not exist, create it manually or use the evaluation-harness skill before re-running `run-experiment`.
- Do NOT run `promote-skill-update` without reviewing the review report scores.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `generate-hypothesis` | Read coverage matrix, find high-priority gaps, output hypotheses. | `.claude/skills/skill-scientist/scripts/generate_hypothesis.py` | `$OUTDIR/hypotheses.json` | `$OUTDIR/evidence/` |
| `design-experiment` | Design controlled experiments with positive/negative controls per hypothesis. | `.claude/skills/skill-scientist/scripts/design_experiment.py` | `$OUTDIR/design_manifest.json` | `$OUTDIR/evidence/` |
| `run-experiment` | Execute experiments against evaluation fixtures, capture pass/fail results. | `.claude/skills/skill-scientist/scripts/run_experiment.py` | `$OUTDIR/results_manifest.json` | `$OUTDIR/evidence/` |
| `review-experiment` | Score experiment results against success criteria, compute pass/fail threshold. | `.claude/skills/skill-scientist/scripts/review_experiment.py` | `$OUTDIR/review_report.json` | `$OUTDIR/evidence/` |
| `promote-skill-update` | Generate promotion proposals for passed experiments, describe required diffs. | `.claude/skills/skill-scientist/scripts/promote_skill_update.py` | `$OUTDIR/promotion_report.json` | `$OUTDIR/evidence/` |

## Evidence Required
- Save all generated JSON artifacts in the output directory.
- Include timestamps, workflow name, and tool versions in every output manifest.
- Store experiment logs (stdout/stderr captures) in the evidence directory.
- Evidence templates from `skill.yaml`:
  - `hypothesis_generated`: `hypotheses.json` with gap IDs and priority levels
  - `experiment_result`: `results_manifest.json` with positive/negative control outcomes
  - `review_passed`: `review_report.json` with normalized score >= 7.0
  - `promotion_ready`: `promotion_report.json` with target skill and diff description

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- Evaluation harness: `.claude/skills/evaluation-harness/`
- Inspired by: SakanaAI AI Scientist pattern (arXiv:2408.06292)