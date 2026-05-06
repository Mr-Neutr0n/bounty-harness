# Technique Knowledge Base

## Overview
Structured knowledge base of every attack technique. Stores preconditions, detection signals, payload families, false-positive rules, required evidence, severity mappings, and standards references (WSTG, ASVS, API Top 10, VRT, CWE). The planner uses this KB to determine WHICH techniques apply to WHICH surfaces before running any tooling.

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `technique-kb`
- Severity range: `info`, `low`, `medium`, `high`, `critical`
- Required tools: `python3`, `jq`
- Expected input files: none
- Scope check: not applicable — read-only technique definitions.

## Workflow Selection
- Start with `validate` to verify all technique YAML files against the schema.
- Use `match` to find techniques applicable to a specific domain profile.
- Use `search` to query by keyword, category, severity, or standard ID.
- Runbooks: use `runbooks/`.
- If a workflow has no script reference, treat it as a manual or tool-native workflow.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `validate` | Validate all technique YAML files against the canonical schema. | `.claude/skills/technique-kb/scripts/technique_validator.py` | `$OUTDIR/technique-kb/validation.txt` | `$OUTDIR/technique-kb/evidence/` |
| `match` | Match techniques to domain archetypes and attack surfaces. | `.claude/skills/technique-kb/scripts/technique_matcher.py` | `$OUTDIR/technique-kb/matches.json` | `$OUTDIR/technique-kb/evidence/` |
| `search` | Search techniques by keyword, category, severity, or standard ID. | `.claude/skills/technique-kb/scripts/technique_search.py` | `$OUTDIR/technique-kb/search_results.json` | `$OUTDIR/technique-kb/evidence/` |

## Evidence Required
- Not applicable — this skill produces technique matching data, not vulnerability findings.
- All techniques include standards mappings, detection signals, and false-positive rules.

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- Technique schema: `technique_schema.yaml`
- Standards: WSTG, ASVS, API Top 10, VRT, CWE
