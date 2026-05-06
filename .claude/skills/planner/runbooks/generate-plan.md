# Runbook: Generate Plan

## Purpose
Produce a domain-driven ranked test plan from domain profile + technique catalog + coverage data.

## Prerequisites
- Domain profile JSON (output of `domain-model/scripts/archetype_classifier.py`)
- Technique catalog (YAML files in `technique-kb/techniques/`)
- Optional: Coverage matrix JSON (output of prior plan-vs-results)

## Command

```bash
python3 .claude/skills/planner/scripts/generate_plan.py \
  --domain-profile /path/to/domain_profile.json \
  --techniques-dir .claude/skills/technique-kb/techniques/ \
  --coverage-matrix /path/to/coverage.json \
  --output output/TARGET/plan.json
```

## Flags
| Flag | Purpose | Default |
|------|---------|---------|
| `--domain-profile` | Path to domain profile JSON | Required |
| `--techniques-dir` | Path to technique YAML directory | Required |
| `--coverage-matrix` | Path to coverage matrix JSON | None (all treated as gaps) |
| `--output` | Output path for plan JSON | Required |
| `--exclude-intrusive` | Exclude intrusive techniques | False |
| `--exclude-destructive` | Exclude data-modifying techniques | False |

## Expected Output
A plan JSON file following `plan_schema.yaml` containing:
- Metadata with target, program, generation timestamp, coverage percentage
- Domain profile snapshot (archetypes + surfaces)
- Ranked plan items with scores, rationales, preconditions, safety flags, expected signals
- Summary stats (by priority, auth requirements, safe-to-run count)

## Triage
| Output | Decision |
|--------|----------|
| `plan_items` is empty | No techniques matched — the technique catalog may be empty or domain profile has no surfaces. Run recon first, then re-generate. |
| High proportion of LOW items | Domain profile lacks enough surface matches. Consider expanding recon or accepting lower confidence. |
| High proportion of CRITICAL items | Target is high-impact with many matching surfaces. Prioritize execution immediately. |

## Next Step After Generate
Run `plan_visualizer.py` to create a human-readable version, then proceed to `review-plan.md`.