# Runbook: Review Plan

## Purpose
Review a generated plan for completeness, safety, and execution readiness before running any workflows.

## Prerequisites
- Generated plan JSON (`plan.json`)
- Access to scope document for the program
- Familiarity with the target's technology stack and business context

## Steps

### 1. Visualize the plan
```bash
python3 .claude/skills/planner/scripts/plan_visualizer.py \
  --plan plan.json \
  --output plan.md
```

### 2. Validate the plan
```bash
python3 .claude/skills/planner/scripts/plan_validator.py \
  --plan plan.json
```

### 3. Review Checklist

#### Scope Alignment
- [ ] Every CRITICAL item targets an explicitly in-scope asset
- [ ] No item targets out-of-scope domains, subdomains, or IP ranges
- [ ] Third-party integrations are correctly scoped per program rules

#### Safety Review
- [ ] All items marked `INTRUSIVE` have explicit safety gates configured
- [ ] All items marked `DESTRUCTIVE` have rollback plans or are excluded
- [ ] `RATE-LIMITED` items respect the program's rate limit policy
- [ ] Items requiring auth have auth available or are deferred

#### Completeness Check
- [ ] All detected surfaces have at least one matching technique
- [ ] All archetype categories have relevant techniques in the plan
- [ ] Coverage gaps noted in the prior plan have been addressed

#### Execution Readiness
- [ ] Tools for CRITICAL items are available in PATH
- [ ] Auth credentials for items requiring auth are stored and tested
- [ ] Evidence directory structure exists for the target

### 4. Adjustments

If the plan needs adjustment, re-run generate_plan.py with appropriate filters:

```bash
python3 .claude/skills/planner/scripts/generate_plan.py \
  --domain-profile domain.json \
  --techniques-dir .claude/skills/technique-kb/techniques/ \
  --exclude-intrusive \
  --output plan_safe.json
```

## Decision
| Review Outcome | Action |
|----------------|--------|
| Plan passes all checks | Proceed to `execute-plan.md` |
| Minor adjustments needed | Adjust domain profile and regenerate |
| Major gaps in coverage | Run additional recon or technique development, then re-generate |
| Scope violations found | Fix scope document or adjust technique surface mappings |

## Next Step
After plan is approved, proceed to `execute-plan.md`.