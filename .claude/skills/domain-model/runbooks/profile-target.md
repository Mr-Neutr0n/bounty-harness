# Profile Target Runbook — Domain Profile Report

## Purpose
Generate a comprehensive markdown report from the archetype classification and surface mapping, providing a prioritized testing order and recommended skill-loading sequence.

## Prerequisites
- `classify` workflow must have completed (archetypes.json exists).
- `map-surfaces` workflow must have completed (surfaces.json exists).

## Execution

```bash
mkdir -p $OUTDIR/domain-model && \
python3 .claude/skills/domain-model/scripts/domain_report.py \
  --target $TARGET \
  --archetypes $OUTDIR/domain-model/archetypes.json \
  --surfaces $OUTDIR/domain-model/surfaces.json \
  --output $OUTDIR/domain-model/domain-profile.md
```

## Expected Output
- `$OUTDIR/domain-model/domain-profile.md` — Markdown report with full domain profile.

## Report Sections
1. **Archetype Classification** — table of matched archetypes with confidence scores and high-value actions.
2. **Evidence Summary** — per-archetype evidence strings that led to the classification.
3. **Attack Surfaces Detected** — table of surfaces with confidence, auth, and intrusiveness.
4. **Priority Testing Order** — three tiers: Immediate (high), Secondary (medium), Follow-up (inferred).
5. **Recommended Skill Loading Order** — deduplicated ordered list of skills to load.

## Using the Report for Dispatch
- Read the "Priority Testing Order" section.
- For each surface in Immediate tier, load the listed skills in order.
- Follow each skill's SKILL.md decision tree sub-workflow.
- Collect evidence as findings are confirmed (curl, screenshots, timestamps).
- Return to the domain profile after completing each tier.

## Next Step
After profile completes, the LLM should begin loading vulnerability-class skills in the order specified by the report.