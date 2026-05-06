# Skill Scientist Quickstart

## Prerequisites

1. Install required tools: `python3`, `jq`, `bash`
2. Verify the coverage matrix exists at `.claude/skills/skill-scientist/payloads/coverage_matrix.yaml`
3. Verify the evaluation harness exists at `.claude/skills/evaluation-harness/`

## Full Pipeline Walkthrough

### Step 1: Generate Hypotheses

```bash
export OUTDIR=./output/skill-scientist/$(date +%Y-%m-%dT%H%M)
export COVERAGE_MATRIX=.claude/skills/skill-scientist/payloads/coverage_matrix.yaml

python3 .claude/skills/skill-scientist/scripts/generate_hypothesis.py \
  --coverage-matrix $COVERAGE_MATRIX \
  --context $OUTDIR \
  > $OUTDIR/hypotheses.json
```

**Expected output:** `hypotheses.json` containing gap analysis and ranked hypotheses.

**Triage:**
- If `hypotheses_count` > 0: proceed to Step 2.
- If `hypotheses_count` = 0: all gaps are addressed. No further action needed.

### Step 2: Design Experiments

```bash
python3 .claude/skills/skill-scientist/scripts/design_experiment.py \
  --hypotheses-file $OUTDIR/hypotheses.json \
  --context $OUTDIR \
  > $OUTDIR/design_manifest.json
```

**Expected output:** `design_manifest.json` with fixture names, positive/negative control descriptions, and success criteria.

**Triage:**
- If `experiment_count` > 0: proceed to Step 3.
- If `experiment_count` = 0: no hypotheses were parsed. Check `hypotheses.json` format.

### Step 3: Create Fixtures (Manual Step)

For each experiment in the design manifest that has no existing fixture:

```bash
FIXTURE_NAME=fixture-<hypothesis-id>

mkdir -p .claude/skills/evaluation-harness/fixtures/$FIXTURE_NAME
```

Create `test_positive.sh`:
```bash
#!/usr/bin/env bash
# Fixture: <positive control description>
# Expected: exit 0 (detection triggers correctly)

echo "Running $FIXTURE_NAME positive test"
# Insert detection probe here

exit 0
```

Create `test_negative.sh`:
```bash
#!/usr/bin/env bash
# Fixture: <negative control description>
# Expected: exit 1 (detection does NOT trigger)

echo "Running $FIXTURE_NAME negative test"
# Insert negative verification here

exit 1
```

### Step 4: Run Experiments

```bash
python3 .claude/skills/skill-scientist/scripts/run_experiment.py \
  --design-manifest $OUTDIR/design_manifest.json \
  --context $OUTDIR \
  > $OUTDIR/results_manifest.json
```

**Expected output:** `results_manifest.json` with per-experiment pass/fail results.

**Triage:**
- If `fixtures_found` < `total_experiments`: create missing fixtures (Step 3) and re-run.
- If all fixtures found: proceed to Step 5.

### Step 5: Review Results

```bash
python3 .claude/skills/skill-scientist/scripts/review_experiment.py \
  --results-manifest $OUTDIR/results_manifest.json \
  --context $OUTDIR \
  > $OUTDIR/review_report.json
```

**Expected output:** `review_report.json` with scored results and pass/fail determination.

**Triage:**
- If `passed_count` > 0: proceed to Step 6.
- If `passed_count` = 0: all experiments need revision. Check `results_manifest.json` for error details.

### Step 6: Generate Promotion Proposals

```bash
python3 .claude/skills/skill-scientist/scripts/promote_skill_update.py \
  --review-report $OUTDIR/review_report.json \
  --context $OUTDIR \
  > $OUTDIR/promotion_report.json
```

**Expected output:** `promotion_report.json` with target skills, file modifications, and impact estimates.

### Step 7: Review and Approve

1. Open `promotion_report.json`
2. For each proposal:
   - Review the `diff_description`
   - Confirm `target_skill` is in scope
   - Verify `impact_estimate` is plausible
3. Approved proposals can be manually applied to the target skill
4. Rejected proposals should be documented with rejection reason

## Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `hypotheses_count` = 0 | All gaps already covered or matrix empty | Verify `coverage_matrix.yaml` has missing entries |
| `fixtures_found` < `total_experiments` | Fixtures not yet created | Run Step 3 for missing fixtures |
| `positive_passed` = false | Detection probe not working | Check stdout for error messages, debug `test_positive.sh` |
| `negative_passed` = false | Probe triggering on safe input | Adjust detection threshold, add stronger negative assertions |
| `normalized_score` < 7.0 | Multiple scoring dimensions failed | Review individual dimension scores in review_report.json |

## Quick Re-Run

To re-run the full pipeline after fixture updates:

```bash
python3 .claude/skills/skill-scientist/scripts/run_experiment.py \
  --design-manifest $OUTDIR/design_manifest.json \
  --context $OUTDIR \
  > $OUTDIR/results_manifest.json && \
python3 .claude/skills/skill-scientist/scripts/review_experiment.py \
  --results-manifest $OUTDIR/results_manifest.json \
  --context $OUTDIR \
  > $OUTDIR/review_report.json && \
python3 .claude/skills/skill-scientist/scripts/promote_skill_update.py \
  --review-report $OUTDIR/review_report.json \
  --context $OUTDIR \
  > $OUTDIR/promotion_report.json
```