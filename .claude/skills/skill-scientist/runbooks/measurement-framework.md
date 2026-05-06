# Measurement Framework

How to measure skill improvements with precision, recall, F1, and coverage metrics.

## Core Metrics

### Precision
```
Precision = TP / (TP + FP)
```
Proportion of detections that are actual vulnerabilities. High precision means low false positives.

**Measurement:** Compare detections on positive fixtures vs. negative fixtures. Each false detection on a negative fixture reduces precision.

### Recall
```
Recall = TP / (TP + FN)
```
Proportion of actual vulnerabilities that are detected. High recall means low false negatives.

**Measurement:** Compare detections on positive fixtures vs. number of positive fixtures. Each missed detection reduces recall.

### F1 Score
```
F1 = 2 * (Precision * Recall) / (Precision + Recall)
```
Harmonic mean of precision and recall. Balances both dimensions.

**Measurement:** Computed from precision and recall values after running full fixture suite.

### Coverage
```
Coverage = (standards_with_detection / total_standards) * 100
```
Percentage of OWASP WSTG / ASVS standards that have at least one detection workflow.

**Measurement:** Derived from the coverage matrix by counting status=implemented vs. total entries.

---

## Baselines and Comparisons

### Establishing a Baseline

```
bash .claude/skills/skill-scientist/scripts/measure_coverage.sh
```

This script (if present) computes:
1. Current coverage percentage from coverage_matrix.yaml
2. Current active fixture count from evaluation-harness
3. Current passed experiment count from latest review_report.json

### Before/After Comparison

For each promoted skill update:

| Metric | Before | After | Delta | Direction |
| --- | --- | --- | --- | --- |
| Coverage (%) | computed | computed | difference | higher is better |
| Precision | 0-1 scale | 0-1 scale | difference | higher is better |
| Recall | 0-1 scale | 0-1 scale | difference | higher is better |
| F1 | 0-1 scale | 0-1 scale | difference | higher is better |
| Fixtures | count | count | difference | more fixtures = more validated |
| Passed experiments | count | count | difference | more passed = better detection quality |

---

## Measurement Workflow

### 1. Pre-Improvement Snapshot

```bash
python3 .claude/skills/skill-scientist/scripts/snapshot_metrics.py \
  --coverage-matrix payloads/coverage_matrix.yaml \
  --output ./output/metrics/baseline_$(date +%Y%m%d).json
```

Captures: coverage %, fixture counts, latest review scores.

### 2. Apply Improvement

Manual step: apply changes from `promotion_report.json` to target skill files.

### 3. Post-Improvement Re-measurement

```bash
python3 .claude/skills/skill-scientist/scripts/snapshot_metrics.py \
  --coverage-matrix payloads/coverage_matrix.yaml \
  --output ./output/metrics/post_improvement_$(date +%Y%m%d).json
```

### 4. Compare

```bash
python3 .claude/skills/skill-scientist/scripts/diff_metrics.py \
  --baseline ./output/metrics/baseline_20260101.json \
  --current ./output/metrics/post_improvement_20260102.json
```

---

## Experiment-Level Metrics

Per experiment, the review framework already computes:

| Metric | Source | Scale |
| --- | --- | --- |
| Accuracy | `review_report.json` scores.accuracy | 0-10 |
| False Positive Control | `review_report.json` scores.false_positive_control | 0-10 |
| Evidence Completeness | `review_report.json` scores.evidence_completeness | 0-5 |
| Reproducibility | `review_report.json` scores.reproducibility | 0-5 |
| Normalized Score | `review_report.json` normalized_score | 0-10 |
| Pass/Fail | `review_report.json` passed | boolean |

---

## Trend Tracking

Maintain a historical metrics file:

```
output/metrics/history.jsonl
```

Each line is a JSON record:
```json
{"date": "2026-01-01", "coverage_pct": 45.2, "total_fixtures": 32, "passed_experiments": 18, "f1_estimate": 0.72}
```

Compute trends:
```bash
cat output/metrics/history.jsonl | jq -s 'map(.coverage_pct) | [.[-1]-.[0], .[-1]]'
```

---

## Target Thresholds

| Metric | Minimum | Good | Excellent |
| --- | --- | --- | --- |
| Coverage | 50% | 75% | 90%+ |
| Precision | 0.70 | 0.85 | 0.95+ |
| Recall | 0.60 | 0.80 | 0.90+ |
| F1 | 0.65 | 0.82 | 0.92+ |
| Pass Rate | 60% | 80% | 95%+ |
| Fixtures per skill | 2 | 5 | 10+ |

---

## Measurement Anti-Patterns

| Anti-Pattern | Why It's Bad | Fix |
| --- | --- | --- |
| Measuring only coverage without precision | 100% coverage with 10% precision is noise | Always report precision + recall with coverage |
| Fixtures that are too easy | No discrimination signal, everything passes | Design challenging negative controls |
| No negative controls | Can't measure precision or false positive rate | Every experiment MUST have a negative control |
| Single-run scores as truth | Flaky tests inflate/deflate scores | Run 3x minimum, use median |
| Ignoring evidence completeness | Can't audit results, can't reproduce | Require full stdout/stderr capture for every run |