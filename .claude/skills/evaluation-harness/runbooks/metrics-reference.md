# Metrics Reference

## Core metrics

### True Positive (TP)
A positive control test that passes. The fixture's vulnerability is correctly detected.

### True Negative (TN)
A negative control test that passes. The fixture does not trigger a false detection on benign input.

### False Positive (FP)
A negative control test that fails. The skill incorrectly fires on benign input.

### False Negative (FN)
A positive control test that fails. The skill misses a real vulnerability.

## Derived metrics

### Precision
```
Precision = TP / (TP + FP)
```
What fraction of detections are real vulnerabilities. High precision means low noise.

- 1.0: Every detection is a real vuln
- 0.5: Half of detections are false alarms
- 0.0: All detections are false

### Recall
```
Recall = TP / (TP + FN)
```
What fraction of real vulnerabilities are detected. High recall means comprehensive coverage.

- 1.0: Every real vuln is found
- 0.5: Half of vulns are missed
- 0.0: No vulns detected

### F1 Score
```
F1 = 2 × Precision × Recall / (Precision + Recall)
```
Harmonic mean of precision and recall. Balances completeness against noise. The primary metric for skill quality.

- 1.0: Perfect precision and recall
- 0.8: Good balance
- 0.5: Significant issues
- 0.0: Skill is broken

### False Positive Rate (FPR)
```
FPR = FP / (FP + TN)
```
How often the skill fires on benign input. Lower is better.

- 0.0: No false positives
- 0.1: 10% false alarm rate
- 0.5: Half of benign inputs trigger detection

### Accuracy
```
Accuracy = (TP + TN) / (TP + TN + FP + FN)
```
Overall correct classification rate. Less useful than F1 for unbalanced datasets.

### Health Score
```
Health = F1 × 10
```
Linear mapping of F1 to a 0-10 scale for dashboard display.

- 8.0–10.0: Production ready
- 5.0–7.9: Needs improvement
- 0.0–4.9: Critical issues

## Benchmark metrics

### Delta (Δ)
```
Δ_metric = current_metric − baseline_metric
```
Positive delta = improvement. Negative delta = regression.

### Regression threshold
Any metric drop exceeding 5% or a health score drop exceeding 0.5 points is flagged as a regression.

### Improvement threshold
Any metric increase exceeding 5% or a health score increase exceeding 0.5 points is flagged as an improvement.

## Runtime budget

Each test has a maximum runtime of 30 seconds (controlled by `run_skill_test.py`). If a fixture exceeds this, it is marked as timed out and counted as a failure.

## Evidence completeness

Every test result records:
- Fixture name and skill tested
- Vulnerability class and severity
- Timestamp (UTC ISO 8601)
- Positive control output and pass/fail
- Negative control output and pass/fail
- Runtime in seconds
- Any errors encountered

Missing evidence (no output captured, server crash, port conflict) degrades the fixture to a failure.

## Interpreting results

| Scenario | Precision | Recall | F1 | Diagnosis |
| --- | --- | --- | --- | --- |
| Perfect | 1.0 | 1.0 | 1.0 | Skill is ready |
| Noise only | 0.5 | 1.0 | 0.67 | Skill fires too broadly — add filters |
| Misses only | 1.0 | 0.5 | 0.67 | Skill is too narrow — expand patterns |
| Broken | 0.0 | 0.0 | 0.0 | Skill detects nothing — check logic |
| All pass | 1.0 | 0.5 | 0.67 | Positive controls are likely too easy |
| All fail | 0.0 | 0.0 | 0.0 | Fixture or environment issue |