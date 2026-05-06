# Review Criteria

Detailed scoring rubric for experiment review. Each experiment is scored on 4 dimensions.

## Scoring Dimensions

| Dimension | Max Score | Weight | Description |
| --- | --- | --- | --- |
| Accuracy | 10 | 33% | Positive and negative control outcomes |
| False Positive Control | 10 | 33% | Negative control integrity and error rate |
| Evidence Completeness | 5 | 17% | Quality and coverage of captured artifacts |
| Reproducibility | 5 | 17% | Consistency across repeated runs |

**Total:** 0-30 raw score, normalized to 0-10. Pass threshold: >= 7.0.

---

## Accuracy (0-10)

Measures whether the detection probe correctly identifies true positives and avoids false negatives.

| Scenario | Score |
| --- | --- |
| Positive control passed + Negative control passed | 10 |
| Positive control passed + Negative control NOT passed | 5 |
| Positive control NOT passed + Negative control passed | 5 |
| Neither control passed | 0 |
| Positive control passed, negative not run (missing fixture) | 5 |
| Neither script exists | 0 |

### Accuracy Red Flags
- Probe exits 0 on negative fixture (false positive)
- Probe exits non-zero on positive fixture (false negative)
- Probe hangs or times out
- Probe depends on external network state

---

## False Positive Control (0-10)

Measures how well the experiment guards against false positives, starting from a perfect 10 and deducting.

| Deduction | Reason |
| --- | --- |
| -5 | Negative control produced a false positive |
| -1 per error | Each captured error (max 5 errors) |
| -3 | No negative control script exists |
| -2 | Negative control output is empty (silent failure) |

### False Positive Control Red Flags
- Negative fixture triggers the same path as positive fixture
- Detection uses pattern matching that is too broad
- Probe does not distinguish between vulnerable and safe states
- Error count exceeds 5 (score floors at 0)

---

## Evidence Completeness (0-5)

Measures the richness of captured output for auditability and debugging.

| Scenario | Score |
| --- | --- |
| Both positive_output and negative_output captured with content | 5 |
| One output captured, other missing | 3 |
| Both outputs present but empty strings | 2 |
| Neither output captured | 0 |

### Evidence Completeness Red Flags
- stdout capture is truncated
- Exit codes not recorded
- Timestamps not included in output
- No request/response artifacts for HTTP-based probes
- No screenshot for browser-based probes

---

## Reproducibility (0-5)

Measures consistency. In the current implementation, this is a placeholder value.

| Scenario | Score |
| --- | --- |
| Three consecutive runs produce identical results | 5 |
| Two of three runs match | 3 |
| Results vary across runs | 0 |
| Single run only (current default) | 5 |

### Reproducibility Red Flags (Future)
- Flaky results due to timing
- Results depend on network latency
- Stateful fixtures cause test ordering issues
- Parallel execution produces race conditions

---

## Composite Scoring Example

| Experiment | Accuracy | FP Control | Evidence | Reproducibility | Raw Total | Normalized | Pass? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Perfect experiment | 10 | 10 | 5 | 5 | 30 | 10.0 | Yes |
| Positive only, good evidence | 5 | 10 | 5 | 5 | 25 | 8.3 | Yes |
| Missing negative, no evidence | 5 | 7 | 0 | 5 | 17 | 5.7 | No |
| Both controls fail, errors | 0 | 5 | 2 | 5 | 12 | 4.0 | No |
| Missing fixtures entirely | 0 | 10 | 0 | 5 | 15 | 5.0 | No |

---

## Review Decision Rules

1. **Pass (normalized >= 7.0)**: Eligible for promotion. Proceed to `promote-skill-update`.
2. **Fail (normalized < 7.0)**: Requires revision. Check dimension scores for improvement areas.
3. **Borderline (6.5 - 6.9)**: Flag for manual review. May pass with reviewer override if all red flags are resolved.
4. **Hard Fail (< 5.0)**: Hypothesis needs fundamental redesign or fixture correction.

## Reviewer Checklist

Before approving a passed experiment:

- [ ] Positive fixture genuinely represents the vulnerability class
- [ ] Negative fixture genuinely represents a safe equivalent
- [ ] Detection probe would not trigger on unrelated safe inputs
- [ ] All required evidence artifacts are present and readable
- [ ] Exit codes and output are unambiguous
- [ ] Experiment does not depend on transient external state
- [ ] Scoring dimensions are consistent with manual inspection