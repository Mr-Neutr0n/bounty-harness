# Evaluation Harness — Quickstart

## What this is
The evaluation harness measures whether your bug bounty skills actually work. Each fixture is a micro-service with a known vulnerability. Positive controls verify the skill detects the vuln. Negative controls verify the skill does not fire on benign input. The harness turns vibes into metrics.

## Prerequisites
- Python 3.10+ with `yaml` (PyYAML)
- `curl` available on PATH
- `bash` available
- No Docker needed for basic runs (fixtures use Python stdlib)
- Ports 8081–8088 must be free

## First run

### 1. Install PyYAML if needed
```bash
pip3 install --break-system-packages PyYAML
```

### 2. Make all test scripts executable
```bash
chmod +x .claude/skills/evaluation-harness/fixtures/*/test_*.sh
```

### 3. Run skill tests
```bash
python3 .claude/skills/evaluation-harness/scripts/run_skill_test.py \
  --skills-dir .claude/skills \
  --fixtures-dir .claude/skills/evaluation-harness/fixtures \
  --context output/eval
```

### 4. Generate the evaluation matrix
```bash
python3 .claude/skills/evaluation-harness/scripts/generate_matrix.py \
  --results-manifest output/eval/results_manifest.json \
  --context output/eval
```

### 5. Run the benchmark (saves baseline)
```bash
python3 .claude/skills/evaluation-harness/scripts/benchmark_runner.py \
  --eval-matrix output/eval/eval_matrix.json \
  --context output/eval
```

## Understanding results

Open `output/eval/eval_dashboard.md` to see the health dashboard.

| Metric | Meaning | Good value |
| --- | --- | --- |
| Precision | How many detections are real vulns | > 0.90 |
| Recall | How many real vulns are detected | > 0.90 |
| F1 | Harmonic mean of precision and recall | > 0.90 |
| FPR | False positive rate | < 0.10 |
| Health | F1 * 10 | > 8.0 |

### Color codes
- Green: 8.0+ (production ready)
- Yellow: 5.0–7.9 (needs improvement)
- Red: 0.0–4.9 (critical issues)

## Port conflicts
If ports 8081–8088 are in use, kill the conflicting processes:
```bash
lsof -ti:8081,8082,8083,8084,8085,8086,8087,8088 | xargs kill -9
```

## Running a single fixture
```bash
bash .claude/skills/evaluation-harness/fixtures/xss-reflected/test_positive.sh
bash .claude/skills/evaluation-harness/fixtures/xss-reflected/test_negative.sh
```

## Next steps
- Read `fixture-catalog.md` to understand each fixture
- Read `adding-fixtures.md` to create new fixtures
- Read `metrics-reference.md` for detailed metric definitions