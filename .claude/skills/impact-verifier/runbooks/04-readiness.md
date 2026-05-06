# 04 — Report Readiness

## Overview

Score report readiness.

## Prerequisites

- `verified.jsonl` and `rejected.jsonl` exist from 03-verify.

## Steps

1. `bin/bb-run impact-verifier false-positive-gate`
2. `bin/bb-run impact-verifier report-readiness`
3. Inspect `readiness_report.md`.

## Verification

- `readiness_report.md` contains per-finding readiness scores.
- Aggregate readiness score >= 80 is submission-ready.
- Scores below 80 require further evidence collection or verification.
- `fp_gate` output shows any false positive patterns caught.