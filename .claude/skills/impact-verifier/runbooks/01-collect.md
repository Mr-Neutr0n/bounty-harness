# 01 — Collect Candidates

## Overview

Collect candidates from all skill outputs.

## Prerequisites

- Context initialized via `bin/bb-init`.
- At least one vulnerability skill has produced output.

## Steps

1. `bin/bb-run impact-verifier collect-candidates`
2. Inspect `candidates.jsonl` for candidate count.
3. Verify each candidate has `source_file` and `candidate_id` fields.

## Verification

- `candidates.jsonl` exists and is non-empty.
- Every line in `candidates.jsonl` contains `source_file` and `candidate_id`.
- Duplicate candidates are deduplicated on `candidate_id`.