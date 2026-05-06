# 03 — Verify Impact

## Overview

Verify specific impact class.

## Prerequisites

- `candidates.jsonl` has `impact_class` assigned from 02-classify.

## Steps

1. `bin/bb-run impact-verifier verify-data-exposure`
2. `bin/bb-run impact-verifier verify-privilege-escalation`
3. `bin/bb-run impact-verifier verify-ssrf`
4. Run additional `verify-*` workflows as needed.
5. Inspect `verified.jsonl` and `rejected.jsonl`.

## Verification

- Confirmed candidates appear in `verified.jsonl` with `verification_method` and `confidence`.
- Rejected candidates appear in `rejected.jsonl` with `rejection_reason`.
- All candidates from 02-classify are accounted for.