# 02 — Classify Impact

## Overview

Classify impact for each candidate.

## Prerequisites

- `candidates.jsonl` exists from 01-collect.

## Steps

1. `bin/bb-run impact-verifier classify-impact`
2. Inspect `candidates.jsonl` for `impact_class` field on each record.
3. Review distribution of impact classes for imbalance.

## Verification

- Each candidate has an `impact_class` assigned.
- Common classes: `data_exposure`, `privilege_escalation`, `ssrf`, `rce`, `auth_bypass`, `xss`, `sqli`, `information_disclosure`, `dos`, `business_logic`.
- No candidate left with `unclassified`.