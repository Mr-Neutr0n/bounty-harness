# 03 — Classify Injection Risk

## Overview

Classify injection risk level.

## Prerequisites

- `injection_scan.jsonl` exists from 02-scan.

## Steps

1. `bin/bb-run agent-safety classify-injection-risk`
2. Inspect `risk_report.json`.
3. Review highest-risk content first.

## Verification

- `risk_report.json` contains overall `risk_level` and per-file `findings`.
- Risk levels: `safe`, `suspicious`, `dangerous`, `critical`.
- `critical` findings indicate immediate blocking required.
- Summary section provides total counts per level.