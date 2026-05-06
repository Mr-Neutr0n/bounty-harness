# 04 — Guardrail Check

## Overview

Check tool calls against safety policy.

## Prerequisites

- `risk_report.json` exists from 03-classify.
- Tool name and parameters to check are identified.

## Steps

1. `bin/bb-run agent-safety guardrail-check TOOL_NAME=<name> TOOL_PARAMS=<json>`
2. Inspect `guardrail_decision.json`.
3. Act on the decision before proceeding.

## Verification

- `guardrail_decision.json` contains `decision` field.
- Decision values: `allowed`, `requires_approval`, `blocked`.
- `requires_approval` includes `justification` and `risk_detail`.
- `blocked` includes `policy_rule` reference and `mitigation` suggestion.