## Overview
Build authorization matrix from personas and routes.

## Prerequisites
- `personas.json` with 2+ active personas
- `routes.jsonl`

## Steps
1. Run `build-matrix`
2. Check that `matrix.json` has persona pairs

## Verification
- `matrix.json` shows owner/attacker pairs
- All persona roles mapped to route scopes