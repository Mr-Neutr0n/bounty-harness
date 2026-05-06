## Overview
Generate canary payloads.

## Steps
1. Run `generate-canary` with `CANARY_PURPOSE=ssrf_probe TEST_ID=test_001`
2. Check `canaries.jsonl`

## Verification
- Unique canary URL per test
- Output includes payload, purpose, and test ID