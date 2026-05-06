## Overview
Test race windows and idempotency.

## Steps
1. Run `test-race-window`
2. Run `test-idempotency`
3. Check `race_tests.jsonl`

## Verification
- Concurrent tests with timestamps
- Each test records expected vs actual outcome