## Overview
Test coupon/gift-card race and refund-after-cancel.

## Steps
1. Run `test-coupon-race`
2. Run `test-refund-after-cancel`
3. Check `findings.jsonl`

## Verification
- Financial invariants tested
- Double-redemption attempts flag correctly
- Cancel-then-refund sequences caught