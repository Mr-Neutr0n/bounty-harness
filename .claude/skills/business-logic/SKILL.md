# Business Logic Testing

## Overview
Model application workflows as state machines and test for invalid transitions, race windows, idempotency violations, and invariant breaks. Targets the bugs that scanners never find.

## Quick Reference
- **Skill**: business-logic
- **Version**: 1.0.0
- **Bounded Context**: BusinessLogicContext
- **Required tools**: `python3`, `curl`, `jq`
- **Risk tier**: intrusive (tests state-changing operations)

## Workflow Selection
- Setup: `infer-workflows` from traffic corpus and domain model.
- Targeted test: `define-workflow` manually, then test specific transitions.
- Broad scan: `test-skip-step`, `test-repeat-step`, `test-reorder-steps`.
- Race testing: `test-race-window`, `test-idempotency`.
- Value abuse: `test-coupon-race`, `test-refund-after-cancel`.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `infer-workflows` | Generate workflow models from traffic corpus and archetype data. |
| `define-workflow` | Manually define a multi-step workflow for testing. |
| `test-skip-step` | Test bypassing required workflow steps. |
| `test-repeat-step` | Test re-executing already completed steps. |
| `test-reorder-steps` | Test executing steps out of intended order. |
| `test-race-window` | Test concurrent requests at sensitive transition points. |
| `test-idempotency` | Verify operations handle duplicate requests correctly. |
| `test-coupon-race` | Test concurrent coupon/gift-card redemption. |
| `test-refund-after-cancel` | Test refund trigger after subscription cancellation. |
| `summarize-violations` | Produce report of violated invariants. |

## Evidence Required
- Workflow model showing intended states and transitions.
- Request/response trace for each violated invariant.
- Concurrency evidence for race conditions (timestamps, thread IDs).
- Persona context for cross-user workflow abuse.

## References
- OWASP WSTG-BUSL-01 through WSTG-BUSL-09
- OWASP Business Logic Security Cheat Sheet
- CWE-840: Business Logic Errors
- PortSwigger Business Logic Vulnerabilities Academy