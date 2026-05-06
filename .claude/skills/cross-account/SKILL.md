# Cross-Account Authorization Testing

## Overview
Automate IDOR/BOLA/BFLA/tenant isolation testing by replaying captured requests across multiple authenticated personas and diffing the responses. Converts raw traffic into structured authorization experiments.

## Quick Reference
- **Skill**: cross-account
- **Version**: 1.0.0
- **Bounded Context**: AuthorizationContext
- **Required tools**: `python3`, `curl`, `jq`
- **Risk tier**: intrusive (replays against target)

## Workflow Selection
- Setup: `build-matrix` from personas and corpus routes.
- Quick test: `replay-route` on a single high-value route.
- Full scan: `replay-corpus` across all routes and all persona pairs.
- Object-level: `object-swap` to test IDOR on object references.
- Tenant-level: `tenant-swap` to test cross-tenant access.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `build-matrix` | Construct authorization matrix from personas and route catalog. |
| `replay-corpus` | Replay every corpus route as every persona persona pair. |
| `replay-route` | Test a single route across all persona pairs. |
| `object-swap` | Swap object IDs between personas and replay. |
| `tenant-swap` | Test cross-tenant access behavior. |
| `role-downgrade` | Test if downgraded users retain access. |
| `anonymous-replay` | Test authenticated routes without credentials. |
| `diff-responses` | Diff replay results and flag unauthorized access. |
| `evidence-pack` | Package confirmed finding with replay evidence. |

## Evidence Required
- Baseline owner request and response.
- Attacker replay request and response.
- Diff showing status code, body field, or authorization discrepancy.
- Persona relationship (same tenant, different tenant, admin vs user).

## References
- OWASP WSTG-ATHZ-02 (Insecure Direct Object References)
- OWASP API1:2023 (Broken Object Level Authorization)
- OWASP API5:2023 (Broken Function Level Authorization)