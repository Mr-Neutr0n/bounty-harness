# Impact Verifier

## Overview
The final gate before reporting. Converts candidate findings into confirmed bounty-grade reports only when impact is proven. Enforces evidence completeness, false-positive checks, impact classification, and report readiness scoring.

## Quick Reference
- **Skill**: impact-verifier
- **Version**: 1.0.0
- **Bounded Context**: ImpactContext
- **Required tools**: `python3`, `jq`, `curl`
- **Risk tier**: passive (validates, does not test)

## Workflow Selection
- Collect: `collect-candidates` from all skill output directories.
- Classify: `classify-impact` to determine impact class.
- Verify: Run the specific verify workflow for the impact class.
- Gate: `false-positive-gate` and `report-readiness` before reporting.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `collect-candidates` | Aggregate candidate findings from all skill outputs. |
| `classify-impact` | Determine impact class for a candidate finding. |
| `verify-data-exposure` | Prove actual data exposure from unauthorized access. |
| `verify-privilege-escalation` | Prove role/permission boundary was broken. |
| `verify-account-takeover` | Prove full account takeover path. |
| `verify-tenant-break` | Prove cross-tenant data access. |
| `false-positive-gate` | Run automated false-positive checks. |
| `report-readiness` | Score finding readiness for submission. |

## Evidence Required
- Impact class confirmation with proof artifacts.
- False-positive checklist completed.
- Report readiness score >= 80.
- All standard evidence artifacts present.

## References
- Bugcrowd VRT 1.18
- OWASP ASVS V4 (Access Control)
- OWASP Reporting guidelines