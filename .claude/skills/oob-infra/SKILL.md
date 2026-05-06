# OOB Infrastructure

## Overview
Manage out-of-band callback infrastructure for detecting blind vulnerabilities. Generate canaries, poll for interactions, correlate callbacks to specific tests, and produce evidence-grade OOB proof.

## Quick Reference
- **Skill**: oob-infra
- **Version**: 1.0.0
- **Bounded Context**: OobContext
- **Required tools**: `python3`, `curl`, `jq`, `interactsh-client`
- **Risk tier**: active-safe (passive callbacks)

## Workflow Selection
- Start: `start-client` to launch an interactsh session.
- During testing: `generate-canary` to get unique payload URLs.
- After testing: `poll-interactions` and `correlate` to map callbacks to tests.
- Cleanup: `stop-client` when done.
- Evidence: `evidence-export` for confirmed OOB findings.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `start-client` | Launch interactsh client and extract callback URL. |
| `generate-canary` | Create a unique canary payload for a specific test. |
| `poll-interactions` | Query the server for received callbacks. |
| `correlate` | Map interactions back to specific tests and requests. |
| `stop-client` | Cleanly shut down the callback client. |
| `self-host-check` | Verify self-hosted interactsh server health. |
| `evidence-export` | Package OOB evidence for reporting. |

## Evidence Required
- Canary payload ID and purpose.
- Interaction timestamps, protocols, remote addresses.
- Correlation between payload and originating test.
- Raw callback data (request headers, body for HTTP callbacks).

## References
- ProjectDiscovery Interactsh documentation
- OWASP WSTG-INPV-11 (SSRF Testing)
- OWASP WSTG-INPV-07 (Blind XSS)
- PortSwigger OAST (Out-of-band Application Security Testing)