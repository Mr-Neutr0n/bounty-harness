# Agent Safety

## Overview
Protect the AI-assisted bug bounty toolkit from prompt injection in target-controlled content. Sanitize untrusted HTML, JS, markdown, API responses, and tool outputs before they reach the LLM reasoning layer.

## Quick Reference
- **Skill**: agent-safety
- **Version**: 1.0.0
- **Bounded Context**: AgentSafetyContext
- **Required tools**: `python3`, `jq`
- **Risk tier**: passive (defensive layer)

## Workflow Selection
- Before AI triage: `sanitize-corpus` on any target content.
- During scanning: `scan-untrusted-content` to detect injection patterns.
- Review: `classify-injection-risk` to score content danger.
- Audit: `decision-log-summary` to review agent decisions.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `sanitize-corpus` | Strip instruction-like patterns from target content. |
| `scan-untrusted-content` | Detect prompt injection, hidden instructions, and exfiltration patterns. |
| `classify-injection-risk` | Score content by injection danger level. |
| `guardrail-check` | Validate AI tool call against safety policy. |

## Evidence Required
- Sanitized content comparison (before/after).
- Injection pattern matches with context.
- Tool call decision log with approval status.

## References
- OWASP LLM01:2025 (Prompt Injection)
- OWASP LLM Prompt Injection Prevention Cheat Sheet
- OWASP AI Agent Security Cheat Sheet
- PortSwigger Web LLM Attacks Academy Topic