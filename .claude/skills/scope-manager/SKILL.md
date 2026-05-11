# Scope Manager

## Overview
Structured scope definition, validation, versioning, and guardrails for bug bounty engagements. Prevents accidental out-of-scope testing and tracks scope evolution over time.

## Quick Reference
- **Skill**: scope-manager
- **Version**: 1.0.0
- **Bounded Context**: ScopeManagementContext
- **Required tools**: `python3`
- **Risk tier**: passive (read-only, no target interaction)

## Available Workflows

| Workflow | Purpose | Safety Tier |
|---|---|---|
| `init-scope` | Generate structured scope file for new target | passive |
| `validate-url` | Check if URL is within scope | passive |
| `diff-scope` | Compare two scope files | passive |
| `guard-request` | Guard HTTP request against scope | passive |
| `track-scope` | Save scope snapshot for versioning | passive |
| `check-changes` | Detect scope changes since last snapshot | passive |
| `export-scope` | Export scope in JSON or text format | passive |

## Workflow Selection

| Intent | Workflow |
|---|---|
| Create initial scope file | `init-scope` |
| Check if URL is in scope | `validate-url` |
| Compare two scope files | `diff-scope` |
| Guard a request before sending | `guard-request` |
| Save scope snapshot | `track-scope` |
| Detect scope changes | `check-changes` |
| Export scope data | `export-scope` |

## Scope File Format

```text
# In Scope
example.com
*.example.com
api.example.com

# Out of Scope
www.example.com/blog
mail.example.com

# APIs
api.example.com/v1
api.example.com/v2

# Mobile Apps
# iOS: com.example.app
# Android: com.example.app
```

## Evidence Required
For every scope operation, collect:
- Scope file content and SHA-256 hash
- Timestamp of creation/modification
- Program name and target domain
- Diff output when comparing versions (added/removed items)
- Guard decision log (URL, allowed/disallowed, reason)
- Validation results for batch URL checks

## Integration with Other Skills
- Use `guard-request` before `api`, `xss`, `sqli` workflows to prevent OOS testing
- Use `track-scope` after `bb-init` to establish baseline
- Use `check-changes` before each session to detect program scope updates

## References
- OWASP WSTG-INFO-01 (Conduct Search Engine Discovery)
- HackerOne Scope Best Practices
