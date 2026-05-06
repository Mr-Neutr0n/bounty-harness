# Persona

## Overview
Manage authenticated testing personas (attacker, victim, admin, readonly, etc.) with secure credential storage, session validation, and per-persona header export for replay-based security testing.

## Quick Reference
- **Skill**: persona
- **Version**: 1.0.0
- **Bounded Context**: PersonaContext
- **Required tools**: `python3`, `curl`, `jq`, `openssl`
- **Risk tier**: destructive-manual (stores real credentials)

## Workflow Selection
- New program with accounts: start with `init-personas`, then `import-cookie` for each account, then `validate-sessions`.
- Reusing prior sessions: run `validate-sessions` to confirm they still work, then `export-headers`.
- Before reporting: run `redact-secrets` to produce report-safe manifests.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `init-personas` | Create persona manifest template for the current engagement. |
| `import-cookie` | Import a cookie, bearer token, API key, or header set for one persona. |
| `validate-sessions` | Request a known URL as each persona and classify auth state. |
| `redact-secrets` | Produce safe redacted manifest for reports and logs. |
| `export-headers` | Generate per-persona replay headers for consumption by other skills. |

## Evidence Required
- Credential files stored under `$OUTDIR/persona/creds/` (gitignored).
- Redacted manifests show hashed identifiers only.
- Session validation logs confirm active/inactive/partial auth state.

## References
- OWASP WSTG-ATHN-01 through WSTG-ATHN-10
- OWASP ASVS V2 (Authentication)
- OWASP ASVS V4 (Access Control)