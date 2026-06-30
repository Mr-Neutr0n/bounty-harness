# Traffic Corpus

## Overview
Import real application traffic (HAR, Burp, mitmproxy, proxify, browser logs) and normalize it into a deduplicated, route-aware, object-aware corpus for replay-based security testing.

## Quick Reference
- **Skill**: traffic-corpus
- **Version**: 1.0.0
- **Bounded Context**: TrafficCorpusContext
- **Required tools**: `python3`, `jq`, `curl`
- **Risk tier**: active-safe (imports, does not replay)

## Workflow Selection
- Starting fresh: `import-traffic` with one or more source files, then `normalize-corpus`.
- Analyzing structure: `extract-routes` then `extract-objects` and `summarize-corpus`.
- GraphQL targets: `extract-graphql` after normalization.
- WebSocket targets: `extract-websockets` after normalization.

## Available Workflows
| Workflow | Purpose |
|---|---|
| `import-traffic` | Import one or more traffic sources (HAR, Burp XML, mitmproxy, proxify, raw curl). |
| `normalize-corpus` | Deduplicate and normalize all samples into canonical route signatures. |
| `extract-routes` | Produce route catalog with HTTP method, path shape, auth indicators, and tags. |
| `extract-objects` | Extract object references (user IDs, file IDs, workspace IDs, etc.) from samples. |
| `extract-graphql` | Extract GraphQL queries, mutations, subscriptions, and operation variables. |
| `extract-websockets` | Extract WebSocket message patterns from captured traffic. |
| `summarize-corpus` | Produce human-readable summary of corpus size, routes, objects, and coverage. |

## Redaction and Secrets Handling
Imported traffic (HAR exports, captured cookies, `Authorization` / bearer tokens, session IDs, and API keys) is treated as sensitive and kept local-only under `$OUTDIR/traffic-corpus/`; these raw captures are never committed and the directory is covered by `.gitignore`. Before any corpus is shared or exported, secrets in headers and bodies are redacted/sanitized so cookies and bearer tokens never leave the local engagement workspace.

## Evidence Required
- Source traffic files (raw) stored under `$OUTDIR/traffic-corpus/raw/`.
- Normalized corpus in JSONL format.
- Route signatures preserve original request/response pairs for evidence.

## References
- OWASP WSTG-INFO-05 (Fingerprint Web Application)
- OWASP WSTG-INFO-06 (Application Entry Points)
- OWASP API Top 10 2023
- PortSwigger API Testing Academy Topic