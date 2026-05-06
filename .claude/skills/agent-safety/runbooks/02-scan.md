# 02 — Scan Untrusted Content

## Overview

Scan untrusted content for injection patterns.

## Prerequisites

- Content to scan available at `CONTENT_PATH`.

## Steps

1. `bin/bb-run agent-safety scan-untrusted-content CONTENT_PATH=<path>`
2. Inspect `injection_scan.jsonl` for findings.
3. Review findings by severity and pattern type.

## Verification

- `injection_scan.jsonl` contains findings with `pattern`, `context`, `position`, `severity`.
- Patterns categorized: prompt_injection, tool_manipulation, data_exfiltration, command_injection.
- Zero findings should still produce a valid (empty) scan output.