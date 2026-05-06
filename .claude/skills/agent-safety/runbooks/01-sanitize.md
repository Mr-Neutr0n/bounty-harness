# 01 — Sanitize Content

## Overview

Strip injection patterns from content.

## Prerequisites

- Context initialized via `bin/bb-init`.
- Target content file available at `CORPUS_PATH`.

## Steps

1. `bin/bb-run agent-safety sanitize-corpus CORPUS_PATH=<path>`
2. Inspect `sanitized.jsonl` for modification records.
3. Compare original content vs sanitized output.

## Verification

- `sanitized.jsonl` contains one record per file with `modifications` array.
- Each modification has `pattern`, `original`, `replacement`, `position`.
- Sanitized content is written alongside originals.