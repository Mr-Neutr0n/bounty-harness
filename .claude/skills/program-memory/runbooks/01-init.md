# 01 — Initialize Memory

## Overview

Initialize program memory store.

## Prerequisites

- Context initialized via `bin/bb-init`.
- `PROGRAM` variable set in `.bb/context.env`.

## Steps

1. `bin/bb-run program-memory init-memory`
2. Verify directory structure at `engagements/<PROGRAM>/memory/`.
3. Inspect `program_memory.json` contents.

## Verification

- `engagements/<PROGRAM>/memory/` directory exists.
- `program_memory.json` created with empty `facts`, `patterns`, `false_positives`, `run_history` arrays.
- File is valid JSON with `created_at` and `program` fields.