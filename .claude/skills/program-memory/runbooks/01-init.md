# 01 — Initialize Program Memory

## Overview

Initialize the governed SQLite memory store for a program. Creates `.bb/memory.sqlite` with the full schema including fact types, confidence tracking, sensitivity tagging, and expiration support. Idempotent — safe to run multiple times.

## Prerequisites

- Context initialized via `bin/bb-init`.
- `PROGRAM` variable set in `.bb/context.env`.

## Steps

1. `bin/bb-run program-memory init-memory`
2. Verify `.bb/memory.sqlite` exists and has the `facts` table.
3. Check schema with: `sqlite3 .bb/memory.sqlite ".schema facts"`

## Verification

- `.bb/memory.sqlite` file exists.
- `facts` table present with columns: `fact_id`, `program`, `category`, `content`, `confidence`, `source_artifact`, `created_at`, `expires_at`, `sensitivity`, `status`, `correction_of`, `reviewed_by_human`.
- Indexes exist on `(program)`, `(program, category)`, `(program, status)`.

## Governance Notes

- Each program gets its own namespace via the `program` column.
- Cross-program queries are DISABLED by default.
- The DB file is shared across programs but facts are per-program isolated.