# 02 — Import Run Data

## Overview

Import run data into memory.

## Prerequisites

- `program_memory.json` exists from 01-init.
- Run output available in `OUTDIR` or specified path.

## Steps

1. `bin/bb-run program-memory import-run RUN_DIR=<path>`
2. Inspect `import_report.json` for import statistics.
3. Verify new entries appear in `program_memory.json`.

## Verification

- `import_report.json` shows `candidates_imported`, `findings_imported`, `fp_patterns_imported`.
- `program_memory.json` `run_history` array updated with new entry.
- Deduplication prevents stale duplicates.
- Import timestamp recorded.