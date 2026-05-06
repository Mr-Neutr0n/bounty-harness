# 04 — Export Planner Hints

## Overview

Export planner hints from memory.

## Prerequisites

- `program_memory.json` populated with facts and false positives.

## Steps

1. `bin/bb-run program-memory summarize-memory`
2. `bin/bb-run program-memory export-planner-hints`
3. Inspect `planner_hints.json`.

## Verification

- `planner_hints.json` contains `downweight` and `upweight` arrays.
- `downweight` lists techniques with repeated false positives.
- `upweight` lists techniques aligned with confirmed facts.
- Hints are consumption-ready for the planner skill.
- Summary includes `total_runs`, `total_facts`, `total_fp_patterns`.