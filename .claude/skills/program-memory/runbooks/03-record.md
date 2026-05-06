# 03 — Record Facts

## Overview

Record facts and false positives manually.

## Prerequisites

- `program_memory.json` exists from 01-init.

## Steps

1. `bin/bb-run program-memory record-fact FACT_CATEGORY=<cat> FACT_VALUE=<val> FACT_CONFIDENCE=<0-1>`
2. `bin/bb-run program-memory record-false-positive PATTERN=<desc> CONTEXT=<notes>`
3. Inspect `program_memory.json` for new entries.

## Verification

- Fact added to `facts` array with `category`, `value`, `confidence`, `source`.
- False positive added to `false_positives` array with `pattern`, `context`, `first_seen`.
- Entries are JSON-mergeable for future runs.