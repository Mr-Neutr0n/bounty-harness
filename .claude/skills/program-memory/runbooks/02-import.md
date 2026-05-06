# 02 — Import from Previous Runs

## Overview

Import findings, false positives, and decisions from previous run outputs into the governed memory store. Always preview first with a dry run before applying imports with `--apply`.

## Prerequisites

- Memory initialized via 01-init.
- Previous run outputs available at a known path.

## Steps

1. Preview import candidates:
   ```bash
   python3 .claude/skills/program-memory/scripts/memory_store.py search \
     --program $PROGRAM --status active
   ```
   Review existing facts before importing duplicates.

2. Record findings as facts:
   ```bash
   python3 .claude/skills/program-memory/scripts/memory_store.py record \
     --program $PROGRAM \
     --category accepted_finding \
     --content "Stored XSS via profile bio field on /api/user/update" \
     --confidence high \
     --sensitivity program-private
   ```

3. Record false positive patterns:
   ```bash
   python3 .claude/skills/program-memory/scripts/memory_store.py record \
     --program $PROGRAM \
     --category false_positive \
     --content "SQLi template matched on generic PHP error page on /search" \
     --confidence high
   ```

4. Record tech facts (auto-extracted from recon):
   ```bash
   python3 .claude/skills/program-memory/scripts/memory_store.py record \
     --program $PROGRAM \
     --category tech_fact \
     --content "Technology: React 18 detected at https://app.example.com" \
     --source-artifact "$OUTDIR/recon/js_recon/tech.json"
   ```

5. Record scope notes:
   ```bash
   python3 .claude/skills/program-memory/scripts/memory_store.py record \
     --program $PROGRAM \
     --category scope_note \
     --content "*.staging.example.com out of scope" \
     --confidence high
   ```

6. After import, run decay to clean up expired entries:
   ```bash
   bin/bb-run program-memory decay-facts
   ```

## Verification

- Facts appear in search results with correct categories and confidence levels.
- No duplicate content recorded (search first if a fact already exists).
- Source artifacts referenced for traceability.

## Governance Rules

- Auto-import from output MUST preview first. No silent imports.
- Every fact gets a unique `fact_id` for later correction/superseding.
- High-impact facts (decisions, accepted findings, false positives) flagged `reviewed_by_human=0`.