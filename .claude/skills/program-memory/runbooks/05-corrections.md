# 05 — Corrections and Contradictions

## Overview

Program memory supports self-correction. Facts can be superseded by corrections, and contradictory facts are surfaced for human review — never silently merged or auto-resolved.

## Recording a Correction

When a fact is found to be wrong, record a correction that supersedes it:

```bash
python3 .claude/skills/program-memory/scripts/memory_store.py correct \
  --fact-id "f-abc123def456" \
  --new-content "Technology: Actually Express.js, not Django, on /api based on response headers" \
  --reason "Django admin panel was a false positive from template match; X-Powered-By: Express confirms Node stack"
```

What happens:
1. The original fact's `status` changes from `active` to `superseded`.
2. A new `correction` fact is inserted, linked to the original via `correction_of`.
3. The new fact contains the correction reason and updated content.
4. Search and summarize will show the correction, not the superseded original.

Using the skill workflow:
```bash
bin/bb-run program-memory record-correction \
  FACT_ID="f-abc123def456" \
  CORRECTION_CONTENT="Technology: Actually Express.js" \
  CORRECTION_REASON="Response headers confirm Express"
```

## Finding Contradictions

Contradictions are pairs of active facts in the same category that appear to conflict:

```bash
bin/bb-run program-memory check-contradictions
```

The `contradictions` subcommand uses heuristic detection looking for:
- Negation mismatches (one fact says "not present", another says "present")
- Scope conflicts (one says "in scope", another says "out of scope")
- Presence/absence conflicts (one says "found", another says "not found")

Example contradiction pair:
- Fact A: "*.staging.example.com is in scope"
- Fact B: "staging.example.com is out of scope"
- Both are `scope_note` category and `active` status

## Resolution Workflow

1. Detect: `bin/bb-run program-memory check-contradictions`
2. Review: Examine each contradiction pair manually
3. Decide: Determine which fact is correct
4. Correct: Record a correction to supersede the wrong fact:
   ```bash
   bin/bb-run program-memory record-correction \
     FACT_ID="<wrong-fact-id>" \
     CORRECTION_CONTENT="<corrected-content>" \
     CORRECTION_REASON="<why it was wrong>"
   ```
5. Verify: Re-run contradictions check — the pair should no longer appear

## Hard Rules for Corrections

- Corrections must always cite a reason.
- The original fact is preserved (status = superseded) for audit trail.
- Corrections are never applied silently or automatically.
- Contradictions are surfaced for review, not auto-resolved.
- Corrections inherit the original fact's program namespace — cross-program correction is impossible.

## Verifying Correction Chains

```bash
# View original fact
python3 .claude/skills/program-memory/scripts/memory_store.py get --fact-id f-abc123def456

# Search for correction (it has correction_of pointing back)
python3 .claude/skills/program-memory/scripts/memory_store.py search \
  --program $PROGRAM --category correction --status active
```