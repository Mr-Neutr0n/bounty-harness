# 03 — Recording Facts, False Positives, and Decisions

## Overview

Record governed facts into program memory with explicit categories, confidence levels, sensitivity tagging, and optional expiration.

## Fact Categories

| Category | Purpose | Typical Sensitivity |
|---|---|---|
| `program_fact` | General program knowledge | program-private |
| `tech_fact` | Technology stack discoveries | program-private |
| `false_positive` | Known false positive patterns | program-private |
| `accepted_finding` | Confirmed bounty findings | program-private |
| `credential_note` | Auth mechanism notes | high-sensitivity |
| `rate_limit_note` | Rate limiting observations | program-private |
| `scope_note` | Scope boundary information | report-safe |
| `decision` | Human decisions and rationale | program-private |
| `correction` | Superseding corrections | program-private |

## Confidence Levels

- `low` — Speculative, needs verification
- `medium` — Reasonable confidence from observation
- `high` — Confirmed through testing or official documentation

## Sensitivity Tiers

- `program-private` — Only visible within program context (default)
- `report-safe` — Safe for report exports, no secrets
- `high-sensitivity` — Never exported, never summarized

## Recording Facts

### Using skill workflows:
```bash
bin/bb-run program-memory record-fact \
  FACT_CATEGORY=tech_fact \
  FACT_CONTENT="Technology: Django 4.2 detected at /admin" \
  FACT_CONFIDENCE=high \
  FACT_SOURCE_ARTIFACT="recon/tech_detect.json"
```

### Using the script directly:
```bash
python3 .claude/skills/program-memory/scripts/memory_store.py record \
  --program $PROGRAM \
  --category tech_fact \
  --content "Technology: Django 4.2 detected at /admin" \
  --confidence high \
  --source-artifact "recon/tech_detect.json"
```

### With expiration:
```bash
python3 .claude/skills/program-memory/scripts/memory_store.py record \
  --program $PROGRAM \
  --category rate_limit_note \
  --content "Safe rate: 10 rps on /api/search" \
  --expires-at "2026-06-01T00:00:00Z"
```

### Marking as human-reviewed:
```bash
python3 .claude/skills/program-memory/scripts/memory_store.py record \
  --program $PROGRAM \
  --category false_positive \
  --content "False positive: XSS on /healthcheck - actual cause: static JSON response mimics reflected input" \
  --confidence high \
  --reviewed
```

## Checking for Contradictions

Before recording scope or tech facts, check for existing contradictions:
```bash
bin/bb-run program-memory check-contradictions
```

## Verification

- `fact_id` returned and unique.
- Content did not trigger secret detection warnings.
- Category and confidence are valid values.
- If `--reviewed` was used, `reviewed_by_human=1`.</think>


<｜DSML｜invoke name="write">
<｜DSML｜parameter name="content" string="true"># 04 — How Planner Consumes Memory Summaries

## Overview

The `summarize` workflow produces a redacted, compact summary designed for the planner skill to consume as context. The summary includes technology facts, scope notes, known false positives, past decisions, corrections, and rate-limit data — but never raw credentials or high-sensitivity content.

## Generating the Summary

```bash
bin/bb-run program-memory summarize
```

This writes `$OUTDIR/program-memory/memory_summary.md`.

## What the Summary Contains

- **Technology Facts**: All active `tech_fact` entries (non-high-sensitivity). Helps planner match techniques to the detected stack.
- **Scope Notes**: Active `scope_note` entries. Informs planner about in/out-of-scope boundaries.
- **Known False Positives**: Active `false_positive` entries. Planner down-weights techniques that match these patterns.
- **Past Decisions**: Active `decision` entries. Provides context about past tradeoffs and choices.
- **Corrections**: Active `correction` entries. Ensures planner uses corrected facts, not superseded originals.
- **Rate Limit Notes**: Active `rate_limit_note` entries. Planner respects rate limits when scheduling tests.
- **Facts Pending Review**: Count of high-impact facts (`decision`, `false_positive`, `accepted_finding`) still un-reviewed. Planner treats these with lower weight.

## What the Summary Excludes

- Facts tagged `high-sensitivity` (credential notes, auth secrets).
- Facts with `status = 'stale'` or `status = 'superseded'`.
- Raw credential data or PII.
- Internal `fact_id` references.

## Planner Integration

The planner should:
1. Call `summarize` before generating a plan.
2. Read the markdown summary as a planning context artifact.
3. Down-weight techniques matching `false_positive` entries.
4. Up-weight techniques aligned with `tech_fact` entries (e.g., Django detected → prioritize Django-specific techniques).
5. Skip techniques targeting endpoints flagged as out-of-scope via `scope_note`.
6. Respect rate limits from `rate_limit_note` entries.

## Running Before Every Plan

```bash
bin/bb-run program-memory decay-facts    # clean stale entries
bin/bb-run program-memory summarize      # produce fresh summary
bin/bb-run planner generate-plan-safe    # consume summary
```