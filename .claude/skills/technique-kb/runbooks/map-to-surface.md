# How to Map Techniques to a Target Surface

## Prerequisites

You need two JSON files:

1. `archetypes.json` — list of domain-model archetype IDs for the target
2. `surfaces.json` — list of domain-model surface IDs for the target

Example `archetypes.json`:
```json
["developer-platform", "collaboration-saas"]
```

Example `surfaces.json`:
```json
["api-object-crud", "auth-flow", "webhook-callbacks"]
```

## Run the matcher

```bash
cd .claude/skills/technique-kb
python3 scripts/technique_matcher.py \
  --techniques-dir techniques \
  --archetypes-file archetypes.json \
  --surfaces-file surfaces.json
```

## Understanding output

The output is a ranked JSON list:

```json
{
  "target_archetypes": ["developer-platform", "collaboration-saas"],
  "target_surfaces": ["api-object-crud", "auth-flow", "webhook-callbacks"],
  "total_matches": 5,
  "techniques": [
    {
      "technique_id": "api-bola-id-swap",
      "name": "Broken Object Level Authorization",
      "category": "api",
      "severity": "high",
      "severity_rank": 4,
      "match_type": "archetype_and_surface",
      "match_score": 3,
      ...
    }
  ]
}
```

## Match types

| Score | Type | Meaning |
|---|---|---|
| 3 | archetype_and_surface | Matches both archetype AND surface (highest confidence) |
| 2 | archetype_only | Matches archetype but not surface (broadly relevant) |
| 1 | surface_only | Matches surface but not archetype (surface-driven) |

## Ranking

Results are sorted by:
1. match_score (3 > 2 > 1)
2. severity_rank (critical 5 > high 4 > ...)

## Triage

1. Focus on `archetype_and_surface` matches first — these are the highest-confidence hits
2. Review `archetype_only` for broad applicability
3. Surface-only matches are edge cases — review manually
4. Check `safety.requires_approval` on each — approve before running intrusive techniques
5. Pass matched technique IDs to the bug bounty agent for execution