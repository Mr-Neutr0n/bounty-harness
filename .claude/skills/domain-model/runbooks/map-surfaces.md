# Map Surfaces Runbook — Attack Surface Mapping

## Purpose
Map the target's detected infrastructure, endpoints, and services to the surface taxonomy defined in surfaces.yaml. Combines direct signal matching with archetype inference.

## Prerequisites
- `classify` workflow must have completed (archetypes.json exists).
- Recon context directory must be accessible.

## Execution

```bash
mkdir -p $OUTDIR/domain-model && \
python3 .claude/skills/domain-model/scripts/surface_mapper.py \
  --context $OUTDIR/recon \
  --archetypes $OUTDIR/domain-model/archetypes.json \
  --output $OUTDIR/domain-model/surfaces.json
```

## Expected Output
- `$OUTDIR/domain-model/surfaces.json` — JSON file with detected surfaces, confidence levels, auth requirements, and related skills.

## Sample Output Format
```json
{
  "target": "vimeo.com",
  "detected_surfaces": [
    {
      "id": "upload-pipeline",
      "name": "Upload Pipeline",
      "confidence": "high",
      "auth_required": "optional",
      "intrusive_level": "careful",
      "related_skills": ["file-upload", "ssrf", "rce"],
      "evidence": ["upload subdomain", "multipart/form-data forms detected"],
      "archetype_match": true
    }
  ],
  "total_detected": 1
}
```

## Triage Rules
- Confidence "high": direct signal match from recon data. Test first.
- Confidence "medium": single signal or partial match. Test second.
- Confidence "inferred": only matched via archetype membership. Test third.
- `auth_required: mandatory`: prepare authenticated session before testing.
- `intrusive_level: intrusive`: confirm scope allows this level of testing.

## Next Step
After map-surfaces completes, run `profile` workflow to generate the full report.