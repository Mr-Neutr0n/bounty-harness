# Runbook: platform-export

Render a confirmed finding into a platform-specific report (HackerOne, Bugcrowd, or generic disclosure) from its evidence directory.

## When to use
Run after `generate-single`/`cvss-score` have produced report content and a CVSS vector, and the finding's impact has been verified. This is the final step before manual submission to a program.

## Inputs
- `FINDING_DIR` — evidence directory for the finding (request.txt, response.txt, poc.sh, screenshot.png, manifest).
- `PLATFORM` — one of `hackerone`, `bugcrowd`, `generic` (defaults to `hackerone`).
- `OUTDIR` — run output directory.

## Command
```bash
bin/bb-run reporting platform-export
# or directly:
python3 .claude/skills/reporting/scripts/platform_templates.py render \
  --finding-dir "$FINDING_DIR" \
  --platform "${PLATFORM:-hackerone}" \
  --output "$OUTDIR/reports/report_${PLATFORM:-hackerone}.md"
```

To see which fields a platform expects before rendering:
```bash
python3 .claude/skills/reporting/scripts/platform_templates.py list-fields --platform hackerone
```

## Output
- `$OUTDIR/reports/report_<platform>.md` — submission-ready markdown with title, severity, CVSS, summary, steps to reproduce, PoC, impact, and affected assets.

## Triage checklist
- Confirm the severity and CVSS vector match the verified impact (cross-check against `impact-verifier`).
- Ensure steps to reproduce are minimal and deterministic.
- Redact or sanitize auth headers, session cookies, bearer tokens, and PII in any pasted request/response before submission.
- Keep the rendered report local-only until you submit it; it is never committed to the repository.

## Safety
Passive — this workflow only reads local evidence and writes a local markdown file. It sends no traffic to the target.
