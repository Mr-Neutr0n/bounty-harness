# Reporting — False Positive Filter & Quality Gate

## Purpose
Apply a systematic quality checklist to every finding before submission. Verify PoCs still work, check for leaked secrets in the report, run the complete report through peer review steps, and flag any items that need manual triage.

## Required Variables
- `$OUTDIR`: output directory for reports
- `$EVIDENCE_DIR`: evidence directory
- `$TARGET_URL`: vulnerable endpoint

## Commands

```bash
echo "=== STEP 1: Re-verify all PoC scripts ==="
for poc in "$EVIDENCE_DIR"/poc_*.sh; do
  [ -f "$poc" ] || continue
  echo "[*] Running: $poc"
  bash "$poc" "$TARGET_URL" 2>&1 | tail -3
done

echo "=== STEP 2: Validate report.md ==="
report="$OUTDIR/report.md"

echo "=== STEP 3: Check for leaked secrets ==="
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$report" --no-git -v 2>&1 | tee "$OUTDIR/gitleaks_report.log"
else
  rg -n -i 'password|token|secret|key|api[_-]?key|credential' "$report" 2>/dev/null && echo "[!] Potential secrets found in report!" || echo "[*] No obvious secrets detected"
fi

echo "=== STEP 4: Check for URLs/artifacts that should be redacted ==="
rg -n '127\.0\.0\.1|192\.168\.|10\.\d+\.\d+\.\d+' "$report" 2>/dev/null && echo "[!] Internal IPs found" || echo "[*] No internal IPs"
rg -n '@(gmail|yahoo|outlook|proton)\.com' "$report" 2>/dev/null && echo "[!] Email addresses found" || echo "[*] No emails exposed"

echo "=== STEP 5: Quality checklist ==="
python3 - "$OUTDIR" "$EVIDENCE_DIR" << 'PYEOF'
import sys, json, os

CHECKLIST = [
    ("1. Finding title is clear and descriptive", None),
    ("2. Vulnerable endpoint/URL is specified", None),
    ("3. HTTP method and parameters are documented", None),
    ("4. CVSS v3.1 score is present and correct", None),
    ("5. CVSS vector string is included (if available)", None),
    ("6. Severity matches CVSS qualitative range", None),
    ("7. Business impact statement is non-generic", None),
    ("8. Remediation is actionable and specific", None),
    ("9. PoC script reproduces the vulnerability", None),
    ("10. Screenshots show the vulnerability clearly", None),
    ("11. Request/response evidence is captured", None),
    ("12. No PII or secrets in evidence or report", None),
    ("13. HackerOne VRT category is assigned", None),
    ("14. No placeholder text or TODO markers remain", None),
    ("15. Reproduction steps work on a fresh session", None),
]

print("| # | Check | Status | Notes |")
print("|---|-------|--------|-------|")
for idx, (check, _) in enumerate(CHECKLIST, 1):
    print(f"| {idx} | {check} | ⬜ Pending | |")

print("\nRun this checklist manually against each finding before submission.")

inv_json = os.path.join(sys.argv[1], "inventory/findings_with_impact.json")
if os.path.exists(inv_json):
    with open(inv_json) as fh:
        findings = json.load(fh)
    print(f"\nFindings to verify: {len(findings)}")
    for f in findings:
        print(f"  - [{f['severity']}] {f['title']} ({f['template']})")
PYEOF

echo "=== STEP 6: Build final submission checklist ==="
cat > "$OUTDIR/submission_checklist.md" << 'SHEOF'
# Submission Checklist

## Before submitting, verify:

- [ ] All PoCs run successfully against the tested host
- [ ] No hardcoded credentials or tokens in the report
- [ ] Screenshots show the vulnerability and are properly annotated
- [ ] CVSS scores are accurate and vectors are defensible
- [ ] Remediation advice is specific to the affected technology stack
- [ ] Report is well-formatted: headings, code blocks, no broken images
- [ ] Evidence bundle (`evidence_bundle.zip`) includes all artifacts
- [ ] Target scope: only in-scope domains/hosts are included
- [ ] No duplicate findings submitted to the same program
- [ ] Submission severity matches the program's severity guidelines

## Final sign-off

- Date: $(date -u +%Y-%m-%d)
- Analyst: ________________
- Peer reviewer: ________________
- Program: ________________
SHEOF

echo "Done. Review $OUTDIR/submission_checklist.md before submitting."
```

## Detection Signals
- All PoCs either pass or have a documented reason for failure
- `gitleaks detect` returns 0 leaks
- No unredacted emails, IPs, or tokens in the report
- All 15 checklist items reviewed and marked

## Next
├── If all gates pass → report is ready for submission
├── If PoC fails → re-verify, fix PoC, or mark as false positive
├── If secrets found → redact immediately, do NOT submit
└── If quality gaps found → fix findings, re-run this phase