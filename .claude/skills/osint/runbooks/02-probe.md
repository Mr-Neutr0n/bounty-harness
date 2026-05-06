# OSINT — Probe (Automated Secret Scanning)

## Purpose
Run automated secret scanners (TruffleHog, Gitleaks, Semgrep) against cloned target repositories. Detect high-signal credentials, API keys, certificates, and hardcoded tokens that manual dorking may miss.

## Required Variables
- $TARGET: domain or organization name
- $OUTDIR: output directory for scan results

## Commands

```bash
mkdir -p $OUTDIR/probe/clones $OUTDIR/probe/scans

gh search repos "org:${TARGET}" --limit 100 --json nameWithOwner \
  | jq -r '.[].nameWithOwner' > $OUTDIR/probe/target_repos.txt

while IFS= read -r repo; do
  REPO_SAFE=$(echo "$repo" | tr '/' '_')
  CLONE_PATH="$OUTDIR/probe/clones/${REPO_SAFE}"
  rm -rf "$CLONE_PATH"
  gh repo clone "$repo" "$CLONE_PATH" -- --depth=50 2>/dev/null || continue

  trufflehog git "file://${CLONE_PATH}" --json --no-update \
    > "$OUTDIR/probe/scans/trufflehog_${REPO_SAFE}.json" 2>/dev/null

  gitleaks detect --source "$CLONE_PATH" \
    --report-path "$OUTDIR/probe/scans/gitleaks_${REPO_SAFE}.json" \
    --report-format json --no-git 2>/dev/null

  semgrep --config=auto "$CLONE_PATH" --json --no-git-ignore \
    -o "$OUTDIR/probe/scans/semgrep_${REPO_SAFE}.json" 2>/dev/null

  rm -rf "$CLONE_PATH"
done < $OUTDIR/probe/target_repos.txt

python3 "$HOME/Desktop/bug bounty/.claude/skills/osint/scripts/github_secret_scanner.py" \
  --input "$OUTDIR/discovery/github_code_urls.txt" \
  --output "$OUTDIR/probe/scans/custom_secrets.json" 2>/dev/null || true

find $OUTDIR/probe/scans -name 'trufflehog_*.json' -exec cat {} + \
  | jq -s 'map(select(.DetectorName != null))' \
  > $OUTDIR/probe/consolidated_trufflehog.json

cat $OUTDIR/probe/scans/gitleaks_*.json 2>/dev/null \
  | jq -s '.[] | select(. != null)' \
  > $OUTDIR/probe/consolidated_gitleaks.json

cat $OUTDIR/probe/scans/semgrep_*.json 2>/dev/null \
  | jq -s 'map(.results[]) | map({path: .path, check: .check_id, message: .extra.message})' \
  > $OUTDIR/probe/consolidated_semgrep.json
```

## Detection Signals
- TruffleHog `Verified` field is `true` — credential was validated live
- Gitleaks matches with `Entropy` > 4.5 — high-entropy strings are likely real secrets
- Semgrep `security` severity findings in `secrets` or `generic-api-key` rules
- Same secret appearing across multiple repos (cross-contamination)

## Next
├── If verified secrets found → proceed to `03-verify.md` for manual validation
├── If unverified secrets found → proceed to `04-impact-escalation.md` for bulk testing
├── If no findings → widen search: clone full history with `--depth=` removed
└── If clone failures → repos may be private/deleted; skip and continue