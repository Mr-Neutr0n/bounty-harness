# OSINT — Verify (Credential & Token Validation)

## Purpose
Validate discovered credentials and API tokens against their respective services. Confirm whether leaked keys are still active, what permissions they carry, and what data they expose.

## Required Variables
- $TARGET: domain or organization name
- $OUTDIR: output directory for verification results

## Commands

```bash
mkdir -p $OUTDIR/verify

cat $OUTDIR/probe/consolidated_trufflehog.json \
  | jq -r '.[] | select(.Raw | test("^ghp_")) | .Raw' \
  | while read -r TOKEN; do
    RESP=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: token $TOKEN" \
      "https://api.github.com/user")
    echo "ghp_*** | status=$RESP"
  done > $OUTDIR/verify/github_token_results.txt

cat $OUTDIR/probe/consolidated_trufflehog.json \
  | jq -r '.[] | select(.Raw | test("^xox[bpras]-")) | .Raw' \
  | while read -r TOKEN; do
    curl -s -H "Authorization: Bearer $TOKEN" \
      "https://slack.com/api/auth.test" \
      | jq '{ok: .ok, user: .user, team: .team, url: .url}' \
      >> $OUTDIR/verify/slack_token_results.json
  done

cat $OUTDIR/probe/consolidated_trufflehog.json \
  | jq -r '.[] | select(.Raw | test("^sk_live_")) | .Raw' \
  | while read -r KEY; do
    curl -s -u "${KEY}:" "https://api.stripe.com/v1/balance" \
      | jq '{object: .object, pending: .pending[0].amount, available: .available[0].amount}' \
      >> $OUTDIR/verify/stripe_key_results.json
  done

find $OUTDIR -name "*.json" -o -name "*.txt" \
  | xargs rg -oI 'AKIA[0-9A-Z]{16}' 2>/dev/null \
  | sort -u | while read -r KEY; do
    echo "AKIA key found: $KEY"
  done > $OUTDIR/verify/aws_key_candidates.txt

find $OUTDIR -name "*.json" -o -name "*.txt" \
  | xargs rg -oI 'ya29\.[0-9A-Za-z\-_]+' 2>/dev/null \
  | while read -r TOKEN; do
    curl -s -H "Content-Type: application/x-www-form-urlencoded" \
      -d "access_token=$TOKEN" \
      "https://www.googleapis.com/oauth2/v1/tokeninfo" \
      | jq '{email: .email, scope: .scope, expires_in: .expires_in}' \
      >> $OUTDIR/verify/gcp_token_results.json
  done

find $OUTDIR -name "*trufflehog*" -o -name "*gitleaks*" \
  | xargs rg -oI '[A-Za-z0-9+/]{30,}={0,2}' 2>/dev/null \
  | sort -u > $OUTDIR/verify/high_entropy_candidates.txt

find $OUTDIR -name "*trufflehog*" -o -name "*gitleaks*" \
  | xargs rg -oI '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' 2>/dev/null \
  | sort -u > $OUTDIR/verify/discovered_emails.txt

while read -r EMAIL; do
  holehe "$EMAIL" --only-used 2>/dev/null \
    >> $OUTDIR/verify/holehe_results.txt
done < $OUTDIR/verify/discovered_emails.txt
```

## Detection Signals
- GitHub token returns HTTP 200 → token is active, note scopes from `X-OAuth-Scopes` header
- Slack `auth.test` returns `"ok": true` → full Slack workspace access confirmed
- Stripe `sk_live_` key returns balance data → live payment processing access
- GCP token returns `email` and `scope` → active with specific permissions
- `holehe` reports `"exists": true` for target email → account registered on that service

## Next
├── If active tokens/keys confirmed → proceed to `04-impact-escalation.md`
├── If tokens are expired/revoked → document as "previously leaked, now mitigated"
├── If no valid tokens → proceed to `06-false-positive-filter.md`
└── IMPORTANT: Do NOT use active credentials beyond verification. Document scope only.