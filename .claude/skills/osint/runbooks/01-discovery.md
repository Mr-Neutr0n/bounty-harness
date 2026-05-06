# OSINT — Discovery

## Purpose
Enumerate exposed code, config files, and infrastructure for the target organization via GitHub, Google, Shodan, and Censys. Surface leaked secrets, misconfigured repos, and forgotten deployment artifacts.

## Required Variables
- $TARGET: domain or organization name (e.g., `example.com` or `example-org`)
- $OUTDIR: output directory for collected results

## Commands

```bash
mkdir -p $OUTDIR/discovery

gh search code "org:$TARGET" --limit 100 --json url,repository,path \
  | jq -r '.[] | "\(.repository.url)/blob/HEAD/\(.path)"' \
  > $OUTDIR/discovery/github_code_urls.txt

gh search code "org:$TARGET password OR secret OR token OR api_key OR private_key" \
  --limit 50 --json url,repository,path,matches \
  > $OUTDIR/discovery/github_secrets_raw.json

gh search code "org:$TARGET filename:.env" --limit 50 \
  --json url,repository,path \
  > $OUTDIR/discovery/github_env_files.json

gh search code "org:$TARGET filename:config OR filename:.npmrc OR filename:.pypirc" \
  --limit 50 --json url,repository,path \
  > $OUTDIR/discovery/github_config_files.json

curl -s -G "https://www.google.com/search" \
  --data-urlencode "q=site:${TARGET} ext:env OR ext:sql OR ext:log OR ext:bak OR ext:swp OR ext:yml" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
  > $OUTDIR/discovery/google_dorks_raw.html

curl -s "https://internetdb.shodan.io/${TARGET}" \
  | jq '.' > $OUTDIR/discovery/shodan_target.json

curl -s "https://search.censys.io/api/v2/hosts/search?q=${TARGET}&per_page=50" \
  -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  | jq '.result.hits[] | {ip: .ip, services: .services[].service_name, ports: .services[].port}' \
  > $OUTDIR/discovery/censys_hosts.json

curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[] | "\(.name_value) | issued: \(.entry_timestamp) | issuer: \(.issuer_name)"' \
  | sort -u > $OUTDIR/discovery/cert_transparency.txt
```

## Detection Signals
- `.env`, `.npmrc`, `.pypirc` files found in public repos
- Strings matching `password`, `secret`, `token`, `api_key`, `private_key` in search results
- Open ports on Shodan/Censys indicating exposed databases (3306, 5432, 27017, 6379)
- Wildcard TLS certificates exposing internal subdomains

## Next
├── If secrets or config files found → proceed to `02-probe.md`
├── If infrastructure exposed → proceed to `03-verify.md`
├── If no findings → try variation: no `org:` qualifier, use `user:` or bare search
└── If rate limited → wait 60s and retry with `--limit 30`