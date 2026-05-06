# How to Search Techniques

## Free-text keyword search

```bash
cd .claude/skills/technique-kb
python3 scripts/technique_search.py \
  --techniques-dir techniques \
  --query "SQL injection"
```

Searches across id, name, description, category, severity, tags, standards, signals, auth, and inputs.

## Fielded search

| Prefix | Example | Matches |
|---|---|---|
| `category:` | `category:xss` | All XSS techniques |
| `severity:` | `severity:critical` | Critical severity only |
| `wstg:` | `wstg:INPV-05` | Techniques referencing WSTG-INPV-05 |
| `asvs:` | `asvs:V5.3.4` | ASVS V5.3.4 references |
| `cwe:` | `cwe:79` | CWE-79 (XSS) techniques |
| `vrt:` | `vrt:idor` | HackerOne VRT IDOR techniques |
| `tag:` | `tag:oob` | Out-of-band techniques |
| `auth:` | `auth:two_accounts` | Requiring two user accounts |
| `id:` | `id:xss-stored` | Exact technique ID match |

## Output format

JSON object with `query`, `search_type`, `total`, and `results` array. Each result has:
- `id`, `name`, `category`, `severity`
- `description` (truncated to 200 chars)
- `standards` (full standards object)
- `workflow` (skill and workflow mapping)
- `file` (relative path in techniques directory)

## Advanced: piping to jq

```bash
python3 scripts/technique_search.py --techniques-dir techniques --query "severity:critical" | \
  jq '.results[] | "\(.id) (\(.category)): \(.name)"'
```