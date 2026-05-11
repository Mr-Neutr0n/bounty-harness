# Workflow: Search Security News

## Purpose
Find recent security news, blog posts, and researcher chatter about your target.

## Execution
```bash
bin/bb-run vuln-intel search-news
```

## What It Does
1. Searches DuckDuckGo for security-related news about target
2. Returns article URLs and titles
3. Filters for recent content based on INTEL_DAYS setting

## Interpreting Results
- **Recent breach disclosures** → May indicate ongoing security work or new scope
- **Researcher writeups** → Reveal attack techniques that worked
- **Vendor advisories** → Official confirmation of vulnerabilities

## Next Steps
- Read full articles for technical details
- Check if disclosed issues are patched
- Update scope or test plan based on new information
