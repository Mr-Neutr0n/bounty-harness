# Vulnerability Intelligence

## Overview
Automated vulnerability intelligence gathering for bug bounty targets. Searches NVD, GitHub Security Advisories, disclosed bug bounty reports, proof-of-concept repositories, and security news — then maps findings to technique-kb entries for actionable test plans.

## Quick Reference
- **Skill**: vuln-intel
- **Version**: 1.0.0
- **Bounded Context**: VulnIntelContext
- **Required tools**: `python3`, `curl`
- **Risk tier**: passive (read-only API queries, no target interaction)
- **API keys**: None required for basic operation

## Available Workflows

| Workflow | Purpose | Safety Tier |
|---|---|---|
| `search-cves` | Search NVD for CVEs related to target | passive |
| `search-reports` | Search disclosed bug bounty reports | passive |
| `search-pocs` | Search GitHub for proof-of-concept code | passive |
| `search-news` | Search security news about target | passive |
| `generate-report` | Full intelligence report from all sources | passive |
| `correlate-techniques` | Map findings to technique-kb entries | passive |

## Workflow Selection

| Intent | Workflow |
|---|---|
| Find recent CVEs for target | `search-cves` |
| Find disclosed reports for program | `search-reports` |
| Find PoCs for specific CVE | `search-pocs` |
| Find security news about target | `search-news` |
| Full intelligence report | `generate-report` |
| Map findings to test techniques | `correlate-techniques` |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `INTEL_DAYS` | 60 | Lookback period for CVEs and news |
| `INTEL_CVSS_MIN` | 0.0 | Minimum CVSS score filter |
| `INTEL_PLATFORMS` | hackerone,bugcrowd | Platforms to search for disclosed reports |
| `TECHNIQUE_KB_DIR` | .claude/skills/technique-kb/ | Path to technique knowledge base |

## Evidence Required
For every intelligence finding, collect:
- CVE metadata (ID, description, CVSS, published date, references)
- Disclosed report metadata (ID, platform, title, URL, bounty amount if known)
- PoC repository metadata (stars, language, last updated, license)
- Correlation mapping between CVEs and technique-kb entries
- Screenshot or archive of source pages (for ephemeral content)
- Timestamp of search query execution

## References
- NVD API documentation: https://nvd.nist.gov/developers
- GitHub Security Advisories API
- OWASP WSTG-INFO-01 (Conduct Search Engine Discovery)
- OWASP WSTG-INFO-02 (Fingerprint Web Server)
