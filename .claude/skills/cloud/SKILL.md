# Cloud

## Overview
Multi-cloud security testing — S3/GCP/Azure storage buckets, IAM enumeration, Lambda/Cloud Functions, metadata attacks, container registry, K8s clusters

This is a thin human-facing router. Use `skill.yaml` as the source of truth for exact commands, inputs, outputs, and workflow chaining.

## Quick Reference
- Skill: `cloud`
- Severity range: `medium`, `high`, `critical`
- Required tools: `aws`, `gcloud`, `az`, `curl`, `ffuf`, `python3`, `dnsx`, `subfinder`, `jq`, `openssl`, `trufflehog`
- Expected input files: `takeover_candidates.txt`, `all_urls.txt`, `live_urls.txt`
- Scope check: confirm authorization before running intrusive or authenticated testing.

## Workflow Selection
- Start with `s3-buckets` unless prior evidence points to a more specific workflow.
- Follow each workflow `next` mapping in `skill.yaml` after reviewing generated findings.
- If a workflow has no script reference, treat it as a manual or tool-native workflow and use the closest phase runbook when available.
- Runbooks: use `runbooks/` and select the closest phase runbook when workflow names do not map 1:1.

## Available Workflows
| Workflow | Purpose | Script paths | Primary outputs | Evidence |
| --- | --- | --- | --- | --- |
| `s3-buckets` | Enumerate likely S3 bucket names and test for public exposure. | `.claude/skills/cloud/scripts/s3_bucket_enumerator.py` | `$OUTDIR/cloud/aws/s3/findings.jsonl` | `$OUTDIR/cloud/aws/s3/evidence/` |
| `aws-iam-privesc` | Scan the configured AWS profile for IAM privilege escalation paths. | `.claude/skills/cloud/scripts/iam_privesc_scanner.py` | `$OUTDIR/cloud/aws/iam/findings.jsonl` | `$OUTDIR/cloud/aws/iam/evidence/` |

## Evidence Required
- Save raw request and response data for each confirmed finding.
- Include timestamps, affected target, exact workflow name, tool versions, and reproduction steps.
- Store screenshots or terminal captures in the workflow evidence directory when the workflow defines one.
- Evidence templates from `skill.yaml`:
- `s3_public_object`: curl response showing S3 object accessible without auth
- `iam_priv_esc`: Policy document showing privilege escalation path
- `metadata_creds`: Extracted AWS/GCP/Azure credentials from metadata service

## References
- Source of truth: `skill.yaml`
- Runbooks: `runbooks/`
- OWASP mappings: none listed in `skill.yaml`.
