#!/usr/bin/env python3
"""
IAM PrivEsc Scanner — enumerates AWS IAM and identifies privilege escalation paths.

Requires boto3 (`pip install boto3`) and valid AWS credentials.

Checks:
  - Users, roles, policies listing
  - Over-permissive policies (*:*, Action:*)
  - iam:CreateAccessKey + iam:ListAccessKeys chain
  - iam:CreateLoginProfile
  - iam:UpdateLoginProfile
  - lambda:CreateFunction + lambda:InvokeFunction (role assumption)
  - cloudformation:CreateStack
  - s3:PutBucketPolicy
  - iam:AttachRolePolicy (can attach AdministratorAccess)
  - sts:AssumeRole on "*"

Reports: resource, risky_action, privesc_possible, privesc_path
Outputs findings.jsonl
"""

import argparse
import json
import sys
import os
import time
import re
from typing import Optional


KNOWN_PATHS = [
    {
        "name": "CreateAccessKey + ListAccessKeys",
        "required": ["iam:CreateAccessKey", "iam:ListAccessKeys"],
        "description": "Create a new access key for another IAM user, then use their credentials",
        "severity": "CRITICAL",
    },
    {
        "name": "CreateLoginProfile",
        "required": ["iam:CreateLoginProfile"],
        "description": "Create a console login profile for a user who doesn't have one",
        "severity": "CRITICAL",
    },
    {
        "name": "UpdateLoginProfile",
        "required": ["iam:UpdateLoginProfile"],
        "description": "Change another user's console password",
        "severity": "CRITICAL",
    },
    {
        "name": "AttachRolePolicy (AdminAccess)",
        "required": ["iam:AttachRolePolicy"],
        "description": "Attach AdministratorAccess to a role you can assume",
        "severity": "CRITICAL",
    },
    {
        "name": "PutRolePolicy (*)",
        "required": ["iam:PutRolePolicy"],
        "description": "Attach an inline policy granting full access to a role you can assume",
        "severity": "CRITICAL",
    },
    {
        "name": "UpdateAssumeRolePolicy",
        "required": ["iam:UpdateAssumeRolePolicy"],
        "description": "Modify trust policy to allow yourself to assume the role",
        "severity": "CRITICAL",
    },
    {
        "name": "Lambda CreateFunction + InvokeFunction",
        "required": ["lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": "Create a Lambda with an elevated role, then invoke it",
        "severity": "CRITICAL",
    },
    {
        "name": "CloudFormation CreateStack",
        "required": ["cloudformation:CreateStack"],
        "description": "Create a stack with an elevated IAM role",
        "severity": "CRITICAL",
    },
    {
        "name": "CloudFormation ExecuteChangeSet",
        "required": ["cloudformation:ExecuteChangeSet"],
        "description": "Execute a change set with elevated permissions",
        "severity": "HIGH",
    },
    {
        "name": "S3 PutBucketPolicy",
        "required": ["s3:PutBucketPolicy"],
        "description": "Set a permissive bucket policy, then use the bucket to escalate",
        "severity": "MEDIUM",
    },
    {
        "name": "STS AssumeRole on *",
        "required": ["sts:AssumeRole"],
        "description": "If resource is '*' for sts:AssumeRole, can assume any cross-account role",
        "severity": "CRITICAL",
    },
    {
        "name": "EC2 RunInstances",
        "required": ["ec2:RunInstances"],
        "description": "Launch EC2 with an instance profile that has elevated privileges",
        "severity": "CRITICAL",
    },
    {
        "name": "Glue CreateDevEndpoint",
        "required": ["glue:CreateDevEndpoint"],
        "description": "Create a Glue dev endpoint with elevated role",
        "severity": "HIGH",
    },
    {
        "name": "SageMaker CreateNotebookInstance",
        "required": ["sagemaker:CreateNotebookInstance"],
        "description": "Create a notebook instance with elevated IAM role",
        "severity": "HIGH",
    },
    {
        "name": "DataPipeline CreatePipeline",
        "required": ["datapipeline:CreatePipeline"],
        "description": "Create a pipeline with elevated role, then update it",
        "severity": "HIGH",
    },
    {
        "name": "CodeStar CreateProject",
        "required": ["codestar:CreateProject"],
        "description": "Create a CodeStar project with elevated service role",
        "severity": "HIGH",
    },
]


def _normalize_action(action: str) -> str:
    return action.lower().replace(" ", "")


def _collect_actions_from_policy(policy_doc: dict) -> list:
    actions = []
    if not isinstance(policy_doc, dict):
        return actions

    for statement in policy_doc.get("Statement", []):
        if not isinstance(statement, dict):
            continue
        raw = statement.get("Action", [])
        if isinstance(raw, str):
            actions.append(_normalize_action(raw))
        elif isinstance(raw, list):
            for a in raw:
                actions.append(_normalize_action(a))
    return list(set(actions))


def _is_dangerous_pattern(action: str) -> bool:
    dangerous = ["*:*", "*", "iam:*", "s3:*", "ec2:*", "lambda:*", "sts:*", "cloudformation:*"]
    return action in dangerous


def run_scan(
    credentials_file: Optional[str],
    profile: Optional[str],
    context: Optional[str],
    dry_run: bool,
) -> list:
    if dry_run:
        return [{
            "resource": "dry_run",
            "risky_action": "",
            "privesc_possible": False,
            "privesc_path": "",
            "severity": "INFO",
            "description": "Dry run — no AWS API calls made",
            "context": context,
            "dry_run": True,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]

    try:
        import boto3
    except ImportError:
        sys.stderr.write("[!] boto3 not installed. Run: pip install boto3\n")
        return [{
            "resource": "error",
            "risky_action": "",
            "privesc_possible": False,
            "privesc_path": "",
            "severity": "ERROR",
            "description": "boto3 not installed. Run: pip install boto3",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]

    findings = []

    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        sys.stderr.write(f"[*] Authenticated as: {identity.get('Arn', 'unknown')}\n")
    except Exception as e:
        sys.stderr.write(f"[!] AWS authentication failed: {e}\n")
        findings.append({
            "resource": "auth",
            "risky_action": "",
            "privesc_possible": False,
            "privesc_path": "",
            "severity": "ERROR",
            "description": f"AWS auth failed: {e}",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        return findings

    iam = session.client("iam")

    sys.stderr.write("[*] Enumerating IAM users...\n")
    users = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
        sys.stderr.write(f"  Found {len(users)} user(s)\n")
    except Exception as e:
        sys.stderr.write(f"  [!] Cannot list users: {e}\n")

    sys.stderr.write("[*] Enumerating IAM roles...\n")
    roles = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))
        sys.stderr.write(f"  Found {len(roles)} role(s)\n")
    except Exception as e:
        sys.stderr.write(f"  [!] Cannot list roles: {e}\n")

    sys.stderr.write("[*] Enumerating IAM policies...\n")
    policies = []
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=False):
            policies.extend(page.get("Policies", []))
    except Exception as e:
        sys.stderr.write(f"  [!] Cannot list policies: {e}\n")
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="AWS", OnlyAttached=False):
            aws_pol = page.get("Policies", [])
            for p in aws_pol:
                if p["Arn"] in ("arn:aws:iam::aws:policy/AdministratorAccess",):
                    policies.append(p)
    except Exception:
        pass

    sys.stderr.write(f"  Found {len(policies)} policy/policies\n")

    user_policies_map = {}
    for user in users[:20]:
        username = user["UserName"]
        try:
            attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            inline_names = iam.list_user_policies(UserName=username).get("PolicyNames", [])
            user_policies_map[username] = {
                "arn": user["Arn"],
                "attached": [p["PolicyArn"] for p in attached],
                "inline": inline_names,
            }
        except Exception:
            user_policies_map[username] = {"arn": user["Arn"], "attached": [], "inline": []}

    role_policies_map = {}
    for role in roles[:20]:
        rolename = role["RoleName"]
        try:
            attached = iam.list_attached_role_policies(RoleName=rolename).get("AttachedPolicies", [])
            inline_names = iam.list_role_policies(RoleName=rolename).get("PolicyNames", [])
            role_policies_map[rolename] = {
                "arn": role["Arn"],
                "attached": [p["PolicyArn"] for p in attached],
                "inline": inline_names,
            }
        except Exception:
            role_policies_map[rolename] = {"arn": role["Arn"], "attached": [], "inline": []}

    all_actions = set()

    for p in policies[:30]:
        arn = p.get("Arn", "")
        try:
            ver = iam.get_policy_version(
                PolicyArn=arn,
                VersionId=p.get("DefaultVersionId", "v1"),
            )
            doc = ver.get("PolicyVersion", {}).get("Document", {})
            actions = _collect_actions_from_policy(doc)
            all_actions.update(actions)

            for action in actions:
                if _is_dangerous_pattern(action):
                    findings.append({
                        "resource": arn,
                        "risky_action": action,
                        "privesc_possible": True,
                        "privesc_path": f"Policy {arn} allows {action!r} — full admin access",
                        "severity": "CRITICAL",
                        "description": f"Policy grants dangerous permission pattern: {action!r}",
                        "context": context,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })

        except Exception:
            pass

    for path_def in KNOWN_PATHS:
        path_actions = path_def["required"]
        has_all = True
        for pa in path_actions:
            found = False
            for action in all_actions:
                if pa.lower() in action.lower():
                    found = True
                    break
            if not found:
                has_all = False
                break

        if has_all:
            findings.append({
                "resource": "combined_policies",
                "risky_action": ", ".join(path_actions),
                "privesc_possible": True,
                "privesc_path": path_def["name"],
                "severity": path_def["severity"],
                "description": path_def["description"],
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

    wildcard_actions = [a for a in all_actions if a.endswith("*") and not _is_dangerous_pattern(a)]
    for wa in wildcard_actions:
        findings.append({
            "resource": "combined_policies",
            "risky_action": wa,
            "privesc_possible": False,
            "privesc_path": "",
            "severity": "MEDIUM",
            "description": f"Wildcard action {wa!r} may allow unintended privilege escalation",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    if not findings:
        findings.append({
            "resource": "overall",
            "risky_action": "",
            "privesc_possible": False,
            "privesc_path": "",
            "severity": "INFO",
            "description": "No obvious privilege escalation paths detected",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="IAM PrivEsc Scanner — enumerate AWS IAM for privilege escalation paths",
        epilog="Requires boto3 (`pip install boto3`) and valid AWS credentials.",
    )
    parser.add_argument("--profile", default=None, help="AWS profile name (from ~/.aws/credentials)")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be scanned without making API calls")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    sys.stderr.write(f"[*] IAM PrivEsc Scanner\n")
    if args.profile:
        sys.stderr.write(f"[*] AWS Profile: {args.profile}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")
    sys.stderr.write(f"[*] Dry run: {args.dry_run}\n")

    findings = run_scan(
        credentials_file=None,
        profile=args.profile,
        context=args.context,
        dry_run=args.dry_run,
    )

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    sys.stderr.write(f"\n[*] Findings written to {outfile}\n")

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    sys.stderr.write(f"[*] Summary: {critical} CRITICAL, {high} HIGH, {len(findings)} total\n")

    for f in findings:
        if f.get("severity") in ("CRITICAL", "HIGH"):
            sys.stderr.write(f"  [{f['severity']}] {f.get('privesc_path', f.get('risky_action', ''))}: {f.get('description', '')}\n")

    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()