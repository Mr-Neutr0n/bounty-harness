#!/usr/bin/env python3
"""
GitHub Secret Scanner — searches GitHub repos for exposed secrets.

Searches for patterns:
  - AWS keys (AKIA, ASIA)
  - Stripe keys (sk_live, sk_test)
  - GitHub tokens (ghp_, gho_, ghu_, ghs_)
  - Generic API keys, passwords, tokens
  - Private keys (-----BEGIN ... PRIVATE KEY-----)
  - Slack webhooks
  - JWT tokens
  - Google API keys
  - Heroku API keys

Uses GitHub code search API, then optionally clones repos for trufflehog deep scan.
Reports: repo, file, line, secret_type, secret_fragment (redacted)
Outputs findings.jsonl
"""

import argparse
import json
import sys
import os
import time
import re
import tempfile
import shutil
import subprocess
import urllib.parse
import urllib.request
import hashlib
import base64
from typing import Optional


SECRET_PATTERNS = [
    {
        "name": "aws_access_key",
        "regex": r"(?i)(?:AKIA|ASIA)[A-Z0-9]{16}",
        "redaction": lambda m: m.group()[:4] + "..." + m.group()[-4:],
    },
    {
        "name": "stripe_live_key",
        "regex": r"(?i)sk_live_[a-zA-Z0-9]{24,}",
        "redaction": lambda m: "sk_live_..." + m.group()[-8:],
    },
    {
        "name": "stripe_test_key",
        "regex": r"(?i)sk_test_[a-zA-Z0-9]{24,}",
        "redaction": lambda m: "sk_test_..." + m.group()[-8:],
    },
    {
        "name": "github_token",
        "regex": r"(?i)gh[pousr]_[A-Za-z0-9_]{36,}",
        "redaction": lambda m: m.group()[:8] + "...",
    },
    {
        "name": "private_key_header",
        "regex": r"-{3,}BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE|PGP)\s+KEY-{3,}",
        "redaction": lambda m: "-----BEGIN ... PRIVATE KEY-----",
    },
    {
        "name": "slack_webhook",
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "redaction": lambda m: "https://hooks.slack.com/..." + m.group()[-16:],
    },
    {
        "name": "google_api_key",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "redaction": lambda m: "AIza..." + m.group()[-8:],
    },
    {
        "name": "heroku_api_key",
        "regex": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "redaction": lambda m: "heroku_key_..." + m.group()[-12:],
    },
    {
        "name": "jwt_token",
        "regex": r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}",
        "redaction": lambda m: "eyJ..." + m.group()[-20:],
    },
    {
        "name": "generic_password",
        "regex": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"&<>]{4,}['\"]?",
        "redaction": lambda m: "password=...",
    },
    {
        "name": "generic_api_key",
        "regex": r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{8,}['\"]?",
        "redaction": lambda m: "api_key=..." + m.group()[-8:],
    },
    {
        "name": "generic_secret",
        "regex": r"(?i)(?:secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9\-_+/]{8,}['\"]?",
        "redaction": lambda m: "secret=..." + m.group()[-8:],
    },
]

GITHUB_SEARCH_QUERIES = [
    "{target_org} password",
    "{target_org} secret",
    '{target_org} "api_key"',
    '{target_org} "api key"',
    '{target_org} "access key"',
    '{target_org} "private key"',
    '{target_org} "-----BEGIN',
    '{target_org} AKIA',
    '{target_org} sk_live',
    '{target_org} ghp_',
    '{target_org} "authorization: Bearer"',
    '{target_org} "client_secret"',
    '{target_org} "secret_key"',
    '{target_org} "DATABASE_URL"',
    '{target_org} "password"',
    '{target_org} extension:env',
    '{target_org} filename:.env',
    '{target_org} filename:credentials',
    '{target_org} filename:config.json AWS_ACCESS_KEY',
    'org:{target_org} password',
    'org:{target_org} secret',
    'org:{target_org} "api key"',
]


def _redact(secret_type: str, match: re.Match, value: str) -> str:
    for sp in SECRET_PATTERNS:
        if sp["name"] == secret_type and "redaction" in sp:
            try:
                return sp["redaction"](match)
            except Exception:
                pass
    if len(value) > 12:
        return value[:4] + "..." + value[-4:]
    return value[:2] + "..." + value[-2:] if len(value) > 4 else "***"


def _search_github_code(gh_token: str, query: str) -> list:
    results = []
    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/code?q={encoded}&per_page=30"

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"token {gh_token}")
    req.add_header("Accept", "application/vnd.github.v3.text-match+json")
    req.add_header("User-Agent", "GitHubSecretScanner/1.0")

    try:
        resp = urllib.request.urlopen(req, timeout=20)
        data = json.loads(resp.read().decode())
        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            text_matches = item.get("text_matches", [])
            for tm in text_matches:
                fragment = tm.get("fragment", "")
                results.append({
                    "repo": repo,
                    "file": path,
                    "url": html_url,
                    "fragment": fragment,
                })
    except urllib.error.HTTPError as e:
        if e.code == 403:
            sys.stderr.write(f"  [!] Rate limited on search: {query[:60]}...\n")
        elif e.code == 422:
            pass
        else:
            sys.stderr.write(f"  [!] HTTP {e.code} on search: {query[:60]}...\n")
    except Exception as e:
        sys.stderr.write(f"  [!] Error searching: {e}\n")

    return results


def _scan_content_for_secrets(content: str) -> list:
    findings = []
    for sp in SECRET_PATTERNS:
        pattern = sp["regex"]
        for match in re.finditer(pattern, content, re.MULTILINE):
            value = match.group()
            findings.append({
                "secret_type": sp["name"],
                "line_number": content[:match.start()].count("\n") + 1,
                "match_value": value,
                "redacted": _redact(sp["name"], match, value),
                "match_position": (match.start(), match.end()),
            })
    return findings


def _run_trufflehog(repo_url: str, timeout: int) -> list:
    findings = []
    work_dir = tempfile.mkdtemp(prefix="gh_secret_")
    try:
        sys.stderr.write(f"    Cloning {repo_url}...\n")
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, work_dir],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            sys.stderr.write(f"    Clone failed: {result.stderr[:200]}\n")
            return findings

        th_cmd = shutil.which("trufflehog") or "trufflehog"
        sys.stderr.write(f"    Running trufflehog on {work_dir}...\n")
        result = subprocess.run(
            [th_cmd, "filesystem", work_dir, "--json", "--no-update"],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                findings.append({
                    "tool": "trufflehog",
                    "detector": entry.get("DetectorName", entry.get("SourceType", "")),
                    "raw": entry.get("Raw", "")[:200],
                    "redacted": entry.get("Redacted", ""),
                    "file": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                    "line": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                    "verified": entry.get("Verified", False),
                })
            except json.JSONDecodeError:
                pass
        sys.stderr.write(f"    Trufflehog found {len(findings)} result(s)\n")
    except FileNotFoundError:
        sys.stderr.write("    [!] trufflehog not found in PATH\n")
    except Exception as e:
        sys.stderr.write(f"    [!] Trufflehog error: {e}\n")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    return findings


def run_scan(target_org: str, gh_token: str, context: Optional[str], deep: bool, timeout: int, dry_run: bool) -> list:
    findings = []

    if dry_run:
        for q in GITHUB_SEARCH_QUERIES[:5]:
            formatted = q.format(target_org=target_org)
            findings.append({
                "search_query": formatted,
                "dry_run": True,
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
        return findings

    seen_repos = set()

    for qidx, query_template in enumerate(GITHUB_SEARCH_QUERIES):
        query = query_template.format(target_org=target_org)
        sys.stderr.write(f"[{qidx+1}/{len(GITHUB_SEARCH_QUERIES)}] Searching: {query[:80]}...\n")

        items = _search_github_code(gh_token, query)
        time.sleep(2)

        for item in items:
            content_findings = _scan_content_for_secrets(item["fragment"])
            for cf in content_findings:
                findings.append({
                    "source": "github_search",
                    "repo": item["repo"],
                    "file": item["file"],
                    "url": item["url"],
                    "line": cf["line_number"],
                    "secret_type": cf["secret_type"],
                    "secret_fragment": cf["redacted"],
                    "context": context,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
            seen_repos.add(item["repo"])

        if len(items) > 0:
            sys.stderr.write(f"  Found {len(items)} results\n")

    if deep and seen_repos:
        sys.stderr.write(f"\n[*] Deep scan: cloning {len(seen_repos)} repo(s) for trufflehog analysis\n")
        for repo in seen_repos:
            clone_url = f"https://{gh_token}@github.com/{repo}.git"
            try:
                th_findings = _run_trufflehog(clone_url, timeout)
                for tf in th_findings:
                    finding = {
                        "source": "trufflehog",
                        "repo": repo,
                        "file": tf.get("file", ""),
                        "line": tf.get("line", 0),
                        "secret_type": tf.get("detector", ""),
                        "secret_fragment": tf.get("redacted", tf.get("raw", "")[:200]),
                        "verified": tf.get("verified", False),
                        "context": context,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    findings.append(finding)
            except Exception as e:
                sys.stderr.write(f"  [!] Failed to clone {repo}: {e}\n")

    if not findings:
        findings.append({
            "source": "summary",
            "repo": "",
            "file": "",
            "url": "",
            "line": 0,
            "secret_type": "",
            "secret_fragment": "",
            "context": context,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Secret Scanner — search GitHub for exposed secrets",
        epilog="Example: python3 github_secret_scanner.py --target-org acme-corp --gh-token ghp_xxxx",
    )
    parser.add_argument("--target-org", required=True, help="GitHub organization or user name to search")
    parser.add_argument("--gh-token", help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--deep", action="store_true", help="Clone repos and run trufflehog for deep scanning")
    parser.add_argument("--timeout", type=int, default=120, help="Clone/trufflehog timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Show search queries without making API calls")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    gh_token = args.gh_token or os.environ.get("GITHUB_TOKEN", "")
    if not gh_token and not args.dry_run:
        sys.stderr.write("[!] No GitHub token provided. Set --gh-token or GITHUB_TOKEN env var.\n")
        sys.stderr.write("[!] Without a token, rate limits are very strict (10 req/min).\n")

    sys.stderr.write(f"[*] GitHub Secret Scanner\n")
    sys.stderr.write(f"[*] Target org: {args.target_org}\n")
    sys.stderr.write(f"[*] Deep scan: {args.deep}\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")

    findings = run_scan(args.target_org, gh_token, args.context, args.deep, args.timeout, args.dry_run)

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    sys.stderr.write(f"\n[*] Findings written to {outfile}\n")

    by_type = {}
    for f in findings:
        st = f.get("secret_type", "unknown")
        by_type[st] = by_type.get(st, 0) + 1

    sys.stderr.write(f"[*] Summary: {len(findings)} total findings\n")
    for st, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
        if st != "dry_run":
            sys.stderr.write(f"  {st}: {cnt}\n")

    print(json.dumps({
        "total_findings": len(findings),
        "by_type": {k: v for k, v in by_type.items() if k != "dry_run"},
    }, indent=2))


if __name__ == "__main__":
    main()