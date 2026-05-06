#!/usr/bin/env python3
"""
Google Dork Runner — runs Google dork patterns programmatically.

Uses googlesearch-python for direct Google searches.
Accepts a dork file with patterns like:
  - site:{target_org}
  - site:{target_org} filetype:pdf
  - site:{target_org} inurl:admin
  - intitle:"index of" {target_org}
  - etc.

Respects rate limiting between queries.
Reports: dork_query, result_url, snippet
Outputs findings.jsonl
"""

import argparse
import json
import sys
import os
import time
import re
import urllib.parse
import urllib.request
from typing import Optional


DEFAULT_DORKS = [
    "site:{target}",
    "site:{target} filetype:pdf",
    "site:{target} filetype:sql",
    "site:{target} filetype:env",
    "site:{target} filetype:log",
    "site:{target} filetype:sql \"password\"",
    "site:{target} filetype:bak",
    "site:{target} filetype:backup",
    "site:{target} inurl:admin",
    "site:{target} inurl:login",
    "site:{target} inurl:register",
    "site:{target} inurl:signup",
    "site:{target} inurl:config",
    "site:{target} inurl:.env",
    "site:{target} inurl:wp-admin",
    "site:{target} inurl:phpmyadmin",
    "site:{target} intitle:\"index of\"",
    "site:{target} intitle:\"dashboard\"",
    "site:{target} intitle:\"admin\"",
    "site:{target} \"password\"",
    "site:{target} \"secret\"",
    "site:{target} \"api key\"",
    "site:{target} \"confidential\"",
    "site:{target} \"internal use only\"",
    "site:{target} \"not for distribution\"",
    "site:{target} \"AWS_ACCESS_KEY\"",
    "site:{target} \"DATABASE_URL\"",
    "site:{target} \"smtp_password\"",
    "site:{target} ext:swp",
    "site:{target} ext:git",
    "site:{target} ext:ini",
    "site:{target} ext:conf",
    "site:{target} ext:config",
    "site:{target} ext:yml ext:yaml",
    "site:{target} ext:json",
    "site:{target} ext:xml",
    "site:{target} ext:csv",
    "site:pastebin.com {target}",
    "site:github.com {target}",
    "site:gitlab.com {target}",
    "site:bitbucket.org {target}",
    "site:trello.com {target}",
    "site:docs.google.com {target}",
    "site:codepen.io {target}",
    "site:jsfiddle.net {target}",
    "intitle:\"{target}\"",
    "inurl:\"{target}\"",
    "\"{target}\" \"password\"",
    "\"{target}\" \"secret_key\"",
    "\"{target} staging\"",
    "\"{target} dev\"",
    "\"{target} internal\"",
    "\"{target} confidential\"",
    "\"@target.com\" filetype:csv",
    "\"@target.com\" filetype:xlsx",
]


def _parse_dork_file(filepath: str) -> list:
    patterns = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def _search_google(query: str, num_results: int, language: str) -> list:
    results = []

    sys.stderr.write(f"    Searching Google...\n")

    encoded_query = urllib.parse.quote(query)
    if language:
        encoded_query = f"{encoded_query}&lr=lang_{language}"

    url = f"https://www.google.com/search?q={encoded_query}&num=10"

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=15)
        html_content = resp.read().decode(errors="replace")

        link_pattern = re.compile(r'href="/url\?q=(https?://[^&\"]+)')
        snippet_pattern = re.compile(r'<div[^>]*class="[^"]*BNeawe[^"]*"[^>]*>(.*?)</div>')

        links = link_pattern.findall(html_content)
        snippets = snippet_pattern.findall(html_content)

        for i, link in enumerate(links[:num_results]):
            clean_link = urllib.parse.unquote(link.split("&")[0])
            snippet = _strip_html(snippets[i]) if i < len(snippets) else ""
            results.append({
                "url": clean_link,
                "snippet": snippet[:500],
            })

    except urllib.error.HTTPError as e:
        sys.stderr.write(f"    [!] HTTP {e.code} — Google may be blocking automated requests\n")
    except Exception as e:
        sys.stderr.write(f"    [!] Error: {e}\n")

    return results


def _strip_html(text: str) -> str:
    clean = re.compile(r"<[^>]+>").sub("", text)
    clean = html_unescape(clean)
    return clean


def html_unescape(text: str) -> str:
    from html import unescape
    return unescape(text)


def run_dorks(
    target: str,
    dork_file: Optional[str],
    num_results: int,
    language: str,
    context: Optional[str],
    dry_run: bool,
) -> list:
    if dork_file:
        dorks = _parse_dork_file(dork_file)
    else:
        dorks = list(DEFAULT_DORKS)

    sys.stderr.write(f"[*] Loaded {len(dorks)} dork pattern(s)\n")

    findings = []

    for didx, dork_template in enumerate(dorks):
        try:
            dork_query = dork_template.format(target=target)
        except KeyError:
            dork_query = dork_template.replace("{target}", target)

        if dry_run:
            findings.append({
                "dork_query": dork_query,
                "dry_run": True,
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            sys.stderr.write(f"[dry-run] {didx+1}/{len(dorks)}: {dork_query[:80]}...\n")
            continue

        sys.stderr.write(f"[{didx+1}/{len(dorks)}] {dork_query[:80]}...\n")

        results = _search_google(dork_query, num_results, language)

        for result in results:
            findings.append({
                "dork_query": dork_query,
                "result_url": result["url"],
                "snippet": result["snippet"],
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        if not results:
            findings.append({
                "dork_query": dork_query,
                "result_url": "",
                "snippet": "",
                "context": context,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        delay = 5 + (2 * (didx % 3))
        sys.stderr.write(f"    Sleeping {delay}s to avoid rate limiting...\n")
        time.sleep(delay)

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Google Dork Runner — run Google dork patterns programmatically",
        epilog="Example: python3 google_dork_runner.py --target example.com --dork-file dorks.txt",
    )
    parser.add_argument("--target", required=True, help="Target domain or keyword for dork substitution")
    parser.add_argument("--dork-file", default=None, help="File containing dork patterns (one per line, uses {target} placeholder)")
    parser.add_argument("--num-results", type=int, default=10, help="Maximum results per dork (default: 10)")
    parser.add_argument("--language", default="", help="Language code filter (e.g., en, de, fr)")
    parser.add_argument("--context", default=None, help="Assessment context string")
    parser.add_argument("--dry-run", action="store_true", help="Show dork queries without making requests")
    parser.add_argument("--output", default=None, help="Output JSONL file path (default: findings.jsonl)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output on stderr")
    args = parser.parse_args()

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    sys.stderr.write(f"[*] Google Dork Runner\n")
    sys.stderr.write(f"[*] Target: {args.target}\n")
    if args.dork_file:
        sys.stderr.write(f"[*] Dork file: {args.dork_file}\n")
    else:
        sys.stderr.write(f"[*] Using {len(DEFAULT_DORKS)} built-in dork patterns\n")
    if args.context:
        sys.stderr.write(f"[*] Context: {args.context}\n")
    sys.stderr.write(f"[*] Dry run: {args.dry_run}\n")

    findings = run_dorks(args.target, args.dork_file, args.num_results, args.language, args.context, args.dry_run)

    outfile = args.output or "findings.jsonl"
    with open(outfile, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    sys.stderr.write(f"\n[*] Findings written to {outfile}\n")

    with_results = sum(1 for f in findings if f.get("result_url"))
    sys.stderr.write(f"[*] Summary: {len(findings)} entries, {with_results} had URL results\n")

    print(json.dumps({
        "total_entries": len(findings),
        "entries_with_urls": with_results,
        "target": args.target,
    }, indent=2))


if __name__ == "__main__":
    main()