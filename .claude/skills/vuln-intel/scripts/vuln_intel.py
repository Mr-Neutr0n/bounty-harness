#!/usr/bin/env python3
"""Vulnerability Intelligence Engine — automated CVE tracking, disclosed report hunting,
PoC discovery, and security news aggregation for bug bounty targets.

Uses free APIs and web search (no API keys required for basic operation):
  - NVD REST API (api.nvd.nist.gov)
  - GitHub REST API (api.github.com)
  - DuckDuckGo Lite HTML search
  - HackerOne public report search

Usage:
    vuln_intel.py search-cves --target anthropic.com --days 60
    vuln_intel.py search-reports --program "Anthropic" --platforms hackerone
    vuln_intel.py search-pocs --cve CVE-2024-1234
    vuln_intel.py search-news --target "anthropic" --days 30
    vuln_intel.py generate-report --target anthropic.com --days 60 --output report.json
    vuln_intel.py correlate --target anthropic.com --program "Anthropic" --technique-kb .claude/skills/technique-kb/
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API_BASE = "https://api.github.com"
DDG_LITE_URL = "https://lite.duckduckgo.com/lite/"
H1_PUBLIC_URL = "https://hackerone.com/reports/search"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> tuple[int, str]:
    """Simple HTTP GET with rate-limit awareness."""
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Security Research; Bug Bounty Toolkit)",
        "Accept": "application/json, text/html",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def parse_nvd_date(d: str) -> str:
    """Convert NVD date format to ISO."""
    if not d:
        return ""
    try:
        dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return d


def search_nvd(
    keyword: str,
    days: int = 60,
    cvss_min: float = 0.0,
    max_results: int = 100,
) -> List[Dict[str, Any]]:
    """Search NVD for CVEs matching keyword, published within last N days."""
    log(f"Searching NVD for '{keyword}' (last {days} days, CVSS >= {cvss_min})")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    results: List[Dict[str, Any]] = []
    start_index = 0
    batch_size = 20

    while len(results) < max_results:
        params = {
            "pubStartDate": since,
            "keywordSearch": keyword,
            "resultsPerPage": str(batch_size),
            "startIndex": str(start_index),
        }
        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
        status, body = http_get(url)
        if status != 200:
            log(f"NVD API error {status}: {body[:200]}")
            break
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            log("NVD API returned non-JSON")
            break

        cves = data.get("vulnerabilities", [])
        if not cves:
            break

        for item in cves:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {})
                    break

            score = cvss.get("baseScore", 0.0) if cvss else 0.0
            severity = cvss.get("baseSeverity", "UNKNOWN") if cvss else "UNKNOWN"

            if score < cvss_min:
                continue

            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
            published = parse_nvd_date(cve.get("published", ""))
            modified = parse_nvd_date(cve.get("lastModified", ""))

            results.append({
                "source": "nvd",
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": score,
                "severity": severity,
                "published": published,
                "modified": modified,
                "references": refs,
                "keyword": keyword,
            })

        total = data.get("totalResults", 0)
        start_index += batch_size
        if start_index >= total or start_index >= max_results:
            break
        time.sleep(0.6)  # NVD rate limit: ~1 req/sec

    log(f"NVD: found {len(results)} CVEs")
    return results


def search_github_pocs(cve_id: str, max_results: int = 20) -> List[Dict[str, Any]]:
    """Search GitHub for PoC repositories related to a CVE."""
    log(f"Searching GitHub PoCs for {cve_id}")
    query = urllib.parse.quote(f"{cve_id} poc OR exploit OR proof-of-concept")
    url = f"{GITHUB_API_BASE}/search/repositories?q={query}&sort=updated&order=desc&per_page={max_results}"
    status, body = http_get(url)
    if status != 200:
        log(f"GitHub API error {status}: {body[:200]}")
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        log("GitHub API returned non-JSON")
        return []

    items = data.get("items", [])
    results = []
    for item in items:
        results.append({
            "source": "github_poc",
            "cve_id": cve_id,
            "repo": item.get("full_name", ""),
            "url": item.get("html_url", ""),
            "description": item.get("description", ""),
            "stars": item.get("stargazers_count", 0),
            "updated": item.get("updated_at", ""),
            "language": item.get("language", ""),
        })
    log(f"GitHub: found {len(results)} PoC repos")
    return results


def search_github_advisories(keyword: str, max_results: int = 20) -> List[Dict[str, Any]]:
    """Search GitHub Security Advisories."""
    log(f"Searching GitHub advisories for '{keyword}'")
    query = urllib.parse.quote(keyword)
    url = f"{GITHUB_API_BASE}/advisories?per_page={max_results}&keyword={query}"
    status, body = http_get(url)
    if status != 200:
        log(f"GitHub Advisories API error {status}")
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []

    results = []
    for item in data if isinstance(data, list) else []:
        cve_id = ""
        for cve in item.get("cves", []):
            if cve.get("cve_id", "").startswith("CVE-"):
                cve_id = cve["cve_id"]
                break
        results.append({
            "source": "github_advisory",
            "ghsa_id": item.get("ghsa_id", ""),
            "cve_id": cve_id,
            "summary": item.get("summary", ""),
            "severity": item.get("severity", ""),
            "published": item.get("published_at", ""),
            "updated": item.get("updated_at", ""),
            "url": item.get("html_url", ""),
        })
    log(f"GitHub Advisories: found {len(results)}")
    return results


def search_ddg(query: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """Search DuckDuckGo Lite for general security news."""
    log(f"Searching DDG for '{query}'")
    data = urllib.parse.urlencode({"q": query, "kl": "us-en"})
    req = urllib.request.Request(
        DDG_LITE_URL,
        data=data.encode("utf-8"),
        headers={
            "User-Agent": "Mozilla/5.0 (Security Research)",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"DDG search error: {e}")
        return []

    results = []
    # Extract results from DDG lite HTML
    # Pattern: <a rel="nofollow" href="URL" ...>Title</a>
    pattern = re.compile(r'<a rel="nofollow" href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    for match in pattern.finditer(html):
        url = match.group(1)
        title = re.sub(r'<[^>]+>', '', match.group(2)).strip()
        if url and title and len(title) > 5:
            results.append({
                "source": "ddg",
                "url": url,
                "title": title,
                "query": query,
            })
        if len(results) >= max_results:
            break

    log(f"DDG: found {len(results)} results")
    return results


def search_h1_disclosed(program: str, max_results: int = 20) -> List[Dict[str, Any]]:
    """Search HackerOne public reports for a program."""
    log(f"Searching HackerOne disclosed reports for '{program}'")
    query = urllib.parse.quote(f"{program} site:hackerone.com/reports")
    ddg_results = search_ddg(query, max_results=max_results)
    reports = []
    for r in ddg_results:
        url = r.get("url", "")
        if "/reports/" in url:
            report_id = url.split("/reports/")[-1].split("?")[0].split("#")[0]
            if report_id.isdigit():
                reports.append({
                    "source": "hackerone_disclosed",
                    "report_id": report_id,
                    "url": url,
                    "title": r.get("title", ""),
                    "program": program,
                })
    log(f"HackerOne: found {len(reports)} disclosed reports")
    return reports


def search_bugcrowd_disclosed(program: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """Search Bugcrowd public submissions for a program."""
    log(f"Searching Bugcrowd for '{program}'")
    query = urllib.parse.quote(f"{program} bugcrowd disclosed")
    ddg_results = search_ddg(query, max_results=max_results)
    reports = []
    for r in ddg_results:
        url = r.get("url", "")
        if "bugcrowd.com" in url:
            reports.append({
                "source": "bugcrowd_disclosed",
                "url": url,
                "title": r.get("title", ""),
                "program": program,
            })
    log(f"Bugcrowd: found {len(reports)} references")
    return reports


def generate_intel_report(
    target: str,
    program: str,
    days: int,
    cvss_min: float,
    output_path: str,
) -> Dict[str, Any]:
    """Aggregate all intelligence sources into a single report."""
    log(f"Generating intel report for {target} (last {days} days)")

    # Search multiple sources
    cves = search_nvd(target, days=days, cvss_min=cvss_min, max_results=50)
    advisories = search_github_advisories(target, max_results=20)
    h1_reports = search_h1_disclosed(program, max_results=20) if program else []
    bc_reports = search_bugcrowd_disclosed(program, max_results=10) if program else []
    news = search_ddg(f"{target} vulnerability security", max_results=15)

    # Search for PoCs for each CVE
    pocs = []
    for cve in cves[:10]:
        cve_id = cve.get("cve_id", "")
        if cve_id:
            pocs.extend(search_github_pocs(cve_id, max_results=5))
            time.sleep(0.5)

    report = {
        "toolkit_version": "3.0.0",
        "skill": "vuln-intel",
        "target": target,
        "program": program,
        "generated_at": now_iso(),
        "lookback_days": days,
        "cvss_min": cvss_min,
        "summary": {
            "cve_count": len(cves),
            "advisory_count": len(advisories),
            "h1_report_count": len(h1_reports),
            "bc_report_count": len(bc_reports),
            "poc_count": len(pocs),
            "news_count": len(news),
        },
        "cves": cves,
        "advisories": advisories,
        "disclosed_reports": h1_reports + bc_reports,
        "pocs": pocs,
        "news": news,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"Report saved to {output_path}")
    return report


def correlate_with_technique_kb(
    report_path: str,
    technique_kb_dir: str,
    output_path: str,
) -> Dict[str, Any]:
    """Map CVEs and findings to technique-kb entries."""
    log(f"Correlating with technique-kb at {technique_kb_dir}")
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    kb_dir = Path(technique_kb_dir)
    kb_entries: List[Dict[str, Any]] = []

    if kb_dir.is_dir():
        for f in sorted(kb_dir.glob("*.yaml")):
            try:
                import yaml
                data = yaml.safe_load(f.read_text())
                if isinstance(data, dict):
                    kb_entries.append(data)
            except Exception:
                continue

    correlations = []
    cves = report.get("cves", [])
    for cve in cves:
        desc = cve.get("description", "").lower()
        for entry in kb_entries:
            name = entry.get("name", "").lower()
            tags = [t.lower() for t in entry.get("tags", [])]
            match = False
            for tag in tags:
                if tag in desc:
                    match = True
                    break
            if name in desc:
                match = True
            if match:
                correlations.append({
                    "cve_id": cve.get("cve_id"),
                    "technique": entry.get("name"),
                    "technique_id": entry.get("id"),
                    "confidence": "medium",
                })

    result = {
        "correlated_at": now_iso(),
        "correlation_count": len(correlations),
        "correlations": correlations,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    log(f"Correlation saved to {output_path} ({len(correlations)} matches)")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulnerability Intelligence Engine")
    sub = parser.add_subparsers(dest="command", help="Commands")

    # search-cves
    sc = sub.add_parser("search-cves", help="Search NVD for CVEs")
    sc.add_argument("--target", required=True, help="Target keyword (domain, product, vendor)")
    sc.add_argument("--days", type=int, default=60, help="Lookback period in days (default: 60)")
    sc.add_argument("--cvss-min", type=float, default=0.0, help="Minimum CVSS score (default: 0)")
    sc.add_argument("--output", help="Output JSON file")

    # search-reports
    sr = sub.add_parser("search-reports", help="Search disclosed bug bounty reports")
    sr.add_argument("--program", required=True, help="Program name")
    sr.add_argument("--platforms", default="hackerone,bugcrowd", help="Comma-separated platforms")
    sr.add_argument("--output", help="Output JSON file")

    # search-pocs
    sp = sub.add_parser("search-pocs", help="Search GitHub for PoCs")
    sp.add_argument("--cve", required=True, help="CVE ID")
    sp.add_argument("--output", help="Output JSON file")

    # search-news
    sn = sub.add_parser("search-news", help="Search security news")
    sn.add_argument("--target", required=True, help="Target keyword")
    sn.add_argument("--days", type=int, default=30, help="Lookback days (default: 30)")
    sn.add_argument("--output", help="Output JSON file")

    # generate-report
    gr = sub.add_parser("generate-report", help="Generate comprehensive intel report")
    gr.add_argument("--target", required=True, help="Target domain/keyword")
    gr.add_argument("--program", default="", help="Bug bounty program name")
    gr.add_argument("--days", type=int, default=60, help="Lookback period (default: 60)")
    gr.add_argument("--cvss-min", type=float, default=0.0, help="Minimum CVSS score")
    gr.add_argument("--output", required=True, help="Output JSON file")

    # correlate
    co = sub.add_parser("correlate", help="Correlate findings with technique-kb")
    co.add_argument("--report", required=True, help="Intel report JSON path")
    co.add_argument("--technique-kb", default=".claude/skills/technique-kb/", help="Technique KB directory")
    co.add_argument("--output", required=True, help="Output JSON file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "search-cves":
        results = search_nvd(args.target, days=args.days, cvss_min=args.cvss_min)
        out = {"cves": results, "count": len(results), "searched_at": now_iso()}
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
            print(f"Saved to {args.output}")
        else:
            print(json.dumps(out, indent=2))

    elif args.command == "search-reports":
        all_reports = []
        platforms = [p.strip().lower() for p in args.platforms.split(",")]
        if "hackerone" in platforms:
            all_reports.extend(search_h1_disclosed(args.program))
        if "bugcrowd" in platforms:
            all_reports.extend(search_bugcrowd_disclosed(args.program))
        out = {"reports": all_reports, "count": len(all_reports), "searched_at": now_iso()}
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
            print(f"Saved to {args.output}")
        else:
            print(json.dumps(out, indent=2))

    elif args.command == "search-pocs":
        results = search_github_pocs(args.cve)
        out = {"pocs": results, "count": len(results), "searched_at": now_iso()}
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
            print(f"Saved to {args.output}")
        else:
            print(json.dumps(out, indent=2))

    elif args.command == "search-news":
        results = search_ddg(f"{args.target} vulnerability security", max_results=20)
        out = {"news": results, "count": len(results), "searched_at": now_iso()}
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
            print(f"Saved to {args.output}")
        else:
            print(json.dumps(out, indent=2))

    elif args.command == "generate-report":
        report = generate_intel_report(
            target=args.target,
            program=args.program,
            days=args.days,
            cvss_min=args.cvss_min,
            output_path=args.output,
        )
        print(json.dumps(report["summary"], indent=2))

    elif args.command == "correlate":
        result = correlate_with_technique_kb(
            report_path=args.report,
            technique_kb_dir=args.technique_kb,
            output_path=args.output,
        )
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
