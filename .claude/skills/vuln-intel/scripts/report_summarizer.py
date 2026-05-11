#!/usr/bin/env python3
"""Vuln Intel Report Summarizer — human-readable summary from intel_report.json.

Usage:
    report_summarizer.py --report $OUTDIR/vuln-intel/intel_report.json --output summary.md
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarize(report_path: str, output_path: str) -> dict:
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    summary = data.get("summary", {})
    target = data.get("target", "unknown")

    lines = [
        f"# Vulnerability Intelligence Report: {target}",
        f"Generated: {now_iso()}",
        "",
        "## Summary",
        f"- CVEs found: {summary.get('cve_count', 0)}",
        f"- Advisories: {summary.get('advisory_count', 0)}",
        f"- Disclosed reports: {summary.get('h1_report_count', 0) + summary.get('bc_report_count', 0)}",
        f"- PoCs available: {summary.get('poc_count', 0)}",
        f"- News articles: {summary.get('news_count', 0)}",
        "",
        "## Critical/High CVEs",
    ]

    cves = data.get("cves", [])
    critical_high = [c for c in cves if c.get("cvss_score", 0) >= 7.0]
    if critical_high:
        for cve in sorted(critical_high, key=lambda x: x.get("cvss_score", 0), reverse=True)[:10]:
            lines.append(f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}) — {cve['description'][:120]}...")
    else:
        lines.append("No critical or high severity CVEs found.")

    lines.extend(["", "## Disclosed Reports"])
    reports = data.get("disclosed_reports", [])
    if reports:
        for r in reports[:10]:
            lines.append(f"- [{r.get('title', 'Untitled')}]({r.get('url', '')})")
    else:
        lines.append("No disclosed reports found.")

    lines.extend(["", "## Recommended Next Steps"])
    lines.append("1. Review critical/high CVEs for testable attack vectors")
    lines.append("2. Read disclosed reports to understand previously found vulnerability classes")
    lines.append("3. Run available PoCs in isolated environment")
    lines.append("4. Map findings to technique-kb entries")
    lines.append("5. Generate prioritized test plan")

    content = "\n".join(lines)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(content, encoding="utf-8")
    return {"status": "summarized", "output": output_path, "critical_high_count": len(critical_high)}


def main():
    parser = argparse.ArgumentParser(description="Vuln Intel Report Summarizer")
    parser.add_argument("--report", required=True, help="Intel report JSON path")
    parser.add_argument("--output", required=True, help="Output markdown path")
    args = parser.parse_args()
    result = summarize(args.report, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
