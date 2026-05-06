#!/usr/bin/env python3
"""Batch report generator — reads all findings, groups by severity/type, generates reports.

Usage:
    batch_reporter.py --findings-dir output/target --context output/reports
    batch_reporter.py --findings-dir output/target --context output/reports --dry-run
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "info": 5}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_date() -> str:
    return datetime.now(timezone.utc).strftime("%B %d, %Y")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def severity_badge(severity: str) -> str:
    sev = severity.lower()
    return f"[{sev.upper()}]"


def severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "none": "⚪", "info": "⚪"}.get(severity.lower(), "⚪")


def discover_findings(findings_dir: Path) -> List[dict]:
    all_findings: List[dict] = []
    seen_ids = set()

    for jl in sorted(findings_dir.rglob("findings.jsonl")):
        try:
            for line in jl.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                uid = record.get("id") or json.dumps(record, sort_keys=True)
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)
                if "source_file" not in record:
                    record["source_file"] = str(jl)
                all_findings.append(record)
        except Exception as e:
            log(f"Error reading {jl}: {e}")

    # Also scan for individual finding JSON files
    for jf in sorted(findings_dir.rglob("*.json")):
        if "findings.jsonl" in jf.name or jf.name in ("metadata.json", "manifest.json", "summary.json", "report.json"):
            continue
        try:
            record = json.loads(jf.read_text(encoding="utf-8"))
            uid = record.get("id") or json.dumps(record, sort_keys=True)
            if uid not in seen_ids:
                seen_ids.add(uid)
                if "source_file" not in record:
                    record["source_file"] = str(jf)
                all_findings.append(record)
        except Exception:
            pass

    return all_findings


def group_findings(findings: List[dict]) -> Dict[str, List[dict]]:
    by_severity: Dict[str, List[dict]] = defaultdict(list)
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in SEVERITY_ORDER:
            sev = "info"
        by_severity[sev].append(f)
    return dict(by_severity)


def group_by_type(findings: List[dict]) -> Dict[str, List[dict]]:
    by_type: Dict[str, List[dict]] = defaultdict(list)
    for f in findings:
        t = (f.get("type") or f.get("vuln_type") or f.get("category") or "unknown").lower()
        by_type[t].append(f)
    return dict(by_type)


def generate_individual_report(finding: dict, out_dir: Path) -> Path:
    fid = finding.get("id", finding.get("title", f"finding_{hash(json.dumps(finding, sort_keys=True))}")).replace("/", "_").replace(" ", "_")[:80]
    rdir = out_dir / fid
    rdir.mkdir(parents=True, exist_ok=True)

    sev = (finding.get("severity") or "info").lower()

    lines: list[str] = []
    lines.append(f"# {finding.get('title', 'Untitled Finding')}\n")
    lines.append(f"**Severity:** {severity_badge(sev)}")
    lines.append(f"**Type:** `{finding.get('type', finding.get('vuln_type', 'unknown'))}`")
    lines.append(f"**Source:** `{finding.get('source_file', 'N/A')}`")
    lines.append("")

    if finding.get("description"):
        lines.append(f"## Description\n\n{finding['description']}\n")
    if finding.get("url") or finding.get("endpoint"):
        lines.append(f"**URL:** `{finding.get('url') or finding.get('endpoint')}`\n")
    if finding.get("evidence"):
        lines.append(f"**Evidence:** {finding['evidence']}\n")
    if finding.get("cvss") or finding.get("base_score"):
        lines.append(f"**CVSS:** `{finding.get('cvss') or finding.get('base_score')}`\n")
    if finding.get("impact"):
        lines.append(f"## Impact\n\n{finding['impact']}\n")

    lines.append("\n---\n")
    lines.append(f"*Generated: {now_date()}*")

    rpath = rdir / "report.md"
    rpath.write_text("\n".join(lines), encoding="utf-8")
    return rpath


def build_summary_md(by_severity: Dict[str, List[dict]], by_type: Dict[str, List[dict]], total: int, ctx: Path) -> str:
    lines: list[str] = []
    lines.append("# Bug Bounty Assessment — Summary Report\n")
    lines.append(f"**Date:** {now_date()}")
    lines.append(f"**Total Findings:** {total}\n")
    lines.append("---\n")

    lines.append("## Severity Distribution\n")
    lines.append("| Severity | Count | % |")
    lines.append("|----------|-------|----|")

    for sev in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get):
        count = len(by_severity.get(sev, []))
        pct = (count / total * 100) if total > 0 else 0
        emoji = severity_emoji(sev)
        lines.append(f"| {emoji} {sev.capitalize()} | {count} | {pct:.1f}% |")

    lines.append("")

    lines.append("## Findings by Severity\n")
    for sev in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get):
        flist = by_severity.get(sev, [])
        if not flist:
            continue
        lines.append(f"### {severity_emoji(sev)} {sev.capitalize()} ({len(flist)})\n")
        for f in flist:
            title = f.get("title", f.get("type", "Unknown"))
            url = f.get("url", f.get("endpoint", ""))
            cvss = f.get("cvss", f.get("base_score", ""))
            line = f"- **{title}**"
            if url:
                line += f" — `{url}`"
            if cvss:
                line += f" (CVSS: {cvss})"
            lines.append(line)
        lines.append("")

    lines.append("## Findings by Type\n")
    lines.append("| Type | Count |")
    lines.append("|------|-------|")
    for t, flist in sorted(by_type.items(), key=lambda x: -len(x[1])):
        lines.append(f"| {t} | {len(flist)} |")

    lines.append("")
    lines.append("## Evidence Manifest\n")
    lines.append(f"- All individual reports: `{ctx / 'reports' / 'findings'}`")
    lines.append(f"- Evidence package: `{ctx / 'reports' / 'evidence'}`")
    lines.append("")

    lines.append("---\n")
    lines.append(f"*Generated by bug-bounty-agent on {now_date()}*")

    return "\n".join(lines)


def build_evidence_manifest(findings: List[dict]) -> str:
    lines: list[str] = []
    lines.append("# Evidence Package Manifest\n")
    lines.append(f"**Generated:** {now_date()}\n")

    files_seen = set()
    for f in findings:
        src = f.get("source_file", "")
        if src and src not in files_seen:
            files_seen.add(src)
            lines.append(f"- `{Path(src).name}` → evidence source")
        ev = f.get("evidence", "")
        if ev and os.path.exists(ev):
            lines.append(f"- `{ev}` → artifact")

    return "\n".join(lines)


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Batch report generator — group findings, produce summary + individual reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  summary.md               Master summary with stats
  reports/findings/        Individual finding reports
  reports/manifest.md      Evidence package manifest
  findings.jsonl           All findings (deduplicated)
""",
    )
    p.add_argument("--findings-dir", "-f", required=True, help="Root directory to scan for findings.jsonl files")
    p.add_argument("--context", "-c", default=".", help="Output directory (default: .)")
    p.add_argument("--dry-run", action="store_true", help="Validate inputs without generating reports")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    findings_root = Path(args.findings_dir).resolve()
    if not findings_root.exists():
        log(f"Findings dir not found: {findings_root}")
        sys.exit(1)

    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)

    log(f"Scanning {findings_root} for findings...")
    all_findings = discover_findings(findings_root)
    log(f"Discovered {len(all_findings)} unique findings")

    if args.dry_run:
        by_sev = group_findings(all_findings)
        by_type = group_by_type(all_findings)
        print(json.dumps({
            "dry_run": True,
            "total": len(all_findings),
            "by_severity": {k: len(v) for k, v in by_sev.items()},
            "by_type": {k: len(v) for k, v in by_type.items()},
        }))
        return

    by_severity = group_findings(all_findings)
    by_type = group_by_type(all_findings)

    reports_dir = ctx / "reports"
    findings_out = reports_dir / "findings"
    findings_out.mkdir(parents=True, exist_ok=True)

    report_paths: list[str] = []
    for finding in all_findings:
        try:
            rp = generate_individual_report(finding, findings_out)
            report_paths.append(str(rp))
        except Exception as e:
            log(f"Failed to generate report for {finding.get('title', 'unknown')}: {e}")

    summary_md = build_summary_md(by_severity, by_type, len(all_findings), ctx)
    summary_path = ctx / "summary.md"
    summary_path.write_text(summary_md, encoding="utf-8")
    log(f"Summary → {summary_path}")

    manifest_md = build_evidence_manifest(all_findings)
    manifest_path = reports_dir / "manifest.md"
    manifest_path.write_text(manifest_md, encoding="utf-8")
    log(f"Manifest → {manifest_path}")

    all_jl_path = ctx / "findings.jsonl"
    with open(all_jl_path, "w", encoding="utf-8") as f:
        for finding in all_findings:
            f.write(json.dumps(finding) + "\n")
    log(f"All findings JSONL → {all_jl_path}")

    result = {
        "total_findings": len(all_findings),
        "reports_generated": len(report_paths),
        "summary": str(summary_path),
        "manifest": str(manifest_path),
        "findings_jsonl": str(all_jl_path),
        "severity_counts": {k: len(v) for k, v in by_severity.items()},
        "type_counts": {k: len(v) for k, v in sorted(by_type.items(), key=lambda x: -len(x[1]))},
    }

    meta_path = ctx / "batch_metadata.json"
    meta_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    log(f"Metadata → {meta_path}")

    print(json.dumps(result))


if __name__ == "__main__":
    main()