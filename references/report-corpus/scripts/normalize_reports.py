#!/usr/bin/env python3
"""
normalize_reports.py — Read raw HackerOne reports and normalize to unified schema.

Input:  directory of raw HackerOne report markdown files, or CSV data
Output: normalized/*.jsonl with unified schema
"""

import argparse
import json
import sys
import os
import pathlib
import hashlib
import csv
import re
from collections import defaultdict
from datetime import datetime


BUG_TYPE_MAP = {
    "XSS": "xss",
    "SQL Injection": "sqli",
    "SQLI": "sqli",
    "SSRF": "ssrf",
    "RCE": "rce",
    "IDOR": "idor",
    "CSRF": "csrf",
    "XXE": "xxe",
    "Race Condition": "race-condition",
    "SSTI": "ssti",
    "OAuth": "oauth",
    "API": "api",
    "GraphQL": "graphql",
    "Upload": "file-upload",
    "Auth": "auth",
    "Authorization": "authorization",
    "Mobile": "mobile",
    "Web Cache": "webcache",
    "Request Smuggling": "request-smuggling",
    "Business Logic": "business-logic",
    "RCE / Command Injection": "rce",
    "Remote Code Execution": "rce",
    "Race": "race-condition",
    "race": "race-condition",
    "Template Injection": "ssti",
    "Server Side Request Forgery": "ssrf",
    "Cross-Site Scripting": "xss",
    "Cross-Site Request Forgery": "csrf",
    "File Upload": "file-upload",
    "Privilege Escalation": "authorization",
    "Authentication": "auth",
    "Insecure Direct Object Reference": "idor",
    "XML External Entity": "xxe",
    "Cache Poisoning": "webcache",
    "Cache Deception": "webcache",
    "Open Redirect": "open-redirect",
    "Clickjacking": "clickjacking",
    "Subdomain Takeover": "subdomain-takeover",
    "Denial of Service": "dos",
    "Information Disclosure": "info-disclosure",
    "Account Takeover": "auth",
    "ATO": "auth",
    "2FA Bypass": "auth",
    "MFA Bypass": "auth",
    "Broken Access Control": "authorization",
    "Exposed Credentials": "info-disclosure",
    "Hardcoded Credentials": "info-disclosure",
    "Source Code Disclosure": "info-disclosure",
    "Path Traversal": "path-traversal",
    "Local File Inclusion": "lfi",
    "LFI": "lfi",
    "Path / LFI / RFI": "lfi",
    "Server-Side Template Injection": "ssti",
    "Reflected XSS": "xss",
    "Stored XSS": "xss",
    "DOM XSS": "xss",
    "Blind XSS": "xss",
    "Error-Based SQL Injection": "sqli",
    "Blind SQL Injection": "sqli",
    "Time-Based SQL Injection": "sqli",
    "Union-Based SQL Injection": "sqli",
    "CRLF Injection": "crlf",
    "Host Header Injection": "host-header",
    "Cache": "webcache",
    "race condition": "race-condition",
    "Race condition": "race-condition",
    "race Condition": "race-condition",
}


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "none",
    "p1": "critical",
    "p2": "high",
    "p3": "medium",
    "p4": "low",
    "p5": "none",
    "10.0": "critical",
    "9.": "critical",
    "8.": "high",
    "7.": "high",
    "6.": "medium",
    "5.": "medium",
    "4.": "low",
    "3.": "low",
    "2.": "none",
    "1.": "none",
    "0.": "none",
}


SKILL_MAP = {
    "xss": ["xss"],
    "sqli": ["sqli"],
    "ssrf": ["ssrf"],
    "rce": ["rce"],
    "idor": ["api"],
    "csrf": ["cors-csrf"],
    "xxe": ["rce"],
    "race-condition": ["race-condition"],
    "ssti": ["rce"],
    "oauth": ["auth"],
    "api": ["api"],
    "graphql": ["api"],
    "file-upload": ["file-upload"],
    "auth": ["auth"],
    "authorization": ["api", "auth"],
    "mobile": ["mobile"],
    "webcache": ["cloud"],
    "request-smuggling": ["ssrf"],
    "business-logic": ["api"],
    "open-redirect": ["xss"],
    "clickjacking": ["cors-csrf"],
    "subdomain-takeover": ["cloud"],
    "dos": ["cloud"],
    "info-disclosure": ["cloud"],
    "path-traversal": ["rce"],
    "lfi": ["rce"],
    "crlf": ["xss"],
    "host-header": ["xss"],
}


SKILL_FROM_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "none",
}


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", text.strip().lower()).strip("-")


def map_bug_type(raw: str) -> str:
    raw_lower = raw.lower()
    for key, mapped in BUG_TYPE_MAP.items():
        if key.lower() in raw_lower or raw_lower == key.lower().replace(" ", "-"):
            return mapped
    return raw_lower.strip().replace(" ", "-")


def map_severity(raw: str) -> str:
    if not raw:
        return "none"
    raw_l = raw.lower().strip()
    if raw_l in ("critical", "high", "medium", "low", "none"):
        return raw_l
    sv_match = re.search(r"([\d]+\.[\d]+)", raw_l)
    if sv_match:
        score = float(sv_match.group(1))
        for key, sev in SEVERITY_MAP.items():
            if key.endswith(".") and raw_l.startswith(str(int(score))):
                return sev
    for key, sev in SEVERITY_MAP.items():
        if key in raw_l:
            return sev
    return "none"


def skill_mapping_for(bug_type: str) -> list:
    return SKILL_MAP.get(bug_type, ["recon"])


def generate_id(source: str, program: str, title: str) -> str:
    raw = f"{source}|{program}|{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def parse_csv_reports(filepath: pathlib.Path) -> list[dict]:
    """Parse a HackerOne CSV data dump."""
    reports = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reports.append(row)
    return reports


def normalize_csv_row(row: dict, row_idx: int) -> dict | None:
    title = row.get("title") or row.get("Report Title") or f"report-{row_idx}"
    program = row.get("handle") or row.get("program") or row.get("Program") or "unknown"
    bug_type_raw = row.get("weakness") or row.get("vulnerability_type") or row.get("Bug Type", "")
    severity_raw = row.get("severity") or row.get("Severity") or row.get("Risk", "")
    bounty_raw = row.get("bounty") or row.get("Bounty") or "0"
    disclosure_date = row.get("disclosed_at") or row.get("Date") or ""

    bug_type = map_bug_type(bug_type_raw)
    severity = map_severity(severity_raw)
    bounty_amount = 0
    try:
        bounty_amount = int(float(str(bounty_raw).replace("$", "").replace(",", "")))
    except (ValueError, TypeError):
        pass

    year = datetime.now().year
    if disclosure_date:
        try:
            year = int(disclosure_date[:4])
        except (ValueError, TypeError):
            pass

    report_id = generate_id("hackerone", program, title)

    report = {
        "id": report_id,
        "source": "hackerone",
        "program": slugify(program),
        "year": year,
        "bug_type": bug_type,
        "severity": severity,
        "bounty_amount": bounty_amount,
        "entrypoint": "",
        "primitive": "",
        "impact": "",
        "target_tech": [],
        "tools_used": [],
        "cwe": "",
        "title": title,
        "description": row.get("description") or title,
        "reproduction_steps": [],
        "skill_mapping": skill_mapping_for(bug_type),
        "confidence": "low",
        "tags": [bug_type],
    }

    return report


def read_markdown_reports(input_dir: pathlib.Path) -> list[dict]:
    """Read HackerOne-style markdown reports from tops_by_bug_type."""
    results = []
    md_dir = input_dir

    if (input_dir / "tops_by_bug_type").is_dir():
        md_dir = input_dir / "tops_by_bug_type"

    for md_file in sorted(md_dir.glob("TOP*.md")):
        bug_label = md_file.stem.replace("TOP", "").lower()
        bug_type = map_bug_type(bug_label)
        with open(md_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        results.extend(parse_top_markdown(content, bug_type, md_file.name))

    return results


def parse_top_markdown(content: str, fallback_bug_type: str, source_file: str) -> list[dict]:
    """Parse a TOP*.md markdown file with links/reports."""
    reports = []

    blocks = re.split(r"\n(?=#{1,3}\s+|##\s+)", content)
    for block in blocks:
        lines = block.strip().split("\n")
        if not lines:
            continue

        header = lines[0].lstrip("#").strip()
        title = (
            re.search(r"\[([^\]]+)\]", block) or re.search(r"\(([^)]+)\)", block)
        )

        title_text = header if header else (title.group(1) if title else "Untitled")
        report_id = generate_id("hackerone-top", "", title_text)

        urls = re.findall(r"https?://hackerone\.com/[^\s)]+", block)
        programs = re.findall(
            r"program[: ]*(\S+)", block, re.IGNORECASE
        )
        program = programs[0] if programs else "unknown"

        severity = "none"
        for sv in ["critical", "high", "medium", "low"]:
            if re.search(rf"\b{sv}\b", block, re.IGNORECASE):
                severity = sv
                break

        report = {
            "id": report_id,
            "source": "hackerone-top",
            "program": slugify(program),
            "year": datetime.now().year,
            "bug_type": fallback_bug_type,
            "severity": severity,
            "bounty_amount": 0,
            "entrypoint": "",
            "primitive": "",
            "impact": "",
            "target_tech": [],
            "tools_used": [],
            "cwe": "",
            "title": title_text,
            "description": block[:1000],
            "reproduction_steps": [],
            "skill_mapping": skill_mapping_for(fallback_bug_type),
            "confidence": "medium",
            "tags": [fallback_bug_type],
            "source_file": source_file,
        }

        if urls:
            report["reproduction_steps"] = urls
            report["impact"] = f"Referenced at: {', '.join(urls[:3])}"

        reports.append(report)

    return reports


def deduplicate(reports: list[dict]) -> list[dict]:
    seen = {}
    deduped = []
    for r in reports:
        key = f"{r.get('program','')}|{r.get('title','')}|{r.get('bug_type','')}"
        key_h = key[:120]
        if key_h not in seen:
            seen[key_h] = True
            deduped.append(r)
        else:
            print(f"  [dedup] Skipping duplicate: {key_h[:80]}...", file=sys.stderr)
    return deduped


def main():
    parser = argparse.ArgumentParser(
        description="Normalize bug bounty reports from raw sources into unified JSONL schema."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Directory containing raw reports (markdown + CSV)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory to write normalized JSONL files",
    )
    args = parser.parse_args()

    input_dir = pathlib.Path(args.input)
    output_dir = pathlib.Path(args.output) / "normalized"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_dir.is_dir():
        print(f"Error: input directory '{input_dir}' does not exist", file=sys.stderr)
        sys.exit(1)

    all_reports: list[dict] = []

    print(f"Scanning input directory: {input_dir}", file=sys.stderr)

    csv_files = list(input_dir.glob("*.csv")) + list(input_dir.glob("**/*.csv"))
    for csv_path in csv_files:
        print(f"  Parsing CSV: {csv_path.name}", file=sys.stderr)
        rows = parse_csv_reports(csv_path)
        for idx, row in enumerate(rows, 1):
            norm = normalize_csv_row(row, idx)
            if norm:
                all_reports.append(norm)
        print(f"    -> {len(rows)} rows parsed", file=sys.stderr)

    md_files = list(input_dir.glob("**/TOP*.md"))
    if md_files:
        print(f"  Parsing {len(md_files)} TOP*.md files", file=sys.stderr)
        md_reports = read_markdown_reports(input_dir)
        all_reports.extend(md_reports)
        print(f"    -> {len(md_reports)} entries from markdown", file=sys.stderr)

    if not all_reports:
        print("Warning: No reports found in input directory", file=sys.stderr)

    print(f"Total raw entries before dedup: {len(all_reports)}", file=sys.stderr)
    all_reports = deduplicate(all_reports)
    print(f"Total after deduplication: {len(all_reports)}", file=sys.stderr)

    bug_type_groups: dict[str, list[dict]] = defaultdict(list)
    for r in all_reports:
        bt = r.get("bug_type", "unknown")
        bug_type_groups[bt].append(r)

    for bug_type, reports in sorted(bug_type_groups.items()):
        out_path = output_dir / f"{slugify(bug_type)}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for report in reports:
                f.write(json.dumps(report, ensure_ascii=False) + "\n")
        print(f"  Wrote {len(reports):4d} entries -> {out_path.name}", file=sys.stderr)

    summary = {
        "total_reports": len(all_reports),
        "bug_types": sorted(bug_type_groups.keys()),
        "counts": {bt: len(rpts) for bt, rpts in sorted(bug_type_groups.items())},
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    summary_path = output_dir / "_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"Summary written to {summary_path}", file=sys.stderr)

    print(f"Done. {len(all_reports)} normalized reports in {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()