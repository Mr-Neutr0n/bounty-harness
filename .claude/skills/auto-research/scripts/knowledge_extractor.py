#!/usr/bin/env python3
"""
knowledge_extractor.py — Extracts candidate techniques/payloads/references
from a piece of downloaded content.

Uses categorization rules from ingest_rules.yaml to classify extracted items
into: new_technique, new_payload, new_reference, or false_positive_rule.

Outputs candidate JSON with structured fields for downstream processing.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_content(content_path):
    with open(content_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def extract_markdown_sections(content):
    sections = []
    pattern = re.compile(r"^(#{1,4})\s+(.+)$", re.MULTILINE)
    matches = list(pattern.finditer(content))

    for i, match in enumerate(matches):
        level = len(match.group(1))
        title = match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        body = content[start:end].strip()

        sections.append({
            "level": level,
            "title": title,
            "body": body,
            "line": content[:match.start()].count("\n") + 1
        })

    return sections


def extract_code_blocks(content):
    blocks = []
    pattern = re.compile(r"^```(\w*)\n(.*?)^```", re.MULTILINE | re.DOTALL)
    for match in pattern.finditer(content):
        lang = match.group(1) or "text"
        code = match.group(2).strip()
        blocks.append({
            "language": lang,
            "code": code,
            "char_offset": match.start()
        })
    return blocks


def extract_cve_ids(content):
    pattern = re.compile(r"CVE-\d{4}-\d{4,}")
    return list(set(pattern.findall(content)))


def extract_nuclei_info(content):
    entries = []
    id_pattern = re.compile(r"^id:\s*(.+)$", re.MULTILINE)
    info_block = re.compile(r"^info:\s*\n([\s\S]*?)(?=^\S|\Z)", re.MULTILINE)

    for match in info_block.finditer(content):
        block = match.group(1)
        entry = {}
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("name:"):
                entry["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                entry["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("severity:"):
                entry["severity"] = line.split(":", 1)[1].strip()
            elif line.startswith("tags:"):
                entry["tags"] = line.split(":", 1)[1].strip()
            elif line.startswith("author:"):
                entry["author"] = line.split(":", 1)[1].strip()
        if entry:
            entry["source_type"] = "nuclei_template"
            entries.append(entry)

    return entries


def categorize_item(text, rules):
    text_lower = text.lower()
    categories = rules.get("extraction", {}).get("categories", [])
    scores = {}

    for cat in categories:
        cat_name = cat["name"]
        signals = cat.get("signals", [])
        hits = sum(1 for s in signals if s.lower() in text_lower)
        if hits > 0:
            scores[cat_name] = hits

    if not scores:
        return "new_reference"

    return max(scores, key=scores.get)


def compute_content_hash(text):
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def extract_candidates(content_path, source_id, rules):
    content = load_content(content_path)
    candidates = []

    extraction_config = rules.get("extraction", {})
    source_extractors = extraction_config.get("source_extractors", {})

    text_for_categorization = content[:10000]

    sections = extract_markdown_sections(content)
    code_blocks = extract_code_blocks(content)
    cve_ids = extract_cve_ids(content)

    extractor = source_extractors.get(source_id, {})

    if source_id in ("nuclei_template", "nuclei-templates"):
        nuclei_entries = extract_nuclei_info(content)
        for entry in nuclei_entries:
            name = entry.get("name", "Unnamed Template")
            desc = entry.get("description", "")
            candidate = {
                "source_id": source_id,
                "name": name,
                "description": desc,
                "category": categorize_item(f"{name} {desc}", rules),
                "source_type": "nuclei_template",
                "severity": entry.get("severity"),
                "tags": entry.get("tags"),
                "author": entry.get("author"),
                "content_hash": compute_content_hash(name + desc),
                "extracted_at": datetime.now(timezone.utc).isoformat()
            }
            candidates.append(candidate)

    elif source_id in ("kev_cve", "cisa-kev"):
        try:
            kev_data = json.loads(content)
            for vuln in kev_data.get("vulnerabilities", []):
                cve = vuln.get("cveID", "")
                name = vuln.get("vulnerabilityName", "")
                candidate = {
                    "source_id": source_id,
                    "name": cve,
                    "description": f"{name} — {vuln.get('shortDescription', '')}",
                    "category": categorize_item(f"{cve} {name} {vuln.get('shortDescription', '')}", rules),
                    "source_type": "kev_cve",
                    "cve_id": cve,
                    "date_added": vuln.get("dateAdded"),
                    "required_action": vuln.get("requiredAction"),
                    "known_ransomware": vuln.get("knownRansomwareCampaignUse"),
                    "content_hash": compute_content_hash(cve),
                    "extracted_at": datetime.now(timezone.utc).isoformat()
                }
                candidates.append(candidate)
        except json.JSONDecodeError:
            for cve in cve_ids:
                candidate = {
                    "source_id": source_id,
                    "name": cve,
                    "description": f"CVE referenced in {source_id} content",
                    "category": categorize_item(cve, rules),
                    "source_type": "cve_reference",
                    "cve_id": cve,
                    "content_hash": compute_content_hash(cve),
                    "extracted_at": datetime.now(timezone.utc).isoformat()
                }
                candidates.append(candidate)

    else:
        for section in sections:
            title = section["title"]
            body = section["body"]

            if len(title) < 3:
                continue

            full_text = f"{title}\n{body[:5000]}"

            section_cves = extract_cve_ids(body)
            section_blocks = extract_code_blocks(body)

            candidate = {
                "source_id": source_id,
                "name": title,
                "description": body[:2000].strip(),
                "category": categorize_item(full_text, rules),
                "source_type": extractor.get("output_type", "technique"),
                "heading_level": section["level"],
                "line_number": section["line"],
                "cve_ids": section_cves if section_cves else None,
                "has_code_blocks": len(section_blocks) > 0,
                "code_block_count": len(section_blocks),
                "content_hash": compute_content_hash(full_text),
                "extracted_at": datetime.now(timezone.utc).isoformat()
            }
            candidates.append(candidate)

    if not candidates:
        basic_candidate = {
            "source_id": source_id,
            "name": f"Content from {source_id}",
            "description": content[:2000].strip(),
            "category": categorize_item(text_for_categorization, rules),
            "source_type": "raw_content",
            "cve_ids": cve_ids if cve_ids else None,
            "content_hash": compute_content_hash(content),
            "extracted_at": datetime.now(timezone.utc).isoformat()
        }
        candidates.append(basic_candidate)

    return candidates


def main():
    parser = argparse.ArgumentParser(
        description="Extract candidate techniques/payloads/references from downloaded content"
    )
    parser.add_argument(
        "--content-file",
        required=True,
        help="Path to the downloaded content file"
    )
    parser.add_argument(
        "--source-id",
        required=True,
        help="Source identifier matching sources.yaml (e.g. 'nuclei-templates')"
    )
    parser.add_argument(
        "--rules",
        required=True,
        help="Path to ingest_rules.yaml"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output files"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Specific output file path (overrides auto-naming)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.content_file):
        print(f"ERROR: content file not found: {args.content_file}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.rules):
        print(f"ERROR: rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    rules = load_yaml(args.rules)
    candidates = extract_candidates(args.content_file, args.source_id, rules)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", args.source_id)

    if args.output:
        output_path = args.output
    else:
        output_path = os.path.join(
            args.output_dir,
            f"candidates_{safe_id}_{timestamp}.json"
        )

    with open(output_path, "w") as f:
        json.dump(candidates, f, indent=2, default=str)

    print(f"Extracted {len(candidates)} candidates from {args.source_id}")
    print(f"Output: {output_path}")

    cat_counts = {}
    for c in candidates:
        cat = c.get("category", "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    for cat, count in sorted(cat_counts.items()):
        print(f"  {cat}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())