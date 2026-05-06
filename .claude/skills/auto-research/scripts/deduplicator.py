#!/usr/bin/env python3
"""
deduplicator.py — Checks candidates against existing techniques in the
technique knowledge base.

Uses fields_to_compare and similarity_threshold from ingest_rules.yaml.
Outputs only truly new candidates (those that don't match existing entries).
"""

import argparse
import json
import os
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_existing_techniques(techniques_dir):
    existing = []
    tech_dir = Path(techniques_dir)
    if not tech_dir.exists():
        return existing

    for fpath in tech_dir.rglob("*.json"):
        try:
            data = load_json(fpath)
            if isinstance(data, list):
                existing.extend(data)
            elif isinstance(data, dict):
                existing.append(data)
        except (json.JSONDecodeError, OSError):
            continue

    for fpath in tech_dir.rglob("*.yaml"):
        try:
            data = load_yaml(str(fpath))
            if isinstance(data, list):
                existing.extend(data)
            elif isinstance(data, dict):
                existing.append(data)
        except Exception:
            continue

    return existing


def normalize_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def get_field_value(record, field_path):
    parts = field_path.split(".")
    current = record
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part, "")
        elif isinstance(current, list):
            current = " ".join(str(v) for v in current)
        else:
            return ""
    if current is None:
        return ""
    if isinstance(current, list):
        return " ".join(str(v) for v in current)
    if isinstance(current, (dict,)):
        return json.dumps(current)
    return str(current)


def compute_text_similarity(text1, text2):
    seq1 = normalize_text(text1)
    seq2 = normalize_text(text2)
    if not seq1 or not seq2:
        return 0.0
    return SequenceMatcher(None, seq1, seq2).ratio()


def compute_record_similarity(candidate, existing, fields):
    scores = []
    weights = []

    for field in fields:
        cand_val = get_field_value(candidate, field)
        exist_val = get_field_value(existing, field)
        sim = compute_text_similarity(cand_val, exist_val)
        scores.append(sim)
        weights.append(1.0)

    if not scores:
        return 0.0

    total_weight = sum(weights)
    if total_weight == 0:
        return 0.0

    weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
    return weighted_score


def is_duplicate(candidate, existing_records, fields, threshold):
    for record in existing_records:
        similarity = compute_record_similarity(candidate, record, fields)
        if similarity >= threshold:
            return True, similarity, record.get("name", record.get("id", "unknown"))
    return False, 0.0, None


def deduplicate(candidates, techniques_dir, rules):
    dedup_config = rules.get("deduplication", {})
    fields = dedup_config.get("fields_to_compare", ["name", "description"])
    threshold = dedup_config.get("similarity_threshold", 0.85)

    existing = load_existing_techniques(techniques_dir)

    new_items = []
    duplicate_items = []

    for candidate in candidates:
        is_dup, similarity, matched_name = is_duplicate(candidate, existing, fields, threshold)
        if is_dup:
            duplicate_items.append({
                "candidate": candidate.get("name", "unknown"),
                "matched_existing": matched_name,
                "similarity": round(similarity, 4)
            })
        else:
            new_items.append(candidate)

    result = {
        "total_candidates": len(candidates),
        "existing_techniques_checked": len(existing),
        "new_candidates": len(new_items),
        "duplicates_removed": len(duplicate_items),
        "fields_compared": fields,
        "similarity_threshold": threshold,
        "duplicates": duplicate_items[:50],
        "candidates": new_items
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Deduplicate candidate techniques against existing knowledge base"
    )
    parser.add_argument(
        "--candidates",
        required=True,
        help="Path to candidate JSON file (from knowledge_extractor.py)"
    )
    parser.add_argument(
        "--techniques-dir",
        required=True,
        help="Directory containing existing technique files (.json/.yaml)"
    )
    parser.add_argument(
        "--rules",
        required=True,
        help="Path to ingest_rules.yaml"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write deduplicated output JSON"
    )
    args = parser.parse_args()

    if not os.path.exists(args.candidates):
        print(f"ERROR: candidates file not found: {args.candidates}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.rules):
        print(f"ERROR: rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)

    rules = load_yaml(args.rules)
    candidates = load_json(args.candidates)

    if not isinstance(candidates, list):
        candidates = [candidates]

    result = deduplicate(candidates, args.techniques_dir, rules)

    output_dir = os.path.dirname(args.output) or "."
    os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"Total candidates: {result['total_candidates']}")
    print(f"Existing techniques checked: {result['existing_techniques_checked']}")
    print(f"New candidates: {result['new_candidates']}")
    print(f"Duplicates removed: {result['duplicates_removed']}")
    print(f"Output: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())