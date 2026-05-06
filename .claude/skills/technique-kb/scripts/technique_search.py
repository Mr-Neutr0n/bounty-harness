#!/usr/bin/env python3
"""Search the technique knowledge base by keyword, category, severity, or standard ID.

Walks all technique YAML files, searches across id, name, description, category,
severity, tags, and standards references.

Usage:
    python3 technique_search.py --techniques-dir techniques --query "SQL injection"
    python3 technique_search.py --techniques-dir techniques --query "category:xss"
    python3 technique_search.py --techniques-dir techniques --query "severity:critical"
    python3 technique_search.py --techniques-dir techniques --query "wstg:INPV-05"
    python3 technique_search.py --techniques-dir techniques --query "cwe:79"
    python3 technique_search.py --help
"""

import argparse
import json
import os
import sys
import yaml


FIELD_PREFIXES = {
    "category:": "category",
    "severity:": "severity",
    "wstg:": "wstg",
    "asvs:": "asvs",
    "api_top10:": "api_top10",
    "vrt:": "vrt",
    "cwe:": "cwe",
    "tag:": "tags",
    "auth:": "auth",
    "id:": "id",
}


def collect_techniques(techniques_dir):
    results = []
    for root, dirs, files in os.walk(techniques_dir):
        for fn in files:
            if fn.endswith((".yaml", ".yml")):
                fp = os.path.join(root, fn)
                try:
                    with open(fp) as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict) and "id" in data:
                        results.append((fp, data))
                except Exception as e:
                    print(f"WARNING: Skipping {fp}: {e}", file=sys.stderr)
    return results


def flatten_all(data):
    """Convert a technique dict into a single searchable string."""
    parts = []

    for k in ("id", "name", "category", "severity", "description"):
        v = data.get(k)
        if v:
            parts.append(str(v))

    for tag in data.get("tags", []):
        parts.append(tag)

    std = data.get("standards", {})
    for std_key in ("wstg", "asvs", "api_top10", "vrt", "cwe"):
        for item in std.get(std_key, []):
            parts.append(str(item))

    requires = data.get("requires", {})
    parts.append(str(requires.get("auth", "")))
    for inp in requires.get("inputs", []):
        parts.append(inp)

    s = data.get("signals", {})
    for sig in s.get("positive", []) + s.get("negative", []):
        parts.append(sig)

    return " ".join(parts).lower()


def matches_field_query(tech, field, raw_value):
    value = raw_value.lower()

    if field == "category":
        return value in (tech.get("category") or "").lower()
    if field == "severity":
        return value in (tech.get("severity") or "").lower()
    if field == "tags":
        return value in " ".join(tech.get("tags", [])).lower()
    if field == "id":
        return value in (tech.get("id") or "").lower()
    if field == "auth":
        return value in (tech.get("requires", {}).get("auth") or "").lower()

    if field in ("wstg", "asvs", "api_top10", "vrt", "cwe"):
        std = tech.get("standards", {})
        items = std.get(field, [])
        for item in items:
            if value in item.lower():
                return True
        return False

    return False


def search_techniques(techniques, query):
    query = query.strip()
    if not query:
        return techniques, "all", ""

    for prefix, field in FIELD_PREFIXES.items():
        if query.lower().startswith(prefix):
            raw_value = query[len(prefix):]
            results = []
            for fp, tech in techniques:
                if matches_field_query(tech, field, raw_value):
                    results.append((fp, tech))
            return results, field, raw_value

    q = query.lower()
    results = []
    for fp, tech in techniques:
        if q in flatten_all(tech):
            results.append((fp, tech))
    return results, "keyword", query


def main():
    parser = argparse.ArgumentParser(
        description="Search the technique knowledge base by criteria",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  technique_search.py --techniques-dir techniques --query "SQL injection"
  technique_search.py --techniques-dir techniques --query "category:xss"
  technique_search.py --techniques-dir techniques --query "severity:critical"
  technique_search.py --techniques-dir techniques --query "cwe:79"
  technique_search.py --techniques-dir techniques --query "wstg:INPV-05"
  technique_search.py --techniques-dir techniques --query "auth:single_account"
  technique_search.py --techniques-dir techniques --query "tag:oob"
""",
    )
    parser.add_argument(
        "--techniques-dir",
        required=True,
        help="Directory containing technique YAML files",
    )
    parser.add_argument(
        "--query",
        required=True,
        help="Search query. Use prefix:value for fielded search (category:, severity:, wstg:, asvs:, vrt:, cwe:, tag:, auth:, id:)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.techniques_dir):
        print(f"ERROR: techniques-dir not found: {args.techniques_dir}", file=sys.stderr)
        sys.exit(2)

    techniques = collect_techniques(args.techniques_dir)
    if not techniques:
        print("ERROR: No techniques found", file=sys.stderr)
        sys.exit(1)

    results, field, value = search_techniques(techniques, args.query)

    output = {
        "query": args.query,
        "search_type": field,
        "search_value": value,
        "total": len(results),
        "results": [],
    }

    for fp, tech in results:
        output["results"].append({
            "id": tech.get("id"),
            "name": tech.get("name"),
            "category": tech.get("category"),
            "severity": tech.get("severity"),
            "description": (tech.get("description") or "").strip()[:200],
            "standards": tech.get("standards", {}),
            "workflow": tech.get("workflow_mapping"),
            "file": os.path.relpath(fp, args.techniques_dir),
        })

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()