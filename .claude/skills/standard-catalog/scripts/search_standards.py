#!/usr/bin/env python3
"""Search across all standard catalogs by keyword.

Usage:
    python3 search_standards.py --catalogs-dir catalogs/ --query "XSS"
    python3 search_standards.py --catalogs-dir catalogs/ --query "authentication" --file wstg_latest.yaml
    python3 search_standards.py --catalogs-dir catalogs/ --query "SQL" --json

Searches id and name fields across all catalog files using case-insensitive matching.
"""

import argparse
import json
import os
import sys
import yaml


def load_catalog(filepath):
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def extract_entries(data, filename):
    entries = []

    def walk(obj, path):
        if isinstance(obj, dict):
            if "id" in obj and "name" in obj:
                entry = {
                    "source": filename,
                    "id": obj["id"],
                    "name": obj["name"],
                    "path": path,
                }
                if "severity" in obj:
                    entry["severity"] = obj["severity"]
                if "rank" in obj:
                    entry["rank"] = obj["rank"]
                if "labs" in obj:
                    entry["labs"] = obj["labs"]
                if "priority" in obj:
                    entry["priority"] = obj["priority"]
                if "products" in obj:
                    entry["products"] = obj["products"]
                entries.append(entry)
            for k, v in obj.items():
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(data, "root")
    return entries


def search_entries(entries, query):
    query_lower = query.lower()
    results = []
    for entry in entries:
        if query_lower in entry["id"].lower() or query_lower in entry["name"].lower():
            results.append(entry)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Search across all standard catalogs by keyword."
    )
    parser.add_argument(
        "--catalogs-dir",
        required=True,
        help="Path to the catalogs directory containing YAML files.",
    )
    parser.add_argument(
        "--query",
        required=True,
        help="Search query string (case-insensitive, matches id and name fields).",
    )
    parser.add_argument(
        "--file",
        default=None,
        help="Search a specific catalog file (e.g., wstg_latest.yaml). If omitted, searches all.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of human-readable text.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.catalogs_dir):
        print(f"ERROR: Catalogs directory not found: {args.catalogs_dir}", file=sys.stderr)
        sys.exit(1)

    if args.file:
        catalog_files = [args.file]
    else:
        catalog_files = sorted(
            f for f in os.listdir(args.catalogs_dir) if f.endswith(".yaml")
        )

    all_results = []

    for filename in catalog_files:
        filepath = os.path.join(args.catalogs_dir, filename)
        if not os.path.isfile(filepath):
            if args.file:
                print(f"ERROR: File not found: {filepath}", file=sys.stderr)
                sys.exit(1)
            continue

        try:
            data = load_catalog(filepath)
        except yaml.YAMLError as e:
            print(f"ERROR: YAML parse error in {filename}: {e}", file=sys.stderr)
            continue

        entries = extract_entries(data, filename)
        results = search_entries(entries, args.query)
        all_results.extend(results)

    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        if not all_results:
            print(f"No results found for query: {args.query}")
        else:
            print(f"Results for '{args.query}': {len(all_results)} match(es)\n")
            for result in all_results:
                source = result["source"]
                entry_id = result["id"]
                name = result["name"]
                extra = []
                if "severity" in result:
                    extra.append(result["severity"])
                if "rank" in result:
                    extra.append(f"rank #{result['rank']}")
                if "labs" in result:
                    extra.append(f"{result['labs']} labs")
                extra_str = f" [{', '.join(extra)}]" if extra else ""
                print(f"  [{source}] {entry_id}: {name}{extra_str}")

    sys.exit(0 if all_results else 1)


if __name__ == "__main__":
    main()