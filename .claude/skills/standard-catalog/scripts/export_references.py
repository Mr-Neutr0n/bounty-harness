#!/usr/bin/env python3
"""Export a combined reference JSON with all standard IDs from all catalogs.

Usage:
    python3 export_references.py --catalogs-dir catalogs/ --output references.json
    python3 export_references.py --catalogs-dir catalogs/ --output references.json --pretty

Produces a unified JSON structure:
    {
      "generated": "<ISO8601 timestamp>",
      "catalogs": {
        "wstg_latest.yaml": { "source": "...", "version": "...", "entries": [...] },
        ...
      },
      "crosswalk": { "WSTG-INFO-01": ["CWE-200"], ... },
      "summary": { "total_entries": N, "catalog_count": N }
    }
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import yaml


CROSSWALK_MAP = {
    "WSTG-INFO": "CWE-200",
    "WSTG-INFO-01": ["CWE-200"],
    "WSTG-INFO-02": ["CWE-200"],
    "WSTG-CONFIG": "CWE-16",
    "WSTG-CONFIG-03": ["CWE-538"],
    "WSTG-CONFIG-04": ["CWE-530"],
    "WSTG-CONFIG-06": ["CWE-650"],
    "WSTG-CONFIG-10": ["CWE-350"],
    "WSTG-CONFIG-12": ["CWE-1021"],
    "WSTG-ATHN-01": ["CWE-319"],
    "WSTG-ATHN-02": ["CWE-798"],
    "WSTG-ATHN-04": ["CWE-287"],
    "WSTG-ATHN-07": ["CWE-521"],
    "WSTG-ATHZ-01": ["CWE-22"],
    "WSTG-ATHZ-03": ["CWE-269"],
    "WSTG-ATHZ-04": ["CWE-639"],
    "WSTG-SESS-02": ["CWE-614"],
    "WSTG-SESS-03": ["CWE-384"],
    "WSTG-SESS-04": ["CWE-488"],
    "WSTG-SESS-05": ["CWE-352"],
    "WSTG-INPV-01": ["CWE-79"],
    "WSTG-INPV-02": ["CWE-79"],
    "WSTG-INPV-03": ["CWE-650"],
    "WSTG-INPV-05": ["CWE-89"],
    "WSTG-INPV-06": ["CWE-90"],
    "WSTG-INPV-08": ["CWE-97"],
    "WSTG-INPV-09": ["CWE-643"],
    "WSTG-INPV-11": ["CWE-94"],
    "WSTG-INPV-12": ["CWE-78"],
    "WSTG-INPV-13": ["CWE-134"],
    "WSTG-INPV-14": ["CWE-652"],
    "WSTG-INPV-15": ["CWE-444"],
    "WSTG-INPV-17": ["CWE-644"],
    "WSTG-INPV-18": ["CWE-1336"],
    "WSTG-INPV-19": ["CWE-918"],
    "WSTG-INPV-20": ["CWE-915"],
    "WSTG-INPV-21": ["CWE-1321"],
    "WSTG-ERRH-01": ["CWE-209"],
    "WSTG-ERRH-02": ["CWE-209"],
    "WSTG-CRYP-01": ["CWE-295"],
    "WSTG-CRYP-03": ["CWE-319"],
    "WSTG-CRYP-04": ["CWE-327"],
    "WSTG-BUSL-01": ["CWE-841"],
    "WSTG-BUSL-10": ["CWE-770"],
    "WSTG-CLNT-01": ["CWE-79"],
    "WSTG-CLNT-02": ["CWE-94"],
    "WSTG-CLNT-03": ["CWE-79"],
    "WSTG-CLNT-04": ["CWE-601"],
    "WSTG-CLNT-05": ["CWE-1336"],
    "WSTG-CLNT-07": ["CWE-942"],
    "WSTG-CLNT-09": ["CWE-1021"],
    "WSTG-CLNT-12": ["CWE-922"],
    "WSTG-APIT-01": ["CWE-200"],
}


def extract_entries(filename, data):
    entries = []

    def walk(obj, path):
        if isinstance(obj, dict):
            if "id" in obj and "name" in obj:
                entry = {"id": obj["id"], "name": obj["name"]}
                for extra in ["severity", "rank", "labs", "priority", "products"]:
                    if extra in obj:
                        entry[extra] = obj[extra]
                entries.append(entry)
            for k, v in obj.items():
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(data, "root")
    return entries


def load_catalog_info(filename, data):
    info = {}
    if "source" in data:
        info["source"] = data["source"]
    if "version" in data:
        info["version"] = data["version"]
    if "year" in data:
        info["year"] = data["year"]
    return info


def build_crosswalk(catalogs_entries):
    crosswalk = {}
    for entry_id, cwe_list in CROSSWALK_MAP.items():
        if isinstance(cwe_list, list):
            crosswalk[entry_id] = cwe_list
        else:
            crosswalk[entry_id] = [cwe_list]
    return crosswalk


def main():
    parser = argparse.ArgumentParser(
        description="Export a combined reference JSON with all standard IDs."
    )
    parser.add_argument(
        "--catalogs-dir",
        required=True,
        help="Path to the catalogs directory containing YAML files.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the output JSON (default: compact).",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.catalogs_dir):
        print(f"ERROR: Catalogs directory not found: {args.catalogs_dir}", file=sys.stderr)
        sys.exit(1)

    catalog_files = sorted(
        f for f in os.listdir(args.catalogs_dir) if f.endswith(".yaml")
    )

    output = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "catalogs": {},
        "crosswalk": {},
        "summary": {"total_entries": 0, "catalog_count": 0},
    }

    total_entries = 0

    for filename in catalog_files:
        filepath = os.path.join(args.catalogs_dir, filename)
        try:
            with open(filepath, "r") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, FileNotFoundError) as e:
            print(f"WARNING: Could not load {filename}: {e}", file=sys.stderr)
            continue

        info = load_catalog_info(filename, data)
        entries = extract_entries(filename, data)
        total_entries += len(entries)

        output["catalogs"][filename] = {
            **info,
            "entries": entries,
        }

    output["crosswalk"] = build_crosswalk(output["catalogs"])
    output["summary"]["total_entries"] = total_entries
    output["summary"]["catalog_count"] = len(output["catalogs"])

    indent = 2 if args.pretty else None
    separators = None if args.pretty else (",", ":")

    try:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=indent, separators=separators)
        print(f"Exported {total_entries} entries from {len(output['catalogs'])} catalogs to {args.output}")
    except OSError as e:
        print(f"ERROR: Could not write output file: {e}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()