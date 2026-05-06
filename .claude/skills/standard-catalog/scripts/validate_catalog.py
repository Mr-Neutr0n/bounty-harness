#!/usr/bin/env python3
"""Validate all catalog YAML files for structure integrity.

Usage:
    python3 validate_catalog.py --catalogs-dir catalogs/
    python3 validate_catalog.py --catalogs-dir catalogs/ --file wstg_latest.yaml

Standards checked:
    wstg_latest.yaml   - sections with id, name, tests[id, name]
    asvs_5.0.yaml      - chapters with id, name, sections[id, name]
    api_top10_2023.yaml - risks with id, name, severity
    bugcrowd_vrt_1.18.yaml - categories with id, name, subcategories
    portswigger_topics.yaml - server_side, client_side, advanced topics
    cwe_top50.yaml     - entries with id, name, rank
    cisa_kev_vendors.yaml - vendors with name, products
    masvs_categories.yaml - categories with id, name, requirements
"""

import argparse
import os
import sys
import yaml

EXPECTED_STRUCTURE = {
    "wstg_latest.yaml": {
        "required_keys": ["source", "version", "sections"],
        "section_type": "sections",
        "section_keys": ["id", "name", "tests"],
        "item_keys": ["id", "name"],
        "item_field": "tests",
    },
    "asvs_5.0.yaml": {
        "required_keys": ["source", "version", "chapters"],
        "section_type": "chapters",
        "section_keys": ["id", "name", "sections"],
        "item_keys": ["id", "name"],
        "item_field": "sections",
    },
    "api_top10_2023.yaml": {
        "required_keys": ["source", "version", "risks"],
        "section_type": "risks",
        "section_keys": None,
        "item_keys": ["id", "name", "severity"],
        "item_field": None,
    },
    "bugcrowd_vrt_1.18.yaml": {
        "required_keys": ["source", "version", "categories"],
        "section_type": "categories",
        "section_keys": ["id", "name", "priority", "subcategories"],
        "item_keys": ["id", "name"],
        "item_field": "subcategories",
    },
    "portswigger_topics.yaml": {
        "required_keys": ["source", "server_side_topics", "client_side_topics", "advanced_topics"],
        "section_type": None,
        "section_keys": None,
        "item_keys": ["id", "name", "labs"],
        "item_field": None,
        "list_fields": ["server_side_topics", "client_side_topics", "advanced_topics"],
    },
    "cwe_top50.yaml": {
        "required_keys": ["source", "year", "entries"],
        "section_type": "entries",
        "section_keys": None,
        "item_keys": ["id", "name", "rank"],
        "item_field": None,
    },
    "cisa_kev_vendors.yaml": {
        "required_keys": ["source", "vendors"],
        "section_type": "vendors",
        "section_keys": None,
        "item_keys": ["name", "products"],
        "item_field": None,
    },
    "masvs_categories.yaml": {
        "required_keys": ["source", "version", "categories"],
        "section_type": "categories",
        "section_keys": ["id", "name", "requirements"],
        "item_keys": ["id", "name"],
        "item_field": "requirements",
    },
}


def validate_file(filepath, structure):
    errors = []
    warnings = []

    if not os.path.isfile(filepath):
        return [f"FILE MISSING: {filepath} - file not found"], []

    try:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML PARSE ERROR: {filepath} - {e}"], []

    if data is None:
        errors.append(f"EMPTY FILE: {filepath}")
        return errors, warnings

    for key in structure["required_keys"]:
        if key not in data:
            errors.append(f"MISSING KEY: '{key}' in {os.path.basename(filepath)}")

    section_type = structure.get("section_type")
    item_field = structure.get("item_field")

    if section_type and section_type in data:
        sections = data[section_type]
        if not isinstance(sections, list):
            errors.append(f"TYPE ERROR: '{section_type}' must be a list in {os.path.basename(filepath)}")
        else:
            for i, section in enumerate(sections):
                if structure.get("section_keys"):
                    for key in structure["section_keys"]:
                        if key not in section:
                            errors.append(
                                f"MISSING KEY: '{key}' in {section_type}[{i}] of {os.path.basename(filepath)}"
                            )

                if item_field and item_field in section:
                    items = section[item_field]
                    if not isinstance(items, list):
                        errors.append(
                            f"TYPE ERROR: '{item_field}' in {section_type}[{i}] must be a list in {os.path.basename(filepath)}"
                        )
                    else:
                        for j, item in enumerate(items):
                            for key in structure["item_keys"]:
                                if key not in item:
                                    errors.append(
                                        f"MISSING KEY: '{key}' in {item_field}[{j}] of {section_type}[{i}] in {os.path.basename(filepath)}"
                                    )

    if not section_type and not item_field:
        if "list_fields" in structure:
            for field in structure["list_fields"]:
                if field in data:
                    items = data[field]
                    if not isinstance(items, list):
                        errors.append(
                            f"TYPE ERROR: '{field}' must be a list in {os.path.basename(filepath)}"
                        )
                    else:
                        for j, item in enumerate(items):
                            for key in structure["item_keys"]:
                                if key not in item:
                                    errors.append(
                                        f"MISSING KEY: '{key}' in {field}[{j}] of {os.path.basename(filepath)}"
                                    )

    ids_seen = set()

    def collect_ids(obj, path):
        if isinstance(obj, dict):
            if "id" in obj:
                item_id = obj["id"]
                if item_id in ids_seen:
                    warnings.append(f"DUPLICATE ID: '{item_id}' at {path} in {os.path.basename(filepath)}")
                else:
                    ids_seen.add(item_id)
            for k, v in obj.items():
                collect_ids(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                collect_ids(v, f"{path}[{i}]")

    collect_ids(data, "root")
    print(f"  OK  {os.path.basename(filepath):30s} ({len(ids_seen)} unique IDs, {len(errors)} errors, {len(warnings)} warnings)")

    return errors, warnings


def main():
    parser = argparse.ArgumentParser(
        description="Validate standard catalog YAML files for structure integrity."
    )
    parser.add_argument(
        "--catalogs-dir",
        required=True,
        help="Path to the catalogs directory containing YAML files.",
    )
    parser.add_argument(
        "--file",
        default=None,
        help="Validate a specific catalog file (e.g., wstg_latest.yaml). If omitted, validates all.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.catalogs_dir):
        print(f"ERROR: Catalogs directory not found: {args.catalogs_dir}", file=sys.stderr)
        sys.exit(1)

    if args.file:
        files_to_check = [args.file]
    else:
        files_to_check = sorted(
            f for f in os.listdir(args.catalogs_dir) if f.endswith(".yaml")
        )

    total_errors = 0
    total_warnings = 0

    for filename in files_to_check:
        if filename not in EXPECTED_STRUCTURE:
            print(f"  ??  {filename:30s} (unknown structure - skipping)")
            continue

        filepath = os.path.join(args.catalogs_dir, filename)
        errors, warnings = validate_file(filepath, EXPECTED_STRUCTURE[filename])
        total_errors += len(errors)
        total_warnings += len(warnings)

        for e in errors:
            print(f"  ERR {e}", file=sys.stderr)
        for w in warnings:
            print(f"  WRN {w}")

    print(f"\nTotal: {total_errors} error(s), {total_warnings} warning(s)")
    if total_errors > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()