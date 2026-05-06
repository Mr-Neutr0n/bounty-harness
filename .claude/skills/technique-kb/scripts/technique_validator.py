#!/usr/bin/env python3
"""Validate all technique YAML files against the technique schema.

Reads the schema from technique_schema.yaml, walks the techniques/ directory,
and validates each .yaml file. Reports pass/fail with specific error messages.

Usage:
    python3 technique_validator.py --techniques-dir techniques --schema technique_schema.yaml
    python3 technique_validator.py --help
"""

import argparse
import os
import sys
import yaml
import jsonschema


def load_schema(schema_path):
    with open(schema_path) as f:
        raw = yaml.safe_load(f)
    schema = raw.get("schema")
    if not schema:
        raise ValueError(f"No 'schema' key found in {schema_path}")
    return schema


def collect_techniques(techniques_dir):
    techniques = []
    for root, dirs, files in os.walk(techniques_dir):
        for fn in files:
            if fn.endswith(".yaml") or fn.endswith(".yml"):
                techniques.append(os.path.join(root, fn))
    return sorted(techniques)


def validate_one(filepath, schema):
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {e}"

    if data is None:
        return False, "File is empty or null"

    if not isinstance(data, dict):
        return False, f"Expected dict, got {type(data).__name__}"

    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        path = ".".join(str(p) for p in e.absolute_path) if e.absolute_path else "<root>"
        return False, f"Validation error at {path}: {e.message}"

    return True, "OK"


def main():
    parser = argparse.ArgumentParser(
        description="Validate technique YAML files against the canonical schema",
        epilog="Exit code is 0 when all pass, 1 when any fail.",
    )
    parser.add_argument(
        "--techniques-dir",
        required=True,
        help="Directory containing technique YAML files",
    )
    parser.add_argument(
        "--schema",
        required=True,
        help="Path to technique_schema.yaml",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.techniques_dir):
        print(f"ERROR: techniques-dir not found: {args.techniques_dir}", file=sys.stderr)
        sys.exit(2)

    if not os.path.isfile(args.schema):
        print(f"ERROR: schema file not found: {args.schema}", file=sys.stderr)
        sys.exit(2)

    try:
        schema = load_schema(args.schema)
    except Exception as e:
        print(f"ERROR: Failed to load schema: {e}", file=sys.stderr)
        sys.exit(2)

    files = collect_techniques(args.techniques_dir)
    if not files:
        print("WARNING: No YAML files found in techniques directory", file=sys.stderr)
        sys.exit(0)

    results = []
    for fp in files:
        ok, msg = validate_one(fp, schema)
        rel = os.path.relpath(fp, args.techniques_dir)
        results.append((rel, ok, msg))
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {rel}")
        if not ok:
            print(f"        {msg}")

    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    print(f"\n--- Summary: {passed} passed, {failed} failed, {len(results)} total ---")

    if failed > 0:
        print("\nFailed files:")
        for rel, ok, msg in results:
            if not ok:
                print(f"  {rel}: {msg}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()