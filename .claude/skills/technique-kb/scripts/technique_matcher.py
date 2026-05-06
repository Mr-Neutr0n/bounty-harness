#!/usr/bin/env python3
"""Match techniques to target archetypes and surfaces.

Reads all technique YAML files, then takes target archetypes and surfaces
from JSON files and produces a ranked JSON list of applicable techniques.

Ranking: exact match on both archetype + surface ranks highest, then
archetype-only, then surface-only.

Usage:
    python3 technique_matcher.py --techniques-dir techniques \
        --archetypes-file archetypes.json --surfaces-file surfaces.json
    python3 technique_matcher.py --help
"""

import argparse
import json
import os
import sys
import yaml


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def load_json(path):
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path) as f:
        return json.load(f)


def normalize_id_list(data, primary_key):
    """Accept either a raw list or the domain-model JSON objects."""
    if isinstance(data, list):
        values = data
    elif isinstance(data, dict):
        values = data.get(primary_key, [])
        if primary_key == "surfaces" and not values:
            values = data.get("detected_surfaces", [])
    else:
        values = []

    normalized = []
    for item in values:
        if isinstance(item, dict):
            item_id = item.get("id")
            if item_id:
                normalized.append(str(item_id))
        elif item:
            normalized.append(str(item))
    return normalized


def collect_techniques(techniques_dir):
    techniques = []
    for root, dirs, files in os.walk(techniques_dir):
        for fn in files:
            if fn.endswith((".yaml", ".yml")):
                fp = os.path.join(root, fn)
                try:
                    with open(fp) as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict) and "id" in data:
                        techniques.append(data)
                except Exception as e:
                    print(f"WARNING: Skipping {fp}: {e}", file=sys.stderr)
    return techniques


def match_technique(tech, target_archetypes, target_surfaces):
    applies = tech.get("applies_to", {})

    tech_arches = set(applies.get("archetypes", []))
    tech_surfs = set(applies.get("surfaces", []))

    target_arches = set(target_archetypes)
    target_surfs = set(target_surfaces)

    has_arch = "all" in tech_arches or bool(tech_arches & target_arches)
    has_surf = "all" in tech_surfs or bool(tech_surfs & target_surfs)

    if "all" in tech_arches:
        has_arch = True
    if "all" in tech_surfs:
        has_surf = True

    score = 0
    match_type = "none"

    if has_arch and has_surf:
        score = 3
        match_type = "archetype_and_surface"
    elif has_arch:
        score = 2
        match_type = "archetype_only"
    elif has_surf:
        score = 1
        match_type = "surface_only"

    sev_score = SEVERITY_RANK.get(tech.get("severity", "info"), 1)

    return score, match_type, sev_score


def main():
    parser = argparse.ArgumentParser(
        description="Match techniques to target archetypes and surfaces",
        epilog="Outputs JSON list sorted by match relevance.",
    )
    parser.add_argument(
        "--techniques-dir",
        required=True,
        help="Directory containing technique YAML files",
    )
    parser.add_argument(
        "--archetypes-file",
        required=True,
        help="JSON file with list of target archetype IDs",
    )
    parser.add_argument(
        "--surfaces-file",
        required=True,
        help="JSON file with list of target surface IDs",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.techniques_dir):
        print(f"ERROR: techniques-dir not found: {args.techniques_dir}", file=sys.stderr)
        sys.exit(2)

    target_archetypes = normalize_id_list(load_json(args.archetypes_file), "archetypes")
    target_surfaces = normalize_id_list(load_json(args.surfaces_file), "surfaces")

    if not target_archetypes and not target_surfaces:
        print("ERROR: no archetype or surface IDs found in input files", file=sys.stderr)
        sys.exit(2)

    techniques = collect_techniques(args.techniques_dir)

    matches = []
    for tech in techniques:
        score, match_type, sev_score = match_technique(tech, target_archetypes, target_surfaces)
        if score > 0:
            matches.append({
                "technique_id": tech.get("id"),
                "name": tech.get("name"),
                "category": tech.get("category"),
                "severity": tech.get("severity"),
                "severity_rank": sev_score,
                "match_type": match_type,
                "match_score": score,
                "safety": tech.get("safety", {}),
                "workflow": tech.get("workflow_mapping"),
                "description": tech.get("description", "").strip()[:200],
            })

    matches.sort(key=lambda m: (m["match_score"], m["severity_rank"]), reverse=True)

    output = {
        "target_archetypes": target_archetypes,
        "target_surfaces": target_surfaces,
        "total_matches": len(matches),
        "techniques": matches,
    }

    print(json.dumps(output, indent=2))

    unmatched = [t for t in techniques if not any(m["technique_id"] == t["id"] for m in matches)]
    if unmatched:
        print(f"\n# {len(unmatched)} unmatched techniques (excluded from output above):", file=sys.stderr)
        for t in unmatched:
            print(f"#   {t.get('id')}", file=sys.stderr)


if __name__ == "__main__":
    main()
