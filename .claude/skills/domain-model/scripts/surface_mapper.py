#!/usr/bin/env python3
"""Surface Mapper — maps recon data to attack surfaces from surfaces.yaml.

Takes the archetype classifier output and recon context directory and maps
detected infrastructure, endpoints, and services to the attack surface taxonomy.

Outputs a JSON file listing detected surfaces, their auth requirements,
and the evidence that led to each detection.

Usage:
    python3 surface_mapper.py --context $OUTDIR/recon --archetypes $OUTDIR/domain-model/archetypes.json
"""

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
SURFACES_YAML = SKILL_DIR / "surfaces.yaml"


def load_surfaces():
    with open(SURFACES_YAML) as f:
        data = yaml.safe_load(f)
    return data["surfaces"]


def load_archetype_results(archetypes_file):
    if not os.path.isfile(archetypes_file):
        return []
    with open(archetypes_file) as f:
        data = json.load(f)
    return data.get("archetypes", [])


def load_live_csv(csv_file):
    rows = []
    if not os.path.isfile(csv_file):
        return rows
    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def load_js_endpoints(endpoints_file):
    if not os.path.isfile(endpoints_file):
        return []
    with open(endpoints_file) as f:
        return [line.strip() for line in f if line.strip()]


def load_js_files(js_files_file):
    if not os.path.isfile(js_files_file):
        return []
    with open(js_files_file) as f:
        return [line.strip() for line in f if line.strip()]


def load_subdomains(subs_file):
    if not os.path.isfile(subs_file):
        return []
    with open(subs_file) as f:
        return [line.strip() for line in f if line.strip()]


def build_context_corpus(context_dir):
    corpus = []

    live_csv = os.path.join(context_dir, "live", "live_full.csv")
    for row in load_live_csv(live_csv):
        corpus.append(json.dumps(row).lower())

    for ep in load_js_endpoints(os.path.join(context_dir, "js", "js_endpoints.txt")):
        corpus.append(ep.lower())

    for fp in load_js_files(os.path.join(context_dir, "js", "js_files.txt")):
        corpus.append(fp.lower())

    for sub in load_subdomains(os.path.join(context_dir, "subdomains", "subs.txt")):
        corpus.append(sub.lower())

    return "\n".join(corpus)


def map_surfaces(context_dir, archetype_results):
    surfaces = load_surfaces()
    corpus = build_context_corpus(context_dir)

    archetype_ids = {a["id"] for a in archetype_results}

    detected = []

    for surf_id, surf_def in surfaces.items():
        signals = surf_def.get("detection_signals", [])
        related_archetypes = surf_def.get("archetypes", [])

        signal_hits = 0
        evidence = []

        for signal in signals:
            if signal.lower() in corpus:
                signal_hits += 1
                evidence.append(signal)

        archetype_match = bool(set(related_archetypes) & archetype_ids)

        if signal_hits > 0 or archetype_match:
            confidence = "high" if signal_hits >= 2 else "medium" if signal_hits == 1 else "inferred"
            found = {
                "id": surf_id,
                "name": surf_def.get("name", surf_id),
                "confidence": confidence,
                "auth_required": surf_def.get("auth_required", "unknown"),
                "intrusive_level": surf_def.get("intrusive_level", "careful"),
                "related_skills": surf_def.get("related_skills", []),
                "evidence": evidence[:5],
                "archetype_match": archetype_match
            }
            detected.append(found)

    detected.sort(key=lambda x: (
        0 if x["confidence"] == "high" else 1 if x["confidence"] == "medium" else 2,
        x["id"]
    ))

    return detected


def main():
    parser = argparse.ArgumentParser(
        description="Map recon data to attack surfaces using surface taxonomy."
    )
    parser.add_argument("--context", required=True,
                        help="Path to recon output directory (e.g. $OUTDIR/recon)")
    parser.add_argument("--archetypes", required=True,
                        help="Path to archetype classifier output JSON")
    parser.add_argument("--output", default=None,
                        help="Output JSON file path (default: <context>/../domain-model/surfaces.json)")
    args = parser.parse_args()

    out_dir = args.output
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(args.context.rstrip("/")),
                               "domain-model", "surfaces.json")

    os.makedirs(os.path.dirname(out_dir), exist_ok=True)

    archetype_results = load_archetype_results(args.archetypes)
    results = map_surfaces(args.context, archetype_results)

    output = {
        "target": Path(args.context).resolve().parent.name or args.archetypes,
        "detected_surfaces": results,
        "total_detected": len(results)
    }

    with open(out_dir, "w") as f:
        json.dump(output, f, indent=2)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
