#!/usr/bin/env python3
"""Domain Profile Report Generator — generates a markdown report from domain model analysis.

Reads the archetype classifier and surface mapper JSON outputs and produces
a human-readable markdown report with domain archetypes, attack surfaces,
priority recommendations, and next-step workflows.

Usage:
    python3 domain_report.py --target example.com --archetypes $OUTDIR/domain-model/archetypes.json --surfaces $OUTDIR/domain-model/surfaces.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DOMAIN_YAML = SKILL_DIR / "domain.yaml"


def load_archetypes():
    with open(DOMAIN_YAML) as f:
        data = yaml.safe_load(f)
    return data["archetypes"]


def load_json(path):
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def archetype_priority_badge(confidence):
    if confidence >= 0.7:
        return "HIGH"
    elif confidence >= 0.3:
        return "MEDIUM"
    return "LOW"


def surface_conf_badge(conf):
    if conf == "high":
        return "HIGH"
    elif conf == "medium":
        return "MEDIUM"
    return "INFERRED"


def generate_report(target, program, archetypes_file, surfaces_file, output_path, json_output_path=None):
    archetype_data = load_json(archetypes_file)
    surfaces_data = load_json(surfaces_file)
    archetype_defs = load_archetypes()

    ar_results = archetype_data.get("archetypes", [])
    sf_results = surfaces_data.get("detected_surfaces", [])

    lines = []
    lines.append(f"# Domain Profile: {target}")
    lines.append("")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    profile = {
        "target": target,
        "generated_at": now,
        "program": program,
        "archetypes": ar_results,
        "surfaces": sf_results,
        "source_files": {
            "archetypes": archetypes_file,
            "surfaces": surfaces_file,
            "markdown_report": output_path,
        },
    }
    if json_output_path is None:
        root, _ = os.path.splitext(output_path)
        json_output_path = f"{root}.json"
    profile["source_files"]["json_profile"] = json_output_path

    lines.append(f"> Generated: {now}")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Archetype Classification")
    lines.append("")
    lines.append("| Archetype | Confidence | Priority | High-Value Actions |")
    lines.append("| --- | --- | --- | --- |")
    for a in ar_results:
        aid = a["id"]
        conf = a["confidence"]
        pct = int(conf * 100)
        badge = archetype_priority_badge(conf)
        defn = archetype_defs.get(aid, {})
        actions = defn.get("high_value_actions", [])
        action_summary = ", ".join(actions[:3]) if actions else "-"
        lines.append(f"| {defn.get('name', aid)} | {pct}% ({conf:.2f}) | **{badge}** | {action_summary} |")

    lines.append("")
    lines.append("### Evidence Summary")
    lines.append("")
    for a in ar_results:
        lines.append(f"**{a['id']}** ({a['confidence']:.2f})")
        for ev in a.get("evidence", []):
            lines.append(f"- {ev}")
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Attack Surfaces Detected")
    lines.append("")
    lines.append("| Surface | Confidence | Auth Required | Intrusive Level | Recommended Skills |")
    lines.append("| --- | --- | --- | --- | --- |")
    for s in sf_results:
        skills = ", ".join(s.get("related_skills", []))
        lines.append(
            f"| {s['name']} | **{surface_conf_badge(s['confidence'])}** | {s['auth_required']} | {s['intrusive_level']} | {skills} |"
        )

    lines.append("")

    high_conf = [s for s in sf_results if s["confidence"] == "high"]
    med_conf = [s for s in sf_results if s["confidence"] == "medium"]
    inferred = [s for s in sf_results if s["confidence"] == "inferred"]

    lines.append("---")
    lines.append("")

    lines.append("## Priority Testing Order")
    lines.append("")
    lines.append("### Immediate (High Confidence Surfaces)")
    if high_conf:
        for i, s in enumerate(high_conf, 1):
            skills = ", ".join(s.get("related_skills", []))
            lines.append(f"{i}. **{s['name']}** — load skills: {skills}")
    else:
        lines.append("- No high-confidence surfaces detected.")

    lines.append("")
    lines.append("### Secondary (Medium Confidence Surfaces)")
    if med_conf:
        for i, s in enumerate(med_conf, 1):
            skills = ", ".join(s.get("related_skills", []))
            lines.append(f"{i}. **{s['name']}** — load skills: {skills}")
    else:
        lines.append("- No medium-confidence surfaces detected.")

    lines.append("")
    lines.append("### Follow-up (Inferred from Archetype)")
    if inferred:
        for i, s in enumerate(inferred, 1):
            skills = ", ".join(s.get("related_skills", []))
            lines.append(f"{i}. **{s['name']}** — load skills: {skills}")
    else:
        lines.append("- No inferred surfaces.")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Recommended Skill Loading Order")
    lines.append("")
    lines.append("Based on combined archetype + surface analysis:")
    lines.append("")

    seen_skills = set()
    for s in high_conf + med_conf + inferred:
        for skill in s.get("related_skills", []):
            if skill not in seen_skills:
                seen_skills.add(skill)
                lines.append(f"1. `{skill}`")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Output Artifacts")
    lines.append("")
    lines.append("| Artifact | Path |")
    lines.append("| --- | --- |")
    lines.append(f"| Archetype JSON | `{archetypes_file}` |")
    lines.append(f"| Surfaces JSON | `{surfaces_file}` |")
    lines.append(f"| Domain Report | `{output_path}` |")
    lines.append(f"| Domain Profile JSON | `{json_output_path}` |")

    content = "\n".join(lines) + "\n"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(content)

    os.makedirs(os.path.dirname(json_output_path), exist_ok=True)
    with open(json_output_path, "w") as f:
        json.dump(profile, f, indent=2)

    print(content)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a domain profile markdown report from archetype and surface analysis."
    )
    parser.add_argument("--target", required=True,
                        help="Target domain (e.g. example.com)")
    parser.add_argument("--program", default="unknown",
                        help="Program name for profile metadata")
    parser.add_argument("--archetypes", required=True,
                        help="Path to archetype classifier output JSON")
    parser.add_argument("--surfaces", required=True,
                        help="Path to surface mapper output JSON")
    parser.add_argument("--output", default=None,
                        help="Output markdown file path (default: <archetypes dir>/domain-profile.md)")
    parser.add_argument("--json-output", default=None,
                        help="Output JSON domain profile path (default: same basename as markdown)")
    args = parser.parse_args()

    out_dir = args.output
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(args.archetypes), "domain-profile.md")

    generate_report(args.target, args.program, args.archetypes, args.surfaces, out_dir, args.json_output)


if __name__ == "__main__":
    main()
