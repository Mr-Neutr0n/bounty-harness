#!/usr/bin/env python3
"""
Domain-Driven Ranked Test Plan Generator

Loads domain profile (archetypes + surfaces), technique catalog, coverage data,
and produces a prioritized plan of workflows ranked by business impact,
surface prevalence, vulnerability severity, signal quality, coverage gaps,
and tool availability.
"""

import argparse
import json
import os
import sys
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


SKILL_DIR = Path(__file__).resolve().parent.parent
RANKING_RULES_PATH = SKILL_DIR / "ranking_rules.yaml"
PLAN_SCHEMA_PATH = SKILL_DIR / "plan_schema.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        print(f"PyYAML not installed — attempting pip install", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "PyYAML"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import yaml as _yaml_module
        globals()["yaml"] = _yaml_module

    with open(path, "r") as fh:
        return yaml.safe_load(fh)


def load_ranking_rules() -> dict[str, Any]:
    return _load_yaml(RANKING_RULES_PATH)


def load_plan_schema() -> dict[str, Any]:
    return _load_yaml(PLAN_SCHEMA_PATH)


def load_domain_profile(path: str) -> dict[str, Any]:
    with open(path, "r") as fh:
        return json.load(fh)


def load_file(path: str) -> str:
    with open(path, "r") as fh:
        return fh.read()


def technique_surfaces(technique: dict[str, Any]) -> list[str]:
    surfaces = technique.get("surfaces")
    if surfaces is None:
        surfaces = technique.get("applies_to", {}).get("surfaces", [])
    if not isinstance(surfaces, list):
        return []
    return [str(surface) for surface in surfaces]


def technique_standards(technique: dict[str, Any]) -> list[str]:
    standards: list[str] = []
    nested = technique.get("standards", {})
    if isinstance(nested, dict):
        for values in nested.values():
            if isinstance(values, list):
                standards.extend(str(value) for value in values)
    for key in ("owasp_wstg", "owasp_api_top10"):
        values = technique.get(key, [])
        if isinstance(values, list):
            standards.extend(str(value) for value in values)
    return sorted(set(standards))


def workflow_mapping(technique: dict[str, Any]) -> tuple[str, str]:
    mapping = technique.get("workflow_mapping", {})
    if not isinstance(mapping, dict):
        mapping = {}
    skill = mapping.get("skill") or technique.get("skill") or technique.get("category", "unknown")
    workflow = mapping.get("workflow") or technique.get("workflow") or "default"
    return str(skill), str(workflow)


def requirement_block(technique: dict[str, Any]) -> dict[str, Any]:
    requires = technique.get("requires", {})
    if not isinstance(requires, dict):
        requires = {}
    tools = requires.get("tools", technique.get("tools", []))
    inputs = requires.get("inputs", technique.get("inputs_needed", []))
    if not isinstance(tools, list):
        tools = []
    if not isinstance(inputs, list):
        inputs = []
    return {
        "auth_required": requires.get("auth", technique.get("auth_required", "none")),
        "inputs_needed": inputs,
        "tools": tools,
    }


def signal_block(technique: dict[str, Any]) -> dict[str, list[str]]:
    sigs = technique.get("expected_signals") or technique.get("signals") or {}
    if not isinstance(sigs, dict):
        sigs = {}
    positive = sigs.get("positive", [])
    negative = sigs.get("negative", [])
    if not isinstance(positive, list):
        positive = []
    if not isinstance(negative, list):
        negative = []
    return {"positive": positive, "negative": negative}


def discover_technique_files(techniques_dir: str) -> list[Path]:
    td = Path(techniques_dir)
    if not td.is_dir():
        return []
    yaml_files = list(td.rglob("*.yaml")) + list(td.rglob("*.yml"))
    return sorted(yaml_files)


def load_technique(filepath: Path) -> dict[str, Any] | None:
    try:
        data = _load_yaml(filepath)
        if not isinstance(data, dict):
            return None
        if "id" not in data:
            return None
        return data
    except Exception as exc:
        print(f"  warn: skipping {filepath}: {exc}", file=sys.stderr)
        return None


def load_all_techniques(techniques_dir: str) -> list[dict[str, Any]]:
    files = discover_technique_files(techniques_dir)
    techniques: list[dict[str, Any]] = []
    for fp in files:
        t = load_technique(fp)
        if t is not None:
            techniques.append(t)
    return techniques


def load_coverage_matrix(path: str | None) -> dict[str, Any]:
    if path is None or not os.path.isfile(path):
        return {"covered": [], "partial": [], "missing": []}
    try:
        with open(path, "r") as fh:
            if path.endswith((".yaml", ".yml")):
                data = yaml.safe_load(fh) if yaml is not None else None
            else:
                data = json.load(fh)
    except Exception:
        return {"covered": [], "partial": [], "missing": []}

    if not isinstance(data, dict):
        return {"covered": [], "partial": [], "missing": []}

    if all(key in data for key in ("covered", "partial", "missing")):
        return data

    covered: list[str] = []
    partial: list[str] = []
    missing: list[str] = []
    for standard in data.get("standards", []) or []:
        for section in standard.get("sections", []) or []:
            for item in section.get("items", []) or []:
                item_id = item.get("id")
                if not item_id:
                    continue
                statuses = [
                    str(entry.get("status", "")).lower()
                    for entry in item.get("covered_by", []) or []
                    if isinstance(entry, dict)
                ]
                if "covered" in statuses:
                    covered.append(item_id)
                elif "partial" in statuses:
                    partial.append(item_id)
                else:
                    missing.append(item_id)

    return {
        "covered": sorted(set(covered)),
        "partial": sorted(set(partial)),
        "missing": sorted(set(missing)),
    }


SEVERITY_MAP = {"critical": 1.0, "high": 0.75, "medium": 0.50, "low": 0.25, "info": 0.10}

SURFACE_CATEGORY_MAP: dict[str, list[str]] = {
    "web_form": ["xss", "sqli", "ssrf", "rce", "file-upload"],
    "get_param": ["xss", "sqli", "ssrf", "rce", "race-condition"],
    "post_param": ["xss", "sqli", "ssrf", "rce", "race-condition", "file-upload"],
    "api_endpoint": ["api", "auth", "cors-csrf", "sqli", "xss", "ssrf", "rce"],
    "auth_endpoint": ["auth", "race-condition", "sqli"],
    "file_upload": ["file-upload", "xss", "rce"],
    "websocket": ["xss", "sqli"],
    "graphql": ["api", "sqli", "auth", "ssrf"],
    "webhook": ["webhooks", "ssrf", "rce", "sqli"],
    "cookie_header": ["auth", "cors-csrf", "xss", "sqli"],
    "redirect": ["ssrf", "xss", "rce"],
    "cloud_asset": ["cloud", "ssrf"],
    "mobile_endpoint": ["mobile", "api", "auth"],
    "search_function": ["xss", "sqli"],
}

WEIGHTS = {
    "business_impact": 0.30,
    "surface_prevalence": 0.20,
    "vulnerability_severity": 0.20,
    "detection_signal_quality": 0.15,
    "coverage_gap_urgency": 0.10,
    "tool_availability": 0.05,
}

TIERS = [
    ("critical", 0.80),
    ("high", 0.60),
    ("medium", 0.35),
    ("low", -1.0),
]


def extract_surface_ids(domain_profile: dict[str, Any]) -> list[str]:
    surfaces = domain_profile.get("surfaces", [])
    return [s.get("id", "").lower() for s in surfaces if isinstance(s, dict) and s.get("id")]


def extract_surface_categories(domain_profile: dict[str, Any]) -> list[str]:
    surfaces = domain_profile.get("surfaces", [])
    cats: list[str] = []
    for s in surfaces:
        if isinstance(s, dict):
            sid = s.get("id", "").lower()
            cats.append(sid)
            cat = s.get("category", "").lower()
            if cat:
                cats.append(cat)
    return list(set(cats))


def extract_archetype_ids(domain_profile: dict[str, Any]) -> list[str]:
    archetypes = domain_profile.get("archetypes", [])
    return [a.get("id", "").lower() for a in archetypes if isinstance(a, dict) and a.get("id")]


def extract_detected_servers(domain_profile: dict[str, Any]) -> list[str]:
    servers = domain_profile.get("detected_servers", [])
    if not servers:
        archetypes = domain_profile.get("archetypes", [])
        for a in archetypes:
            if isinstance(a, dict):
                sigs = a.get("key_signals", [])
                for sig in sigs:
                    if isinstance(sig, str) and "server" in sig.lower():
                        servers.append(sig)
    return list(set(servers))


def tech_to_category(tech: str) -> list[str]:
    tech_l = tech.lower()
    cats: list[str] = []
    if any(k in tech_l for k in ("react", "vue", "angular", "svelte", "javascript", "node")):
        cats.append("xss")
    if any(k in tech_l for k in ("mysql", "postgres", "mongo", "redis", "sqlite", "oracle")):
        cats.append("sqli")
    if any(k in tech_l for k in ("aws", "s3", "gcp", "azure", "cloudfront")):
        cats.append("cloud")
        cats.append("ssrf")
    if any(k in tech_l for k in ("flask", "django", "rails", "laravel", "express", "spring")):
        cats.append("rce")
    if any(k in tech_l for k in ("graphql",)):
        cats.append("api")
    if any(k in tech_l for k in ("stripe", "billing", "checkout")):
        cats.append("billing")
    return cats


def compute_business_impact(technique: dict[str, Any], domain_profile: dict[str, Any]) -> float:
    t_sev = technique.get("severity", "medium").lower()
    base = SEVERITY_MAP.get(t_sev, 0.5)

    archetypes = domain_profile.get("archetypes", [])
    if not archetypes:
        return base

    archetype_severity_weights: list[float] = []
    for arch in archetypes:
        if isinstance(arch, dict):
            sw = arch.get("severity_weight")
            if isinstance(sw, (int, float)):
                archetype_severity_weights.append(float(sw))
    if not archetype_severity_weights:
        return base

    avg_arch_weight = sum(archetype_severity_weights) / len(archetype_severity_weights)
    return (base + avg_arch_weight) / 2.0


def compute_surface_prevalence(technique: dict[str, Any], domain_profile: dict[str, Any],
                                surface_ids: list[str], surface_cats: list[str]) -> float:
    tech_surfaces = technique_surfaces(technique)
    tech_cat = technique.get("category", "").lower()

    match_count = 0
    for ts in tech_surfaces:
        ts_l = str(ts).lower()
        if ts_l in surface_ids or ts_l in surface_cats:
            match_count += 1
            continue
        mapped_cats = SURFACE_CATEGORY_MAP.get(ts_l, [])
        for mc in mapped_cats:
            if mc in surface_cats or any(mc in sc for sc in surface_cats):
                match_count += 1
                break

    for sid in surface_ids:
        mapped_cats = SURFACE_CATEGORY_MAP.get(sid, [])
        if tech_cat in mapped_cats:
            match_count += 1
            break

    if not tech_surfaces and match_count == 0:
        return 0.30

    max_surfaces = max(len(tech_surfaces), len(surface_ids), 1)
    ratio = min(match_count / max_surfaces, 1.0)
    return 0.30 + 0.70 * ratio


def compute_vulnerability_severity(technique: dict[str, Any]) -> float:
    t_sev = technique.get("severity", "medium").lower()
    return SEVERITY_MAP.get(t_sev, 0.5)


def compute_signal_quality(technique: dict[str, Any]) -> float:
    sigs = signal_block(technique)
    positive = sigs["positive"]
    negative = sigs["negative"]

    pos_score = min(len(positive) / 5.0, 1.0)
    neg_score = min(len(negative) / 3.0, 1.0)
    specificity_score = 0.5 if negative else 0.0

    return 0.20 + 0.40 * pos_score + 0.20 * neg_score + 0.20 * specificity_score


def compute_coverage_gap(technique: dict[str, Any], coverage: dict[str, Any]) -> float:
    keys = [technique.get("id", "")] + technique_standards(technique)
    covered = coverage.get("covered", [])
    partial = coverage.get("partial", [])
    if not isinstance(covered, list):
        covered = []
    if not isinstance(partial, list):
        partial = []

    if any(key in covered for key in keys):
        return 0.0
    if any(key in partial for key in keys):
        return 0.40
    if not covered and not partial:
        return 0.80
    return 1.0


def compute_tool_availability(technique: dict[str, Any]) -> float:
    tools = requirement_block(technique)["tools"]
    if not tools:
        return 0.50

    available = 0
    for tool in tools:
        tool_name = str(tool).split()[0].strip()
        if shutil.which(tool_name):
            available += 1

    return available / len(tools)


def determine_priority(score: float) -> str:
    for tier_name, threshold in TIERS:
        if score >= threshold:
            return tier_name
    return "low"


def generate_plan(domain_profile: dict[str, Any], techniques: list[dict[str, Any]],
                  coverage: dict[str, Any]) -> dict[str, Any]:
    surface_ids = extract_surface_ids(domain_profile)
    surface_cats = extract_surface_categories(domain_profile)
    archetype_ids = extract_archetype_ids(domain_profile)
    detected_servers = extract_detected_servers(domain_profile)

    plan_items: list[dict[str, Any]] = []
    scores: list[float] = []

    for technique in techniques:
        s_business = compute_business_impact(technique, domain_profile)
        s_surface = compute_surface_prevalence(technique, domain_profile, surface_ids, surface_cats)
        s_severity = compute_vulnerability_severity(technique)
        s_signal = compute_signal_quality(technique)
        s_coverage = compute_coverage_gap(technique, coverage)
        s_tool = compute_tool_availability(technique)

        total = (
            WEIGHTS["business_impact"] * s_business
            + WEIGHTS["surface_prevalence"] * s_surface
            + WEIGHTS["vulnerability_severity"] * s_severity
            + WEIGHTS["detection_signal_quality"] * s_signal
            + WEIGHTS["coverage_gap_urgency"] * s_coverage
            + WEIGHTS["tool_availability"] * s_tool
        )

        priority = determine_priority(total)

        sigs = signal_block(technique)
        positive_signals = sigs["positive"]
        negative_signals = sigs["negative"]

        matched_surfaces: list[str] = []
        for ts in technique_surfaces(technique):
            ts_l = str(ts).lower()
            if ts_l in surface_ids + surface_cats:
                matched_surfaces.append(ts_l)

        covered = coverage.get("covered", [])
        if not isinstance(covered, list):
            covered = []
        partial = coverage.get("partial", [])
        if not isinstance(partial, list):
            partial = []
        tid = technique.get("id", "")
        coverage_keys = [tid] + technique_standards(technique)
        coverage_gap = not any(key in covered or key in partial for key in coverage_keys)

        rationale_parts: list[str] = []
        if s_business >= 0.75:
            rationale_parts.append(f"critical business impact ({s_business:.2f})")
        elif s_business >= 0.5:
            rationale_parts.append(f"moderate business impact ({s_business:.2f})")
        if matched_surfaces:
            rationale_parts.append(f"surface match: {', '.join(matched_surfaces)}")
        if coverage_gap:
            rationale_parts.append("fills coverage gap")
        if not rationale_parts:
            rationale_parts.append(f"scored by severity ({technique.get('severity', 'unknown')})")

        requirements = requirement_block(technique)
        skill, workflow = workflow_mapping(technique)
        safety = technique.get("safety", {})
        if not isinstance(safety, dict):
            safety = {}
        evidence = technique.get("evidence", {})
        if isinstance(evidence, dict):
            evidence_requirements = evidence.get("required", [])
        else:
            evidence_requirements = technique.get("evidence_requirements", [])
        if not isinstance(evidence_requirements, list):
            evidence_requirements = []

        plan_items.append({
            "priority": priority,
            "score": round(total, 4),
            "score_breakdown": {
                "business_impact": round(s_business, 4),
                "surface_prevalence": round(s_surface, 4),
                "vulnerability_severity": round(s_severity, 4),
                "detection_signal_quality": round(s_signal, 4),
                "coverage_gap_urgency": round(s_coverage, 4),
                "tool_availability": round(s_tool, 4),
            },
            "technique_id": technique.get("id", f"unknown-{uuid.uuid4().hex[:8]}"),
            "technique_name": technique.get("name", technique.get("id", "unknown")),
            "category": technique.get("category", "unknown"),
            "severity": technique.get("severity", "medium"),
            "skill": skill,
            "workflow": workflow,
            "rationale": "; ".join(rationale_parts),
            "surface_matches": matched_surfaces,
            "preconditions": requirements,
            "safety": {
                "intrusive": bool(safety.get("intrusive", technique.get("intrusive", False))),
                "data_modifying": bool(safety.get("data_modifying", technique.get("data_modifying", False))),
                "rate_limited": bool(safety.get("rate_limited", technique.get("rate_limited", False))),
                "requires_confirmation": bool(safety.get("requires_approval", technique.get("requires_confirmation", False))),
            },
            "expected_signals": {
                "positive": positive_signals,
                "negative": negative_signals,
            },
            "evidence_requirements": evidence_requirements,
            "standards_checked": technique_standards(technique),
            "coverage_gap": coverage_gap,
        })
        scores.append(total)

    plan_items.sort(key=lambda x: x["score"], reverse=True)

    by_priority: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in plan_items:
        by_priority[item["priority"]] = by_priority.get(item["priority"], 0) + 1

    auth_required_count = sum(
        1 for item in plan_items
        if item["preconditions"].get("auth_required", "none") not in ("none", "")
    )
    intrusive_count = sum(1 for item in plan_items if item["safety"]["intrusive"])
    safe_count = sum(
        1 for item in plan_items
        if not item["safety"]["intrusive"] and not item["safety"]["data_modifying"]
    )

    coverage_before = domain_profile.get("standards_coverage_pct", 0.0)
    total_available = len(techniques)
    matched = len(plan_items)
    coverage_after = min(coverage_before + (matched / max(total_available, 1)) * 50.0, 100.0)

    return {
        "metadata": {
            "target": domain_profile.get("target", "unknown"),
            "program": domain_profile.get("program", "unknown"),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standards_coverage_pct": round(coverage_after, 1),
            "total_techniques_available": total_available,
            "techniques_matched": matched,
            "techniques_filtered": 0,
        },
        "domain_profile": {
            "archetypes": domain_profile.get("archetypes", []),
            "surfaces": domain_profile.get("surfaces", []),
        },
        "plan_items": plan_items,
        "summary": {
            "total_plan_items": len(plan_items),
            "by_priority": by_priority,
            "auth_required_count": auth_required_count,
            "intrusive_count": intrusive_count,
            "safe_to_run_immediately": safe_count,
            "coverage_before": round(coverage_before, 1),
            "coverage_after": round(coverage_after, 1),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Domain-Driven Ranked Test Plan Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 generate_plan.py --domain-profile /path/to/domain_profile.json \\
      --techniques-dir .claude/skills/technique-kb/techniques/ \\
      --output plan.json

  python3 generate_plan.py --domain-profile domain.json \\
      --techniques-dir techniques/ \\
      --coverage-matrix coverage.json \\
      --output plan.json
        """,
    )
    parser.add_argument(
        "--domain-profile",
        required=True,
        help="Path to domain profile JSON (output of domain-model classifier)",
    )
    parser.add_argument(
        "--techniques-dir",
        required=True,
        help="Path to technique-kb/techniques/ directory containing YAML technique files",
    )
    parser.add_argument(
        "--coverage-matrix",
        default=None,
        help="Optional path to coverage matrix JSON",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for the plan JSON file",
    )
    parser.add_argument(
        "--exclude-intrusive",
        action="store_true",
        help="Exclude intrusive techniques from the plan",
    )
    parser.add_argument(
        "--exclude-destructive",
        action="store_true",
        help="Exclude data-modifying techniques from the plan",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.domain_profile):
        print(f"error: domain profile not found: {args.domain_profile}", file=sys.stderr)
        sys.exit(1)

    techniques_dir = args.techniques_dir
    if not os.path.isdir(techniques_dir):
        print(f"error: techniques directory not found: {techniques_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"loading domain profile from {args.domain_profile} ...")
    domain_profile = load_domain_profile(args.domain_profile)

    print(f"loading techniques from {techniques_dir} ...")
    techniques = load_all_techniques(techniques_dir)

    if not techniques:
        print("warn: no technique YAML files found in techniques directory — "
              "plan will be empty", file=sys.stderr)

    coverage = load_coverage_matrix(args.coverage_matrix)
    print(f"coverage data: {len(coverage.get('covered', []))} covered, "
          f"{len(coverage.get('partial', []))} partial, "
          f"{len(coverage.get('missing', []))} missing")

    print(f"generating plan for {len(techniques)} techniques ...")
    plan = generate_plan(domain_profile, techniques, coverage)

    if args.exclude_intrusive:
        before = len(plan["plan_items"])
        plan["plan_items"] = [
            item for item in plan["plan_items"]
            if not item["safety"]["intrusive"]
        ]
        print(f"excluded {before - len(plan['plan_items'])} intrusive items")

    if args.exclude_destructive:
        before = len(plan["plan_items"])
        plan["plan_items"] = [
            item for item in plan["plan_items"]
            if not item["safety"]["data_modifying"]
        ]
        print(f"excluded {before - len(plan['plan_items'])} destructive items")

    plan["metadata"]["techniques_filtered"] = (
        plan["metadata"]["techniques_matched"] - len(plan["plan_items"])
    )

    by_priority: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in plan["plan_items"]:
        by_priority[item["priority"]] = by_priority.get(item["priority"], 0) + 1
    plan["summary"]["by_priority"] = by_priority
    plan["summary"]["total_plan_items"] = len(plan["plan_items"])
    plan["summary"]["auth_required_count"] = sum(
        1 for item in plan["plan_items"]
        if item["preconditions"].get("auth_required", "none") not in ("none", "")
    )
    plan["summary"]["intrusive_count"] = sum(
        1 for item in plan["plan_items"] if item["safety"]["intrusive"]
    )
    plan["summary"]["safe_to_run_immediately"] = sum(
        1 for item in plan["plan_items"]
        if not item["safety"]["intrusive"] and not item["safety"]["data_modifying"]
    )

    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "w") as fh:
        json.dump(plan, fh, indent=2)

    items = plan["plan_items"]
    priorities = [p for p in ["critical", "high", "medium", "low"] if by_priority.get(p, 0) > 0]

    print()
    print(f"plan written to {args.output}")
    print(f"  total items: {len(items)}")
    if priorities:
        print(f"  by priority: " + ", ".join(
            f"{p}={by_priority[p]}" for p in priorities
        ))
    if items:
        print(f"  top item: [{items[0]['priority']}] {items[0]['technique_name']} "
              f"({items[0]['score']:.4f})")
    print(f"  coverage: {plan['summary']['coverage_before']}% -> "
          f"{plan['summary']['coverage_after']}%")


if __name__ == "__main__":
    main()
