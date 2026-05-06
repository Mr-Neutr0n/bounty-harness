#!/usr/bin/env python3
"""
Plan Visualizer

Converts a planner JSON plan into readable markdown output.
Produces a human-friendly summary table, per-item detail cards,
priority distribution chart, and coverage delta.
"""

import argparse
import json
import os
import sys


def format_score_breakdown(breakdown: dict) -> str:
    parts = []
    labels = [
        ("business_impact", "Biz"),
        ("surface_prevalence", "Surface"),
        ("vulnerability_severity", "Sev"),
        ("detection_signal_quality", "Signal"),
        ("coverage_gap_urgency", "Gap"),
        ("tool_availability", "Tools"),
    ]
    for key, short in labels:
        val = breakdown.get(key, 0)
        parts.append(f"{short}={val:.3f}")
    return " ".join(parts)


def format_safety_badges(safety: dict) -> str:
    badges = []
    if safety.get("intrusive"):
        badges.append("`INTRUSIVE`")
    if safety.get("data_modifying"):
        badges.append("`DESTRUCTIVE`")
    if safety.get("rate_limited"):
        badges.append("`RATE-LIMITED`")
    if safety.get("requires_confirmation"):
        badges.append("`CONFIRM-REQ`")
    if not badges:
        badges.append("`SAFE`")
    return " ".join(badges)


def generate_markdown(plan: dict) -> str:
    lines: list[str] = []

    meta = plan.get("metadata", {})
    dp = plan.get("domain_profile", {})
    summary = plan.get("summary", {})
    items = plan.get("plan_items", [])

    target = meta.get("target", "unknown")
    program = meta.get("program", "unknown")
    generated = meta.get("generated_at", "unknown")

    lines.append(f"# Test Plan: {target}")
    lines.append("")
    lines.append("> Generated: {generated} | Program: {program}".format(
        generated=generated, program=program))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total techniques matched | {summary.get('total_plan_items', 0)} |")
    by_priority = summary.get("by_priority", {})
    for p in ["critical", "high", "medium", "low"]:
        count = by_priority.get(p, 0)
        if count > 0:
            lines.append(f"| 🟥 {p.capitalize()} priority | {count} |")
    lines.append(f"| Requires authentication | {summary.get('auth_required_count', 0)} |")
    lines.append(f"| Intrusive items | {summary.get('intrusive_count', 0)} |")
    lines.append(f"| Safe to run immediately | {summary.get('safe_to_run_immediately', 0)} |")
    lines.append(f"| Standards coverage | {summary.get('coverage_before', 0)}% -> "
                 f"{summary.get('coverage_after', 0)}% |")
    lines.append("")

    surfaces = dp.get("surfaces", [])
    if surfaces:
        lines.append("## Detected Surfaces")
        lines.append("")
        for surf in surfaces:
            if isinstance(surf, dict):
                sid = surf.get("id", "?")
                status = surf.get("status", "?")
                endpoints = surf.get("endpoints_available", 0)
                auth = surf.get("auth_state", "?")
                lines.append(f"- `{sid}` — status: {status}, endpoints: {endpoints}, "
                             f"auth: {auth}")
        lines.append("")

    archetypes = dp.get("archetypes", [])
    if archetypes:
        lines.append("## Domain Archetypes")
        lines.append("")
        for arch in archetypes:
            if isinstance(arch, dict):
                aid = arch.get("id", "?")
                conf = arch.get("confidence", "?")
                sigs = arch.get("key_signals", [])
                lines.append(f"- `{aid}` (confidence: {conf})")
                for sig in sigs[:3]:
                    lines.append(f"  - {sig}")
        lines.append("")

    lines.append("## Prioritized Test Plan")
    lines.append("")

    if not items:
        lines.append("_No techniques matched the current target profile._")
        lines.append("")
        return "\n".join(lines)

    for i, item in enumerate(items):
        idx = i + 1
        priority = item.get("priority", "low").upper()
        name = item.get("technique_name", "unknown")
        score = item.get("score", 0)
        severity = item.get("severity", "?").upper()

        priority_emoji = {"CRITICAL": "\U0001F7E5", "HIGH": "\U0001F7E8",
                          "MEDIUM": "\U0001F7E7", "LOW": "\u2B1C"}
        emoji = priority_emoji.get(priority, "\u2B1C")

        lines.append(f"### {idx}. {emoji} [{priority}] {name} (score: {score:.4f})")
        lines.append("")

        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        safe = format_safety_badges(item.get("safety", {}))
        cat = item.get("category", "?")
        tid = item.get("technique_id", "?")
        skill = item.get("skill", "?")
        workflow = item.get("workflow", "?")
        lines.append(f"| Category | `{cat}` |")
        lines.append(f"| Technique ID | `{tid}` |")
        lines.append(f"| Severity | `{severity}` |")
        lines.append(f"| Skill | `{skill}` |")
        lines.append(f"| Workflow | `{workflow}` |")
        lines.append(f"| Safety | {safe} |")
        lines.append("")

        lines.append(f"**Rationale:** {item.get('rationale', 'none')}")
        lines.append("")

        breakdown = item.get("score_breakdown", {})
        if breakdown:
            lines.append(f"**Score breakdown:** `{format_score_breakdown(breakdown)}`")
            lines.append("")

        preconditions = item.get("preconditions", {})
        auth = preconditions.get("auth_required", "none")
        if auth and auth != "none":
            lines.append(f"- **Auth required:** {auth}")

        tools = preconditions.get("tools", [])
        if tools:
            lines.append(f"- **Tools:** {', '.join(tools)}")

        inputs = preconditions.get("inputs_needed", [])
        if inputs:
            lines.append(f"- **Inputs needed:** {', '.join(inputs)}")

        lines.append("")

        sigs = item.get("expected_signals", {})
        positive = sigs.get("positive", [])
        negative = sigs.get("negative", [])

        if positive:
            lines.append("**Expected positive signals:**")
            for s in positive:
                lines.append(f"- \u2705 {s}")
            lines.append("")

        if negative:
            lines.append("**Expected negative signals:**")
            for s in negative:
                lines.append(f"- \u274C {s}")
            lines.append("")

        evidence = item.get("evidence_requirements", [])
        if evidence:
            lines.append("**Evidence to collect:**")
            for e in evidence:
                lines.append(f"- {e}")
            lines.append("")

        standards = item.get("standards_checked", [])
        if standards:
            lines.append(f"**Standards:** {', '.join(standards)}")
            lines.append("")

        if item.get("coverage_gap"):
            lines.append("\U0001F50D **This technique fills a coverage gap**")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("## Execution Order")
    lines.append("")
    lines.append("```")
    lines.append("1. Start with all CRITICAL priority items (safe, non-intrusive)")
    lines.append("2. Run HIGH priority items that don't require auth")
    lines.append("3. Configure auth for HIGH items that require it")
    lines.append("4. Run MEDIUM priority items as time permits")
    lines.append("5. Review LOW items and decide if they add value")
    lines.append("```")
    lines.append("")

    lines.append("---")
    lines.append(f"_Plan generated by planner skill at {generated}_")

    return "\n".join(lines)


def generate_html(plan: dict) -> str:
    md = generate_markdown(plan)
    try:
        import markdown as _md
        css = """<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a;
       line-height: 1.6; }
h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
h3 { margin-top: 30px; background: #f5f5f5; padding: 8px 12px; border-radius: 6px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
td, th { border: 1px solid #ddd; padding: 6px 12px; text-align: left; }
code { background: #eee; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
pre { background: #f5f5f5; padding: 12px; border-radius: 6px; overflow-x: auto; }
hr { margin: 30px 0; }
</style>
"""
        html = _md.markdown(md, extensions=["tables", "fenced_code"])
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Test Plan: {plan.get('metadata', {}).get('target', 'unknown')}</title>
{css}
</head>
<body>
{html}
</body>
</html>"""
    except ImportError:
        return f"""<html><body><pre>{md}</pre>
<p><em>Install markdown library for styled HTML output: pip install markdown</em></p>
</body></html>"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan Visualizer — convert plan JSON to readable output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 plan_visualizer.py --plan plan.json --output plan.md
  python3 plan_visualizer.py --plan plan.json --output plan.html --format html
        """,
    )
    parser.add_argument("--plan", required=True, help="Path to plan JSON file")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--format", choices=["markdown", "html"], default="markdown",
                        help="Output format (default: markdown)")
    parser.add_argument("--open", action="store_true",
                        help="Attempt to open the output file after generation")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.plan):
        print(f"error: plan file not found: {args.plan}", file=sys.stderr)
        sys.exit(1)

    with open(args.plan, "r") as fh:
        plan = json.load(fh)

    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if args.format == "html":
        content = generate_html(plan)
    else:
        content = generate_markdown(plan)

    with open(args.output, "w") as fh:
        fh.write(content)

    print(f"plan visualizer: wrote {len(content)} bytes to {args.output}")

    if args.open:
        import subprocess
        subprocess.check_call(["open", args.output])


if __name__ == "__main__":
    main()