#!/usr/bin/env python3
"""CVSS v3.1 Base Score Calculator per FIRST.org specification.

Usage:
    cvss_calc.py --AV N --AC L --PR N --UI N --S U --C H --I H --A H
    cvss_calc.py --interactive
    cvss_calc.py --help
"""

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CVSS v3.1 metric definitions ──
METRICS = {
    "AV": {
        "desc": "Attack Vector",
        "values": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "options": "N(Network) / A(Adjacent) / L(Local) / P(Physical)",
    },
    "AC": {
        "desc": "Attack Complexity",
        "values": {"L": 0.77, "H": 0.44},
        "options": "L(Low) / H(High)",
    },
    "PR": {
        "desc": "Privileges Required",
        "values": {"N": 0.85, "L": 0.62, "H": 0.27},
        "options": "N(None) / L(Low) / H(High)",
    },
    "PR_C": {
        "desc": "Privileges Required (Changed Scope)",
        "values": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {
        "desc": "User Interaction",
        "values": {"N": 0.85, "R": 0.62},
        "options": "N(None) / R(Required)",
    },
    "S": {
        "desc": "Scope",
        "values": {"U": "Unchanged", "C": "Changed"},
        "options": "U(Unchanged) / C(Changed)",
    },
    "C": {
        "desc": "Confidentiality Impact",
        "values": {"N": 0.00, "L": 0.22, "H": 0.56},
        "options": "N(None) / L(Low) / H(High)",
    },
    "I": {
        "desc": "Integrity Impact",
        "values": {"N": 0.00, "L": 0.22, "H": 0.56},
        "options": "N(None) / L(Low) / H(High)",
    },
    "A": {
        "desc": "Availability Impact",
        "values": {"N": 0.00, "L": 0.22, "H": 0.56},
        "options": "N(None) / L(Low) / H(High)",
    },
}


def calculate_cvss(av: str, ac: str, pr: str, ui: str, s: str, c_imp: str, i_imp: str, a_imp: str) -> dict:
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c_imp}/I:{i_imp}/A:{a_imp}"

    av_val = METRICS["AV"]["values"][av]
    ac_val = METRICS["AC"]["values"][ac]
    ui_val = METRICS["UI"]["values"][ui]

    if s == "C":
        pr_val = METRICS["PR_C"]["values"][pr]
    else:
        pr_val = METRICS["PR"]["values"][pr]

    c_val = METRICS["C"]["values"][c_imp]
    i_val = METRICS["I"]["values"][i_imp]
    a_val = METRICS["A"]["values"][a_imp]

    # ── Exploitability sub-score ──
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    # ── Impact sub-score ──
    isc_base = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))

    if s == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    if impact <= 0:
        base_score = 0.0
    elif s == "U":
        base_score = min(exploitability + impact, 10)
    else:
        base_score = min(1.08 * (exploitability + impact), 10)

    base_score = round_up(base_score)

    severity = score_to_severity(base_score)

    return {
        "vector_string": vector,
        "base_score": base_score,
        "severity": severity,
        "exploitability": round(exploitability, 3),
        "impact": round(impact, 3),
        "scope": "Unchanged" if s == "U" else "Changed",
    }


def round_up(value: float) -> float:
    int_part = int(value * 100000)
    if int_part % 10000 == 0:
        return round(value, 1)
    result = math.ceil(int_part / 10000) / 10.0
    return result


def score_to_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


def interactive_mode() -> dict:
    print("=== CVSS v3.1 Calculator (Interactive) ===\n")
    params = {}
    for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        metric = METRICS.get(key, {})
        options_str = metric.get("options", ", ".join(metric.get("values", {}).keys()))
        desc = metric.get("desc", key)
        while True:
            val = input(f"{desc} [{options_str}]: ").strip().upper()
            try:
                if key == "S" and val in ("U", "C"):
                    pass
                elif val not in metric.get("values", {}):
                    raise ValueError
            except Exception:
                print(f"  Invalid value for {key}. Options: {options_str}")
                continue
            params[key] = val
            break
    return params


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CVSS v3.1 Base Score Calculator (FIRST.org spec)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  cvss_calc.py --AV N --AC L --PR N --UI N --S U --C H --I H --A H

Interactive:
  cvss_calc.py --interactive

Metric reference:
  AV: N(network) A(adjacent) L(local) P(physical)
  AC: L(low) H(high)
  PR: N(none) L(low) H(high)
  UI: N(none) R(required)
  S:  U(unchanged) C(changed)
  C/I/A: N(none) L(low) H(high)
""",
    )
    p.add_argument("--AV", default=None, help="Attack Vector (N/A/L/P)")
    p.add_argument("--AC", default=None, help="Attack Complexity (L/H)")
    p.add_argument("--PR", default=None, help="Privileges Required (N/L/H)")
    p.add_argument("--UI", default=None, help="User Interaction (N/R)")
    p.add_argument("--S", default=None, help="Scope (U/C)")
    p.add_argument("--C", default=None, help="Confidentiality Impact (N/L/H)")
    p.add_argument("--I", default=None, help="Integrity Impact (N/L/H)")
    p.add_argument("--A", default=None, help="Availability Impact (N/L/H)")
    p.add_argument("--interactive", "-i", action="store_true", help="Interactive mode — prompts for each metric")
    p.add_argument("--context", "-c", default=".", help="Output directory for JSON result (default: .)")
    p.add_argument("--dry-run", action="store_true", help="Validate inputs without calculating")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    if args.interactive:
        params = interactive_mode()
    else:
        required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
        missing = [k for k in required if getattr(args, k, None) is None]
        if missing:
            print(f"ERROR: missing required flags: {' '.join('--' + m for m in missing)}", file=sys.stderr)
            print("Use --interactive or provide all metrics.", file=sys.stderr)
            sys.exit(1)
        params = {k: getattr(args, k) for k in required}

    for k, v in params.items():
        valid = METRICS.get(k, {}).get("values", {}) if k != "S" else {"U": 0, "C": 0}
        if v not in valid:
            print(f"ERROR: invalid value '{v}' for {k}. Options: {list(valid.keys())}", file=sys.stderr)
            sys.exit(1)

    if args.dry_run:
        print(json.dumps({"dry_run": True, "params": params}))
        return

    result = calculate_cvss(
        params["AV"], params["AC"], params["PR"], params["UI"],
        params["S"], params["C"], params["I"], params["A"],
    )
    result["params"] = params
    result["timestamp"] = now_iso()

    print(json.dumps(result, indent=2))

    ctx = __import__("pathlib").Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)
    out_path = ctx / f"cvss_{params['AV']}_{params['S']}_{result['severity']}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nSaved to: {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()