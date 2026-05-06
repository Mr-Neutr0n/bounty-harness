#!/usr/bin/env python3
"""
candidate_reviewer.py — Scores and filters candidates for import readiness.

Scoring dimensions:
  - novelty (0-10): How novel is this technique/payload/reference?
  - exploitability (0-10): How exploitable is it? Real-world impact?
  - data_available (0-10): How much actionable data is present?
  - source_credibility (0-10): How trustworthy is the source?

Outputs a ranked and filtered list suitable for import into the technique KB.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def score_novelty(candidate):
    score = 5.0

    has_cve = bool(candidate.get("cve_ids") or candidate.get("cve_id"))
    category = candidate.get("category", "")
    description = candidate.get("description", "")
    name = candidate.get("name", "")
    description_len = len(description)

    if category == "new_technique":
        score += 2.5
    elif category == "new_payload":
        score += 1.5
    elif category == "new_reference":
        score += 0.5

    if has_cve:
        score += 1.5

    if description_len > 500:
        score += 1.5

    known_patterns = ["known", "common", "standard", "basic", "typical", "trivial"]
    combined_text = f"{name} {description}".lower()
    for pat in known_patterns:
        if pat in combined_text:
            score -= 0.5

    return max(0.0, min(10.0, score))


def score_exploitability(candidate):
    score = 5.0

    category = candidate.get("category", "")
    description = candidate.get("description", "")
    name = candidate.get("name", "")
    combined_text = f"{name} {description}".lower()

    exploit_signals = [
        "exploit", "exploitation", "poc", "proof of concept",
        "weaponized", "actively exploited", "in the wild",
        "public exploit", "code execution", "rce",
        "privilege escalation", "shell", "reverse shell",
        "unauthenticated", "no authentication", "no auth"
    ]
    for sig in exploit_signals:
        if sig in combined_text:
            score += 1.0

    if candidate.get("severity"):
        sev = candidate["severity"].lower()
        sev_map = {"critical": 3.0, "high": 2.5, "medium": 1.5, "low": 0.5, "info": 0.0}
        score += sev_map.get(sev, 1.0)

    if candidate.get("has_code_blocks"):
        score += 1.0

    if candidate.get("code_block_count", 0) > 2:
        score += 0.5

    return max(0.0, min(10.0, score))


def score_data_available(candidate):
    score = 3.0

    description = candidate.get("description", "")
    name = candidate.get("name", "")

    if len(description) > 100:
        score += 1.0
    if len(description) > 500:
        score += 1.0
    if len(description) > 2000:
        score += 1.0

    if candidate.get("has_code_blocks"):
        score += 1.0
    if candidate.get("code_block_count", 0) > 1:
        score += 0.5

    if candidate.get("cve_ids"):
        score += 1.0
    if candidate.get("cve_id"):
        score += 0.5

    if candidate.get("tags"):
        score += 0.5

    if len(name) > 10:
        score += 0.5

    return max(0.0, min(10.0, score))


def score_source_credibility(candidate, rules):
    source_id = candidate.get("source_id", "")
    extraction_type = candidate.get("source_type", "")

    scores_map = rules.get("scoring", {}).get("source_credibility_scores", {})

    if source_id in scores_map:
        base = scores_map[source_id] * 10.0
    elif extraction_type in scores_map:
        base = scores_map[extraction_type] * 10.0
    else:
        base = 5.0

    return base


def score_candidate(candidate, rules):
    scoring = rules.get("scoring", {})
    weights = scoring.get("weights", {
        "novelty": 0.35,
        "exploitability": 0.30,
        "data_available": 0.20,
        "source_credibility": 0.15
    })

    scores = {
        "novelty": score_novelty(candidate),
        "exploitability": score_exploitability(candidate),
        "data_available": score_data_available(candidate),
        "source_credibility": score_source_credibility(candidate, rules)
    }

    composite = sum(
        scores[dim] * weights.get(dim, 0.25)
        for dim in scores
    )

    composite = round(composite, 2)

    return composite, scores


def review_candidates(candidates, rules):
    min_threshold = rules.get("scoring", {}).get("min_score_threshold", 0.40)

    scored = []
    for candidate in candidates:
        composite, dimension_scores = score_candidate(candidate, rules)
        scored.append({
            "candidate": candidate,
            "composite_score": composite,
            "dimension_scores": dimension_scores,
            "passes_threshold": composite >= min_threshold
        })

    scored.sort(key=lambda x: x["composite_score"], reverse=True)

    passed = [s for s in scored if s["passes_threshold"]]
    rejected = [s for s in scored if not s["passes_threshold"]]

    result = {
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "total_candidates": len(candidates),
        "passed": len(passed),
        "rejected": len(rejected),
        "min_threshold": min_threshold,
        "score_distribution": {
            "0-2": sum(1 for s in scored if s["composite_score"] < 2),
            "2-4": sum(1 for s in scored if 2 <= s["composite_score"] < 4),
            "4-6": sum(1 for s in scored if 4 <= s["composite_score"] < 6),
            "6-8": sum(1 for s in scored if 6 <= s["composite_score"] < 8),
            "8-10": sum(1 for s in scored if s["composite_score"] >= 8),
        },
        "candidates": scored
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Score and filter technique candidates for import readiness"
    )
    parser.add_argument(
        "--candidates",
        required=True,
        help="Path to candidate JSON file (deduplicated output from deduplicator.py, or candidates from knowledge_extractor.py)"
    )
    parser.add_argument(
        "--rules",
        required=True,
        help="Path to ingest_rules.yaml"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write reviewed output JSON"
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Override minimum score threshold from rules"
    )
    args = parser.parse_args()

    if not os.path.exists(args.candidates):
        print(f"ERROR: candidates file not found: {args.candidates}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.rules):
        print(f"ERROR: rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)

    rules = load_yaml(args.rules)

    if args.min_score is not None:
        rules.setdefault("scoring", {})["min_score_threshold"] = args.min_score

    data = load_json(args.candidates)

    candidates_list = []
    if isinstance(data, dict):
        dedup_candidates = data.get("candidates")
        if isinstance(dedup_candidates, list):
            candidates_list = dedup_candidates
    if isinstance(data, list):
        candidates_list = data
    if not candidates_list and isinstance(data, dict) and "candidate" in data:
        candidates_list = [data]

    if not candidates_list:
        print("ERROR: no candidates found in input file", file=sys.stderr)
        sys.exit(1)

    result = review_candidates(candidates_list, rules)

    output_dir = os.path.dirname(args.output) or "."
    os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"Total candidates: {result['total_candidates']}")
    print(f"Passed threshold ({result['min_threshold']}): {result['passed']}")
    print(f"Rejected: {result['rejected']}")
    print(f"Score distribution: {json.dumps(result['score_distribution'], indent=2)}")
    print(f"Output: {args.output}")

    if result["passed"] > 0:
        print(f"\nTop 5 candidates:")
        for s in result["candidates"][:5]:
            c = s["candidate"]
            print(f"  [{s['composite_score']}] {c.get('name', 'unknown')[:80]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())