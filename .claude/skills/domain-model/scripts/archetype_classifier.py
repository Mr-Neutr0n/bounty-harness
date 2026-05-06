#!/usr/bin/env python3
"""Archetype Classifier — infers domain archetypes from recon output files.

Reads live_full.csv, JS endpoints, tech stack info, and subdomain lists
from a recon context directory and classifies the target application into
one or more domain archetypes using the signals defined in domain.yaml.

Returns a JSON file with archetype matches, confidence scores, and evidence.

Usage:
    python3 archetype_classifier.py --context $OUTDIR/recon --target example.com
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
DOMAIN_YAML = SKILL_DIR / "domain.yaml"


def load_archetypes():
    with open(DOMAIN_YAML) as f:
        data = yaml.safe_load(f)
    return data["archetypes"]


def load_live_hosts(live_file):
    hosts = []
    if not os.path.isfile(live_file):
        return hosts
    with open(live_file) as f:
        for line in f:
            line = line.strip()
            if line:
                hosts.append(line)
    return hosts


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
    endpoints = []
    if not os.path.isfile(endpoints_file):
        return endpoints
    with open(endpoints_file) as f:
        for line in f:
            line = line.strip()
            if line:
                endpoints.append(line)
    return endpoints


def load_js_files(js_files_file):
    files = []
    if not os.path.isfile(js_files_file):
        return files
    with open(js_files_file) as f:
        for line in f:
            line = line.strip()
            if line:
                files.append(line)
    return files


def load_subdomains(subs_file):
    subs = []
    if not os.path.isfile(subs_file):
        return subs
    with open(subs_file) as f:
        for line in f:
            line = line.strip()
            if line:
                subs.append(line)
    return subs


def collect_recon_text(context_dir):
    """Collect all recon text into a single corpus for signal matching."""
    corpus = []

    live_csv = os.path.join(context_dir, "live", "live_full.csv")
    for row in load_live_csv(live_csv):
        corpus.append(row.get("url", ""))
        corpus.append(row.get("title", ""))
        corpus.append(row.get("tech", ""))
        corpus.append(row.get("content_type", ""))
        corpus.append(row.get("webserver", ""))
        corpus.append(row.get("cdn", ""))

    js_endpoints_file = os.path.join(context_dir, "js", "js_endpoints.txt")
    for ep in load_js_endpoints(js_endpoints_file):
        corpus.append(ep)

    js_files_file = os.path.join(context_dir, "js", "js_files.txt")
    for fpath in load_js_files(js_files_file):
        corpus.append(fpath)

    subs_file = os.path.join(context_dir, "subdomains", "subs.txt")
    for sub in load_subdomains(subs_file):
        corpus.append(sub)

    live_file = os.path.join(context_dir, "live", "live_hosts.txt")
    for host in load_live_hosts(live_file):
        corpus.append(host)

    return "\n".join(corpus).lower()


def match_pattern(pattern, corpus):
    """Check if a signal pattern appears in the recon corpus."""
    pattern_lower = pattern.lower()
    return pattern_lower in corpus


def match_url_pattern(pattern, hosts):
    """Check if any subdomain matches a glob-like pattern."""
    escaped = re.escape(pattern.replace("*", "WILDCARD")).replace("WILDCARD", ".*")
    regex = re.compile(f"^{escaped}$", re.IGNORECASE)
    for host in hosts:
        clean = host.strip()
        if not clean:
            continue
        if "/" in clean:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(clean if "://" in clean else f"https://{clean}")
                hostname = parsed.hostname or clean
            except Exception:
                hostname = clean
        else:
            hostname = clean
        if regex.match(hostname):
            return True
    return False


def classify(target, context_dir):
    archetypes = load_archetypes()
    corpus = collect_recon_text(context_dir)

    all_hosts = []
    subs_file = os.path.join(context_dir, "subdomains", "subs.txt")
    all_hosts.extend(load_subdomains(subs_file))
    live_file = os.path.join(context_dir, "live", "live_hosts.txt")
    all_hosts.extend(load_live_hosts(live_file))

    results = []

    for arch_id, arch_def in archetypes.items():
        signals = arch_def.get("tech_signals", [])
        url_patterns = arch_def.get("url_patterns", [])

        signal_hits = 0
        evidence = []

        for signal in signals:
            if match_pattern(signal, corpus):
                signal_hits += 1
                evidence.append(signal)

        for pattern in url_patterns:
            if match_url_pattern(pattern, all_hosts):
                signal_hits += 1
                evidence.append(f"URL pattern matched: {pattern}")

        total_signals = len(signals) + len(url_patterns)
        if total_signals == 0:
            continue

        confidence = min(1.0, signal_hits / max(total_signals * 0.2, 1.0)) if signal_hits > 0 else 0.0

        if confidence > 0.05:
            results.append({
                "id": arch_id,
                "confidence": round(confidence, 3),
                "evidence": evidence[:10]
            })

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Classify a bug bounty target into domain archetypes from recon data."
    )
    parser.add_argument("--context", required=True,
                        help="Path to recon output directory (e.g. $OUTDIR/recon)")
    parser.add_argument("--target", required=True,
                        help="Target domain (e.g. example.com)")
    parser.add_argument("--output", default=None,
                        help="Output JSON file path (default: <context>/../domain-model/archetypes.json)")
    args = parser.parse_args()

    out_dir = args.output
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(args.context.rstrip("/")),
                               "domain-model", "archetypes.json")

    os.makedirs(os.path.dirname(out_dir), exist_ok=True)

    results = classify(args.target, args.context)

    output = {
        "target": args.target,
        "archetypes": results
    }

    with open(out_dir, "w") as f:
        json.dump(output, f, indent=2)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()