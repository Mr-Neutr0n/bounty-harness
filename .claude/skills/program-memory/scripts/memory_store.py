#!/usr/bin/env python3
"""Program memory store — persist target facts, false positives, findings history, planner hints."""
import argparse, json, os, sys
from datetime import datetime, timezone
from pathlib import Path

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def init_memory(memory_dir, output_path):
    Path(memory_dir).mkdir(parents=True, exist_ok=True)
    memory = {
        "program": "unknown",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "facts": [],
        "stats": {"total_runs": 0, "total_findings": 0, "accepted": 0, "rejected": 0}
    }
    (Path(memory_dir) / "program_memory.json").write_text(json.dumps(memory, indent=2))
    (Path(memory_dir) / "false_positives.jsonl").write_text("")
    (Path(memory_dir) / "findings_history.jsonl").write_text("")
    Path(output_path).write_text(json.dumps({"status": "initialized", "dir": memory_dir}))
    print(json.dumps({"status": "initialized"}))

def import_run(memory_dir, run_dir, output_path):
    mem_file = Path(memory_dir) / "program_memory.json"
    if mem_file.exists():
        memory = json.loads(mem_file.read_text())
    else:
        memory = {"program": "unknown", "facts": [], "stats": {"total_runs": 0, "total_findings": 0, "accepted": 0, "rejected": 0}}
    memory["stats"]["total_runs"] += 1
    findings_file = Path(run_dir) / "impact-verifier" / "verified.jsonl"
    if findings_file.exists():
        count = len([l for l in findings_file.read_text().splitlines() if l.strip()])
        memory["stats"]["total_findings"] = memory["stats"].get("total_findings",0) + count
    memory["last_run"] = datetime.now(timezone.utc).isoformat()
    memory["last_run_dir"] = str(run_dir)
    mem_file.write_text(json.dumps(memory, indent=2))
    Path(output_path).write_text(json.dumps({"status": "imported", "runs": memory["stats"]["total_runs"]}))
    print(json.dumps({"status": "imported"}))

def record_fact(memory_dir, category, value, confidence, output_path):
    mem_file = Path(memory_dir) / "program_memory.json"
    if not mem_file.exists():
        init_memory(memory_dir, output_path)
    memory = json.loads(mem_file.read_text()) if mem_file.exists() else {"facts": []}
    fact = {"category": category, "value": value, "confidence": confidence,
            "recorded_at": datetime.now(timezone.utc).isoformat(), "source": "manual"}
    memory.setdefault("facts", []).append(fact)
    mem_file.write_text(json.dumps(memory, indent=2))
    print(json.dumps({"status": "fact_recorded", "category": category}))

def record_false_positive(memory_dir, pattern, description, output_path):
    fp_file = Path(memory_dir) / "false_positives.jsonl"
    entry = {"pattern": pattern, "description": description,
             "recorded_at": datetime.now(timezone.utc).isoformat()}
    existing = fp_file.read_text() if fp_file.exists() else ""
    fp_file.write_text(existing + json.dumps(entry) + "\n")
    print(json.dumps({"status": "fp_recorded"}))

def record_finding(memory_dir, finding_json, output_path):
    fh_file = Path(memory_dir) / "findings_history.jsonl"
    try:
        finding = json.loads(finding_json)
        finding["recorded_at"] = datetime.now(timezone.utc).isoformat()
        existing = fh_file.read_text() if fh_file.exists() else ""
        fh_file.write_text(existing + json.dumps(finding) + "\n")
        print(json.dumps({"status": "finding_recorded"}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))

def summarize(memory_dir, output_path):
    mem_file = Path(memory_dir) / "program_memory.json"
    memory = json.loads(mem_file.read_text()) if mem_file.exists() else {"facts": [], "stats": {}}
    fp_count = 0
    if (Path(memory_dir) / "false_positives.jsonl").exists():
        fp_count = len([l for l in (Path(memory_dir) / "false_positives.jsonl").read_text().splitlines() if l.strip()])
    lines = [f"# Program Memory: {memory.get('program','unknown')}\n"]
    lines.append(f"- **Total runs**: {memory.get('stats',{}).get('total_runs',0)}")
    lines.append(f"- **Total findings**: {memory.get('stats',{}).get('total_findings',0)}")
    lines.append(f"- **False positive patterns**: {fp_count}")
    lines.append(f"- **Recorded facts**: {len(memory.get('facts',[]))}")
    lines.append(f"\n## Facts\n")
    for fact in memory.get("facts",[]):
        lines.append(f"- [{fact.get('confidence','?')}] **{fact.get('category','')}**: {fact.get('value','')}")
    Path(output_path).write_text("\n".join(lines))
    print(json.dumps({"status": "summarized"}))

def export_hints(memory_dir, output_path):
    hints = {"upweight": [], "downweight": [], "notes": []}
    mem_file = Path(memory_dir) / "program_memory.json"
    if mem_file.exists():
        memory = json.loads(mem_file.read_text())
        hints["notes"] = [f.get("value","") for f in memory.get("facts",[])]
    fp_file = Path(memory_dir) / "false_positives.jsonl"
    if fp_file.exists():
        for line in fp_file.read_text().splitlines():
            if line.strip():
                fp = json.loads(line)
                hints["downweight"].append({"reason": fp.get("description",""), "pattern": fp.get("pattern","")})
    Path(output_path).write_text(json.dumps(hints, indent=2))
    print(json.dumps({"status": "hints_exported", "notes": len(hints["notes"]), "downweights": len(hints["downweight"])}))

def main():
    parser = argparse.ArgumentParser(description="Program memory store")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True)
    parser.add_argument("--memory-dir", required=True)
    parser.add_argument("--run-dir")
    parser.add_argument("--fact-category")
    parser.add_argument("--fact-value")
    parser.add_argument("--confidence", default="medium")
    parser.add_argument("--pattern")
    parser.add_argument("--description")
    parser.add_argument("--finding")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.action == "init":
        init_memory(args.memory_dir, args.output)
    elif args.action == "import":
        import_run(args.memory_dir, args.run_dir, args.output)
    elif args.action == "record-fact":
        record_fact(args.memory_dir, args.fact_category, args.fact_value, args.confidence, args.output)
    elif args.action == "record-fp":
        record_false_positive(args.memory_dir, args.pattern, args.description, args.output)
    elif args.action == "record-finding":
        record_finding(args.memory_dir, args.finding, args.output)
    elif args.action == "summarize":
        summarize(args.memory_dir, args.output)
    elif args.action == "hints":
        export_hints(args.memory_dir, args.output)

if __name__ == "__main__":
    main()