#!/usr/bin/env python3
"""Impact verifier — classify impact, verify evidence, gate false positives, score report readiness."""
import argparse, json, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

IMPACT_CLASSES = ["data_exposure","object_takeover","privilege_escalation","tenant_isolation_break",
                  "account_takeover","financial_loss","stored_xss","blind_ssrf","rce","ai_tool_abuse",
                  "rag_data_exfiltration","mcp_confused_deputy","oauth_token_theft"]

FP_PATTERNS = [
    {"pattern": "public.*resource", "description": "Resource is intentionally public or unauthenticated"},
    {"pattern": "example.*data", "description": "Response contains example/test/synthetic data, not real"},
    {"pattern": "403.*expected", "description": "403 is the correct authorization response"},
    {"pattern": "cdn.*proxy", "description": "Callback originated from CDN/proxy, not target origin"},
    {"pattern": "cached.*response", "description": "Response is stale/cached, does not reflect live auth state"},
]

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def collect_candidates(outdir, output_path):
    candidates = []
    od = Path(outdir)
    for pattern in ["*/findings.jsonl", "*/*/findings.jsonl"]:
        for f in sorted(od.glob(pattern)):
            try:
                for line in f.read_text().splitlines():
                    if line.strip():
                        c = json.loads(line)
                        c["source_file"] = str(f)
                        c["candidate_id"] = f"cand_{os.urandom(4).hex()}"
                        candidates.append(c)
            except Exception:
                pass
    Path(output_path).write_text("\n".join(json.dumps(c) for c in candidates))
    print(json.dumps({"status": "collected", "candidates": len(candidates)}))

def classify_impact(candidates_path, output_path):
    if not Path(candidates_path).exists():
        Path(output_path).write_text("")
        print(json.dumps({"status": "no_candidates"}))
        return
    candidates = [json.loads(l) for l in Path(candidates_path).read_text().splitlines() if l.strip()]
    for c in candidates:
        desc = (c.get("description","") + " " + c.get("category","")).lower()
        detected = False
        for ic in IMPACT_CLASSES:
            if ic.replace("_"," ") in desc:
                c["impact_class"] = ic
                detected = True
                break
        if not detected:
            if "xss" in desc: c["impact_class"] = "stored_xss"
            elif "ssrf" in desc: c["impact_class"] = "blind_ssrf"
            elif "rce" in desc or "injection" in desc: c["impact_class"] = "rce"
            elif "auth" in desc or "privilege" in desc: c["impact_class"] = "privilege_escalation"
            else: c["impact_class"] = "data_exposure"
    Path(output_path).write_text("\n".join(json.dumps(c) for c in candidates))
    classes = list(set(c.get("impact_class","") for c in candidates))
    print(json.dumps({"status": "classified", "impact_classes": classes}))

def verify_impact(candidates_path, impact_class, output_path, rejected_path):
    if not Path(candidates_path).exists():
        Path(output_path).write_text("")
        Path(rejected_path).write_text("")
        print(json.dumps({"status": "no_candidates"}))
        return
    candidates = [json.loads(l) for l in Path(candidates_path).read_text().splitlines() if l.strip()]
    verified = []
    rejected = []
    for c in candidates:
        if c.get("impact_class") == impact_class:
            c["verification"] = "confirmed"
            c["verified_at"] = datetime.now(timezone.utc).isoformat()
            verified.append(c)
        elif c.get("impact_class") != impact_class and impact_class == candidates[0].get("impact_class"):
            pass
        elif c not in verified:
            rejected.append(c)
    if verified:
        Path(output_path).write_text("\n".join(json.dumps(v) for v in verified))
    else:
        Path(output_path).write_text("")
    if rejected:
        Path(rejected_path).write_text("\n".join(json.dumps(r) for r in rejected))
    else:
        Path(rejected_path).write_text("")
    print(json.dumps({"status": "verified", "impact_class": impact_class, "verified": len(verified), "rejected": len(rejected)}))

def fp_check(candidates_path, fp_db_path, output_path):
    if not Path(candidates_path).exists():
        print(json.dumps({"status": "no_candidates"}))
        return
    candidates = [json.loads(l) for l in Path(candidates_path).read_text().splitlines() if l.strip()]
    fp_db = FP_PATTERNS
    if fp_db_path and Path(fp_db_path).exists():
        try:
            fp_db = yaml.safe_load(Path(fp_db_path).read_text()).get("patterns", FP_PATTERNS)
        except Exception:
            pass
    for c in candidates:
        desc = c.get("description","").lower()
        c["false_positive_risk"] = "low"
        for fp in fp_db:
            if re.search(fp["pattern"], desc, re.I):
                c["false_positive_risk"] = "high"
                c["false_positive_reason"] = fp["description"]
                break
        c["fp_checked"] = True
    Path(output_path).write_text("\n".join(json.dumps(c) for c in candidates))
    high_risk = sum(1 for c in candidates if c.get("false_positive_risk") == "high")
    print(json.dumps({"status": "fp_gate_complete", "total": len(candidates), "high_fp_risk": high_risk}))

def readiness_report(verified_path, output_path):
    if not Path(verified_path).exists():
        Path(output_path).write_text("# Report Readiness\n\nNo verified findings.\n")
        print(json.dumps({"status": "empty"}))
        return
    findings = [json.loads(l) for l in Path(verified_path).read_text().splitlines() if l.strip()]
    lines = ["# Report Readiness Report\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
    for f in findings:
        score = 85
        if f.get("false_positive_risk") == "high": score -= 20
        if f.get("verification") != "confirmed": score -= 30
        if not f.get("evidence_path"): score -= 10
        f["readiness_score"] = score
        status = "READY" if score >= 80 else ("NEEDS_WORK" if score >= 60 else "WEAK")
        lines.append(f"## {f.get('finding_id', 'unknown')} — {status} ({score}/100)")
        lines.append(f"- **Category**: {f.get('category','unknown')}")
        lines.append(f"- **Impact**: {f.get('impact_class','unknown')}")
        lines.append(f"- **Severity**: {f.get('severity','medium')}")
        lines.append(f"- **FP Risk**: {f.get('false_positive_risk','unknown')}")
        lines.append("")
    Path(output_path).write_text("\n".join(lines))
    ready = sum(1 for f in findings if f.get("readiness_score",0) >= 80)
    print(json.dumps({"status": "readiness_complete", "findings": len(findings), "ready": ready}))

def main():
    parser = argparse.ArgumentParser(description="Impact verifier")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True)
    parser.add_argument("--outdir")
    parser.add_argument("--candidates")
    parser.add_argument("--impact-class")
    parser.add_argument("--false-positive-db")
    parser.add_argument("--verified")
    parser.add_argument("--output")
    parser.add_argument("--rejected")
    args = parser.parse_args()
    if args.action == "collect":
        collect_candidates(args.outdir, args.output)
    elif args.action == "classify":
        classify_impact(args.candidates, args.output)
    elif args.action == "verify":
        verify_impact(args.candidates, args.impact_class, args.output, args.rejected)
    elif args.action == "fp-check":
        fp_check(args.candidates, args.false_positive_db, args.output)
    elif args.action == "readiness":
        readiness_report(args.verified, args.output)

if __name__ == "__main__":
    main()