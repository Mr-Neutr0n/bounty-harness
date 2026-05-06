#!/usr/bin/env python3
"""Impact verifier — classify impact, verify evidence, gate false positives, score report readiness."""
import argparse, json, os, re, subprocess, sys
from collections import defaultdict
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

SENSITIVE_RE = re.compile(r'(api[_-]?key|apikey|password|secret|token|bearer|cookie|session)[=:]\s*[^\s,;]+', re.I)
EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')


def _redact(text, include_sensitive=False):
    if include_sensitive:
        return text
    if not isinstance(text, str):
        return text
    text = EMAIL_RE.sub("MASKED", text)
    text = SENSITIVE_RE.sub(r'\1=REDACTED', text)
    return text


def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)


def _register_artifact_cmd(kind, path, run_id=None, skill="impact-verifier", summary=""):
    try:
        script = Path(__file__).resolve().parent.parent.parent.parent.parent / "tools" / "artifact_index.py"
        cmd = [
            sys.executable, str(script), "register",
            "--kind", kind, "--path", path,
            "--skill", skill, "--summary", summary
        ]
        if run_id:
            cmd.extend(["--run-id", run_id])
        subprocess.run(cmd, capture_output=True, timeout=10)
    except Exception:
        pass


def _register_findings_from_file(filepath, register_artifacts, run_id=None):
    if not register_artifacts or not Path(filepath).exists():
        return
    try:
        for line in Path(filepath).read_text().splitlines():
            if not line.strip():
                continue
            c = json.loads(line)
            cid = c.get("candidate_id", c.get("finding_id", ""))
            cat = c.get("category", "unknown")
            ic = c.get("impact_class", "unknown")
            summary = f"Finding {cid}: {cat} [{ic}]"
            _register_artifact_cmd("finding", str(filepath), run_id=run_id, summary=summary)
    except Exception:
        pass


def collect_candidates(outdir, output_path, register_artifacts=False, run_id=None):
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
    if register_artifacts:
        _register_findings_from_file(str(output_path), register_artifacts, run_id)
    print(json.dumps({"status": "collected", "candidates": len(candidates)}))


def classify_impact(candidates_path, output_path, register_artifacts=False, run_id=None):
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
    if register_artifacts:
        _register_findings_from_file(str(output_path), register_artifacts, run_id)
    classes = list(set(c.get("impact_class","") for c in candidates))
    print(json.dumps({"status": "classified", "impact_classes": classes}))


def verify_impact(candidates_path, impact_class, output_path, rejected_path, register_artifacts=False, run_id=None):
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
    if register_artifacts and verified:
        _register_findings_from_file(str(output_path), register_artifacts, run_id)
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


def _load_candidates(candidates_path):
    if not Path(candidates_path).exists():
        return []
    return [json.loads(l) for l in Path(candidates_path).read_text().splitlines() if l.strip()]


def candidate_list(candidates_path, output_json):
    candidates = _load_candidates(candidates_path)
    if not candidates:
        result = {"status": "empty", "candidates": []}
        if output_json:
            print(json.dumps(result))
        return result
    items = []
    for c in candidates:
        items.append({
            "candidate_id": c.get("candidate_id","unknown"),
            "severity": c.get("severity","medium"),
            "impact_class": c.get("impact_class","unknown"),
            "status": c.get("verification","pending"),
            "category": c.get("category","unknown"),
            "fp_risk": c.get("false_positive_risk","unknown"),
            "source": c.get("source_file",""),
        })
    result = {"status": "ok", "candidates": items, "count": len(items)}
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Candidates ({len(items)}) ===")
        for item in items:
            print(f"  {item['candidate_id']} [{item['severity']}] {item['impact_class']} ({item['status']}) fp:{item['fp_risk']}")
    return result


def candidate_summary(candidates_path, candidate_id, include_sensitive, output_json):
    candidates = _load_candidates(candidates_path)
    target = None
    for c in candidates:
        if c.get("candidate_id") == candidate_id:
            target = c
            break
    if target is None:
        result = {"status": "not_found", "candidate_id": candidate_id}
        if output_json:
            print(json.dumps(result))
        return result

    description = target.get("description","")
    if not include_sensitive:
        description = _redact(description)

    result = {
        "status": "ok",
        "candidate_id": candidate_id,
        "severity": target.get("severity","medium"),
        "impact_class": target.get("impact_class","unknown"),
        "category": target.get("category","unknown"),
        "status": target.get("verification","pending"),
        "fp_risk": target.get("false_positive_risk","unknown"),
        "fp_reason": target.get("false_positive_reason",""),
        "description": description,
        "source": target.get("source_file",""),
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Candidate: {candidate_id} ===")
        print(f"  Severity:    {result['severity']}")
        print(f"  Impact:      {result['impact_class']}")
        print(f"  Category:    {result['category']}")
        print(f"  Status:      {result['status']}")
        print(f"  FP Risk:     {result['fp_risk']}")
        if result['fp_reason']:
            print(f"  FP Reason:   {result['fp_reason']}")
        print(f"  Description: {result['description'][:300]}")
    return result


def candidate_full(candidates_path, candidate_id, include_sensitive, output_json):
    candidates = _load_candidates(candidates_path)
    target = None
    for c in candidates:
        if c.get("candidate_id") == candidate_id:
            target = c
            break
    if target is None:
        result = {"status": "not_found", "candidate_id": candidate_id}
        if output_json:
            print(json.dumps(result))
        return result

    result = dict(target)
    if not include_sensitive:
        result["description"] = _redact(result.get("description",""))
        result.pop("evidence_path", None)
        if "request" in result:
            result["request"] = _redact(str(result["request"]))
        if "response" in result:
            result["response"] = _redact(str(result["response"]))

    result["status"] = "ok"
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Full Candidate: {candidate_id} ===")
        print(json.dumps(result, indent=2))
    return result


def overview_readiness(candidates_path, output_json):
    candidates = _load_candidates(candidates_path)
    if not candidates:
        result = {"status": "empty", "verified": 0, "pending": 0, "verified_rate": 0.0}
        if output_json:
            print(json.dumps(result))
        return result

    verified = sum(1 for c in candidates if c.get("verification") == "confirmed")
    pending = sum(1 for c in candidates if c.get("verification") != "confirmed")
    total = len(candidates)
    verified_rate = round(verified / max(total, 1), 2)

    by_severity = defaultdict(lambda: {"verified": 0, "pending": 0})
    for c in candidates:
        sev = c.get("severity","medium")
        if c.get("verification") == "confirmed":
            by_severity[sev]["verified"] += 1
        else:
            by_severity[sev]["pending"] += 1

    high_fp = sum(1 for c in candidates if c.get("false_positive_risk") == "high")
    avg_score = 0
    score_count = 0
    for c in candidates:
        if "readiness_score" in c:
            avg_score += c["readiness_score"]
            score_count += 1

    if score_count > 0:
        overall = "READY" if (verified_rate >= 0.70 and avg_score / score_count >= 80) else \
                  ("NEEDS_WORK" if verified_rate >= 0.30 else "WEAK")
    else:
        overall = "UNASSESSED"

    result = {
        "status": "ok",
        "total": total,
        "verified": verified,
        "pending": pending,
        "verified_rate": verified_rate,
        "high_fp_risk_count": high_fp,
        "by_severity": {sev: counts for sev, counts in by_severity.items()},
        "average_readiness_score": round(avg_score / max(score_count, 1), 1) if score_count > 0 else 0,
        "overall": overall,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if output_json:
        print(json.dumps(result))
    else:
        print(f"=== Readiness Overview ===")
        print(f"  Total:       {total}")
        print(f"  Verified:    {verified}")
        print(f"  Pending:     {pending}")
        print(f"  Verified %:  {verified_rate}")
        print(f"  High FP:     {high_fp}")
        print(f"  By Severity: {json.dumps(dict(by_severity))}")
        print(f"  Avg Score:   {result['average_readiness_score']}")
        print(f"  Overall:     {overall}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Impact verifier")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True, choices=[
        "collect","classify","verify","fp-check","readiness",
        "list-candidates","candidate-summary","get-candidate","overview-readiness"
    ])
    parser.add_argument("--outdir")
    parser.add_argument("--candidates")
    parser.add_argument("--impact-class")
    parser.add_argument("--false-positive-db")
    parser.add_argument("--verified")
    parser.add_argument("--output")
    parser.add_argument("--rejected")
    parser.add_argument("--candidate-id", help="Candidate ID for summary / get-candidate")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output in JSON format")
    parser.add_argument("--include-sensitive", action="store_true", help="Include sensitive data in output")
    parser.add_argument("--register-artifacts", action="store_true", default=False,
                        help="Register each classified candidate as a finding artifact")
    args = parser.parse_args()
    ctx = load_context(args.context)
    run_id = ctx.get("run_id", "")
    if args.action == "collect":
        collect_candidates(args.outdir, args.output, args.register_artifacts, run_id)
    elif args.action == "classify":
        classify_impact(args.candidates, args.output, args.register_artifacts, run_id)
    elif args.action == "verify":
        verify_impact(args.candidates, args.impact_class, args.output, args.rejected, args.register_artifacts, run_id)
    elif args.action == "fp-check":
        fp_check(args.candidates, args.false_positive_db, args.output)
    elif args.action == "readiness":
        readiness_report(args.verified, args.output)
    elif args.action == "list-candidates":
        if not args.candidates:
            print(json.dumps({"error": "--candidates is required for list-candidates"}), file=sys.stderr)
            sys.exit(1)
        candidate_list(args.candidates, args.output_json)
    elif args.action == "candidate-summary":
        if not args.candidates:
            print(json.dumps({"error": "--candidates is required for candidate-summary"}), file=sys.stderr)
            sys.exit(1)
        if not args.candidate_id:
            print(json.dumps({"error": "--candidate-id is required for candidate-summary"}), file=sys.stderr)
            sys.exit(1)
        candidate_summary(args.candidates, args.candidate_id, args.include_sensitive, args.output_json)
    elif args.action == "get-candidate":
        if not args.candidates:
            print(json.dumps({"error": "--candidates is required for get-candidate"}), file=sys.stderr)
            sys.exit(1)
        if not args.candidate_id:
            print(json.dumps({"error": "--candidate-id is required for get-candidate"}), file=sys.stderr)
            sys.exit(1)
        candidate_full(args.candidates, args.candidate_id, args.include_sensitive, args.output_json)
    elif args.action == "overview-readiness":
        if not args.candidates:
            print(json.dumps({"error": "--candidates is required for overview-readiness"}), file=sys.stderr)
            sys.exit(1)
        overview_readiness(args.candidates, args.output_json)

if __name__ == "__main__":
    main()