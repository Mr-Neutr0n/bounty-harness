#!/usr/bin/env python3
"""Agent safety checker — sanitize untrusted target content before LLM ingestion."""
import argparse, json, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

INJECTION_PATTERNS = [
    (re.compile(r'ignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)', re.I), "instruction_override"),
    (re.compile(r'you\s+are\s+now\s+(in\s+)?(developer|admin|unrestricted|debug)\s*mode', re.I), "role_switch"),
    (re.compile(r'system\s*(prompt|instructions?|message)', re.I), "system_manipulation"),
    (re.compile(r'reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|config)', re.I), "prompt_extraction"),
    (re.compile(r'<img[^>]+src\s*=\s*[\"\']https?://[^\"\']+[?&](?:data|token|secret|key)=', re.I), "data_exfiltration"),
    (re.compile(r'<script[^>]*>', re.I), "xss_injection"),
    (re.compile(r'base64[=:]', re.I), "encoding_obfuscation"),
    (re.compile(r'[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff]'), "invisible_chars"),
    (re.compile(r'(?:forward|send|redirect|transfer|exfiltrate).*(?:email|data|file|document|password)', re.I), "data_exfil"),
    (re.compile(r'\[IMPORTANT\]|\[SYSTEM\]|\[OVERRIDE\]|\[INSTRUCTION\]', re.I), "marker_injection"),
]

def load_context(ctx_path=".bb/context.json"):
    with open(ctx_path) as f:
        return json.load(f)

def sanitize_content(input_path, output_path):
    if not Path(input_path).exists():
        print(json.dumps({"status": "input_not_found"}))
        return
    content = Path(input_path).read_text()
    sanitized = content
    modifications = []
    for pattern, label in INJECTION_PATTERNS:
        matches = pattern.findall(sanitized)
        if matches:
            sanitized = pattern.sub(f"[FILTERED:{label}]", sanitized)
            modifications.append({"pattern": label, "matches": min(len(matches), 5)})
    entry = {"file": str(input_path), "original_length": len(content), "sanitized_length": len(sanitized),
             "modifications": modifications, "sanitized_at": datetime.now(timezone.utc).isoformat()}
    Path(output_path).write_text(json.dumps(entry) + "\n")
    print(json.dumps({"status": "sanitized", "modifications": len(modifications)}))

def scan_content(input_path, output_path):
    if not Path(input_path).exists():
        print(json.dumps({"status": "input_not_found"}))
        return
    content = Path(input_path).read_text()
    findings = []
    for pattern, label in INJECTION_PATTERNS:
        for match in pattern.finditer(content):
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            findings.append({"pattern": label, "match": match.group()[:100],
                           "context": content[start:end], "position": match.start()})
    entry = {"file": str(input_path), "scan_at": datetime.now(timezone.utc).isoformat(),
             "findings": findings, "risk_level": "dangerous" if len(findings) > 5 else ("suspicious" if findings else "safe")}
    Path(output_path).write_text(json.dumps(entry) + "\n")
    print(json.dumps({"status": "scanned", "findings": len(findings), "risk_level": entry["risk_level"]}))

def classify_risk(input_path, output_path):
    if not Path(input_path).exists():
        print(json.dumps({"status": "input_not_found"}))
        return
    scans = [json.loads(l) for l in Path(input_path).read_text().splitlines() if l.strip()]
    report = {"files_scanned": len(scans), "risk_distribution": {"safe":0,"suspicious":0,"dangerous":0,"critical":0},
              "total_patterns": 0, "recommendation": "safe_to_ingest", "generated_at": datetime.now(timezone.utc).isoformat()}
    for s in scans:
        level = s.get("risk_level","safe")
        report["risk_distribution"][level] = report["risk_distribution"].get(level, 0) + 1
        report["total_patterns"] += len(s.get("findings",[]))
    if report["risk_distribution"].get("dangerous",0) > 0:
        report["recommendation"] = "requires_sanitization"
    if report["total_patterns"] > 20:
        report["recommendation"] = "do_not_ingest"
    Path(output_path).write_text(json.dumps(report, indent=2))
    print(json.dumps({"status": "classified", "recommendation": report["recommendation"]}))

def guardrail_check(tool_name, params, output_path):
    dangerous_tools = {"rm", "delete", "drop", "exec", "eval", "write", "ssh", "sudo", "bash", "shell",
                       "execute_command", "database_write", "file_delete", "send_email"}
    decision = {"tool": tool_name, "params": params, "allowed": True, "requires_approval": False,
                "checked_at": datetime.now(timezone.utc).isoformat()}
    if any(dt in tool_name.lower() for dt in dangerous_tools):
        decision["requires_approval"] = True
    if "DROP TABLE" in str(params) or "rm -rf" in str(params):
        decision["allowed"] = False
        decision["reason"] = "destructive payload detected"
    Path(output_path).write_text(json.dumps(decision, indent=2))
    print(json.dumps({"status": "guardrail_checked", "allowed": decision["allowed"]}))

def check_browser_output(browser_dir, output_path):
    src = Path(browser_dir)
    findings = []
    interactables_file = src / "interactables.json"
    if interactables_file.exists():
        try:
            inter = json.loads(interactables_file.read_text())
            all_text_entries = []
            for form in inter.get("forms", []):
                for inp in form.get("inputs", []):
                    for field in ("name", "placeholder", "id"):
                        val = inp.get(field, "")
                        if val:
                            all_text_entries.append({"context": f"form_input:{field}", "value": val})
                action = form.get("action", "")
                if action:
                    all_text_entries.append({"context": "form_action", "value": action})
            for link in inter.get("links", []):
                href = link.get("href", "")
                text = link.get("text", "")
                if href:
                    all_text_entries.append({"context": "link_href", "value": href})
                if text:
                    all_text_entries.append({"context": "link_text", "value": text})
            for btn in inter.get("buttons", []):
                text = btn.get("text", "")
                if text:
                    all_text_entries.append({"context": "button_text", "value": text})
            for inp in inter.get("inputs", []):
                for field in ("name", "placeholder", "id"):
                    val = inp.get(field, "")
                    if val:
                        all_text_entries.append({"context": f"freestanding_input:{field}", "value": val})
            for entry in all_text_entries:
                text = f"{entry['context']}: {entry['value']}"
                for pattern, label in INJECTION_PATTERNS:
                    if pattern.search(text):
                        findings.append({
                            "pattern": label,
                            "match": text[:200],
                            "source": str(interactables_file),
                            "context": entry["context"],
                        })
        except Exception as e:
            findings.append({"pattern": "parse_error", "match": str(e)[:200], "source": str(interactables_file)})
    page_state_file = src / "page_state.json"
    if page_state_file.exists():
        try:
            ps = json.loads(page_state_file.read_text())
            title = ps.get("title", "")
            url = ps.get("url", "") or ps.get("final_url", "")
            for pattern, label in INJECTION_PATTERNS:
                if title and pattern.search(title):
                    findings.append({"pattern": label, "match": title[:200], "source": str(page_state_file), "context": "page_title"})
                if url and pattern.search(url):
                    findings.append({"pattern": label, "match": url[:200], "source": str(page_state_file), "context": "page_url"})
        except Exception as e:
            findings.append({"pattern": "parse_error", "match": str(e)[:200], "source": str(page_state_file)})
    for json_file in sorted(src.glob("*.json")):
        if json_file.name in ("interactables.json", "page_state.json"):
            continue
        try:
            content = json_file.read_text()[:50000]
            for pattern, label in INJECTION_PATTERNS:
                for m in pattern.finditer(content):
                    start = max(0, m.start() - 20)
                    end = min(len(content), m.end() + 20)
                    findings.append({
                        "pattern": label,
                        "match": m.group()[:100],
                        "context": content[start:end],
                        "source": str(json_file),
                    })
        except Exception:
            pass
    raw_tokens_found = []
    for f in src.glob("*"):
        try:
            content = f.read_text()[:50000]
            if re.search(r'Bearer\s+[A-Za-z0-9\-_\.]{20,}', content):
                raw_tokens_found.append({"file": str(f), "issue": "raw_bearer_token_detected"})
            if re.search(r'(?:api[_-]?key|apikey|secret|password)["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', content, re.I):
                raw_tokens_found.append({"file": str(f), "issue": "raw_credential_detected"})
        except Exception:
            pass
    risk_level = "safe"
    if len(findings) > 5 or raw_tokens_found:
        risk_level = "dangerous"
    elif findings:
        risk_level = "suspicious"
    report = {
        "browser_dir": str(browser_dir),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "injection_findings": findings,
        "token_violations": raw_tokens_found,
        "total_findings": len(findings),
        "risk_level": risk_level,
        "recommendation": "do_not_ingest" if risk_level == "dangerous" else ("requires_sanitization" if risk_level == "suspicious" else "safe_to_ingest"),
    }
    Path(output_path).write_text(json.dumps(report, indent=2))
    print(json.dumps({"status": "browser_output_checked", "findings": len(findings), "token_violations": len(raw_tokens_found), "risk_level": risk_level}))

def main():
    parser = argparse.ArgumentParser(description="Agent safety checker")
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--action", required=True)
    parser.add_argument("--input")
    parser.add_argument("--check-browser-output")
    parser.add_argument("--tool")
    parser.add_argument("--params", default="{}")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.action == "check-browser-output":
        check_browser_output(args.check_browser_output or args.input, args.output)
    elif args.action == "sanitize":
        sanitize_content(args.input, args.output)
    elif args.action == "scan":
        scan_content(args.input, args.output)
    elif args.action == "classify":
        classify_risk(args.input, args.output)
    elif args.action == "guardrail":
        guardrail_check(args.tool, args.params, args.output)

if __name__ == "__main__":
    main()