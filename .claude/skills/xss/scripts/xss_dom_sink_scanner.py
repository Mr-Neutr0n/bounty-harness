#!/usr/bin/env python3
import argparse
import json
import sys
import os
import re
from pathlib import Path

DOM_SOURCES = [
    ("location", r"\blocation\b[^=]", "window.location / document.location access"),
    ("location.hash", r"\blocation\.hash\b", "location.hash"),
    ("location.search", r"\blocation\.search\b", "location.search"),
    ("location.pathname", r"\blocation\.pathname\b", "location.pathname"),
    ("location.href", r"\blocation\.href\b", "location.href"),
    ("document.URL", r"\bdocument\.URL\b", "document.URL"),
    ("document.documentURI", r"\bdocument\.documentURI\b", "document.documentURI"),
    ("document.baseURI", r"\bdocument\.baseURI\b", "document.baseURI"),
    ("document.referrer", r"\bdocument\.referrer\b", "document.referrer"),
    ("window.name", r"\bwindow\.name\b", "window.name"),
    ("document.cookie", r"\bdocument\.cookie\b", "document.cookie"),
    ("postMessage", r"\.addEventListener\s*\(\s*['\"]message['\"]", "postMessage / onmessage event"),
    ("history.pushState", r"\.pushState\(", "history.pushState"),
    ("history.replaceState", r"\.replaceState\(", "history.replaceState"),
    ("XMLHttpRequest.responseText", r"\.responseText\b", "XHR responseText"),
    ("fetch response", r"\.then\s*\(\s*[^)]*\bresp\w*\s*\)", "fetch().then() response"),
    ("WebSocket message", r"\.onmessage\s*=", "WebSocket onmessage"),
    ("navigator.userAgent", r"\bnavigator\.userAgent\b", "navigator.userAgent"),
    ("localStorage", r"\blocalStorage\.getItem\b", "localStorage.getItem"),
    ("sessionStorage", r"\bsessionStorage\.getItem\b", "sessionStorage.getItem"),
    ("eval data", r"eval\s*\([^)]*\+", "eval() with concatenated input"),
    ("URL params", r"URLSearchParams|URL\(.*\)\.searchParams", "URLSearchParams"),
    ("data attribute", r"\.dataset\.", "element.dataset"),
    ("input value", r"\.value\b", "element.value"),
    ("JSON.parse", r"JSON\.parse\s*\([^)]*\)", "JSON.parse of untrusted input"),
]

DOM_SINKS = [
    ("innerHTML", r"\.innerHTML\s*=", "element.innerHTML assignment"),
    ("outerHTML", r"\.outerHTML\s*=", "element.outerHTML assignment"),
    ("document.write", r"document\.write\s*\(", "document.write()"),
    ("document.writeln", r"document\.writeln\s*\(", "document.writeln()"),
    ("eval", r"\beval\s*\(", "eval()"),
    ("Function constructor", r"\bFunction\s*\(", "new Function()"),
    ("setTimeout(string)", r"setTimeout\s*\([^,)]*['\"]", "setTimeout with string arg"),
    ("setInterval(string)", r"setInterval\s*\([^,)]*['\"]", "setInterval with string arg"),
    ("setImmediate(string)", r"setImmediate\s*\([^,)]*['\"]", "setImmediate with string arg"),
    ("execScript", r"execScript\s*\(", "window.execScript() (IE)"),
    ("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\(", "element.insertAdjacentHTML()"),
    ("Range.createContextualFragment", r"\.createContextualFragment\s*\(", "Range.createContextualFragment()"),
    ("DOMParser.parseFromString", r"\.parseFromString\s*\(", "DOMParser.parseFromString()"),
    ("window.open", r"window\.open\s*\([^)]*['\"]javascript", "window.open(javascript: URI)"),
    ("location assignment", r"\blocation\s*=\s*[a-zA-Z]", "location = user_input"),
    ("location.href assignment", r"location\.href\s*=\s*[^=]", "location.href = user_input"),
    ("location.replace", r"location\.replace\s*\(", "location.replace()"),
    ("location.assign", r"location\.assign\s*\(", "location.assign()"),
    ("jQuery html()", r"\.html\s*\(\s*[^)]*[a-z]", "jQuery.html() with variable input"),
    ("jQuery append()", r"\.append\s*\([^)]*<", "jQuery.append() with HTML string"),
    ("jQuery prepend()", r"\.prepend\s*\([^)]*<", "jQuery.prepend() with HTML string"),
    ("jQuery after()", r"\.after\s*\([^)]*<", "jQuery.after() with HTML string"),
    ("jQuery before()", r"\.before\s*\([^)]*<", "jQuery.before() with HTML string"),
    ("jQuery wrap()", r"\.wrap\s*\([^)]*<", "jQuery.wrap() with HTML string"),
    ("jQuery replaceWith()", r"\.replaceWith\s*\([^)]*<", "jQuery.replaceWith() with HTML string"),
    ("React dangerouslySetInnerHTML", r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
    ("Angular byPassSecurityTrustHtml", r"bypassSecurityTrustHtml", "Angular byPassSecurityTrustHtml"),
    ("document.createElement(tag)", r"createElement\s*\([^)]*[a-z]", "document.createElement with variable tag name"),
    ("setAttribute", r"\.setAttribute\s*\([^)]*on\w+", "setAttribute with event handler"),
    ("srcdoc attribute", r"srcdoc\s*=", "iframe srcdoc attribute"),
    ("EventSource URL", r"EventSource\s*\([^)]*\+", "EventSource with concatenated URL"),
    ("import() expression", r"import\s*\([^)]*[a-z]", "dynamic import()"),
]

SANITIZATION_PATTERNS = [
    ("DOMPurify.sanitize", r"DOMPurify\.sanitize\b", "DOMPurify"),
    ("sanitize-html", r"sanitize-?html\b", "sanitize-html library"),
    ("escapeHtml", r"\bescapeHtml\b", "custom escapeHtml"),
    ("encodeURIComponent", r"encodeURIComponent\b", "encodeURIComponent"),
    ("textContent assign", r"\.textContent\s*=", "textContent (safe assignment)"),
    ("innerText assign", r"\.innerText\s*=", "innerText (safe assignment)"),
    ("createTextNode", r"createTextNode\b", "createTextNode (safe)"),
    ("CSP nonce", r"nonce\s*=", "CSP nonce usage"),
]


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except IOError as e:
        return [{"file": str(filepath), "error": str(e), "confidence": 0.0}]
    lines = content.split("\n")
    sources_found = []
    sinks_found = []
    sanitizers_found = []
    for i, line in enumerate(lines, 1):
        for source_name, source_re, source_desc in DOM_SOURCES:
            if re.search(source_re, line):
                snippet = line.strip()[:200]
                sources_found.append({
                    "line": i,
                    "source_type": source_name,
                    "source_description": source_desc,
                    "snippet": snippet,
                })
        for sink_name, sink_re, sink_desc in DOM_SINKS:
            if re.search(sink_re, line):
                snippet = line.strip()[:200]
                sinks_found.append({
                    "line": i,
                    "sink_type": sink_name,
                    "sink_description": sink_desc,
                    "snippet": snippet,
                })
        for san_name, san_re, san_desc in SANITIZATION_PATTERNS:
            if re.search(san_re, line):
                snippet = line.strip()[:200]
                sanitizers_found.append({
                    "line": i,
                    "sanitizer_type": san_name,
                    "sanitizer_description": san_desc,
                    "snippet": snippet,
                })
    if sources_found and sinks_found:
        for src in sources_found:
            for sink in sinks_found:
                confidence = 0.0
                dist = abs(sink["line"] - src["line"])
                if dist <= 5:
                    confidence = 0.7
                elif dist <= 15:
                    confidence = 0.5
                elif dist <= 30:
                    confidence = 0.3
                elif dist <= 60:
                    confidence = 0.2
                else:
                    confidence = 0.1
                if sanitizers_found:
                    nearest_san = min(sanitizers_found, key=lambda s: abs(s["line"] - sink["line"]))
                    if abs(nearest_san["line"] - sink["line"]) <= 5:
                        confidence = max(0.0, confidence - 0.4)
                    elif abs(nearest_san["line"] - sink["line"]) <= 15:
                        confidence = max(0.0, confidence - 0.2)
                if confidence >= 0.1:
                    findings.append({
                        "file": str(filepath),
                        "source_line": src["line"],
                        "sink_line": sink["line"],
                        "distance": dist,
                        "source_type": src["source_type"],
                        "source_description": src["source_description"],
                        "source_snippet": src["snippet"],
                        "sink_type": sink["sink_type"],
                        "sink_description": sink["sink_description"],
                        "sink_snippet": sink["snippet"],
                        "sanitizers_nearby": [s["sanitizer_type"] for s in sanitizers_found if abs(s["line"] - sink["line"]) <= 15],
                        "confidence": round(confidence, 2),
                    })
    if not findings:
        if sources_found or sinks_found:
            findings.append({
                "file": str(filepath),
                "warning": "sources_or_sinks_without_pair",
                "sources_count": len(sources_found),
                "sinks_count": len(sinks_found),
                "sanitizers_count": len(sanitizers_found),
                "confidence": 0.0,
            })
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="DOM XSS Sink Scanner — scan JS files for DOM-based XSS source-to-sink paths",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --js-dir /path/to/js/files
  %(prog)s --js-dir ./output/target.com/js/ --context .bb/context.json
  %(prog)s --js-dir ./js --dry-run
  %(prog)s --js-dir ./js --extensions .js,.mjs,.ts
        """,
    )
    parser.add_argument("--context", default=None, help="Path to context.json")
    parser.add_argument("--js-dir", required=True, help="Directory containing JavaScript files to scan")
    parser.add_argument("--extensions", default=".js,.mjs,.ts,.jsx,.tsx", help="Comma-separated file extensions to scan (default: .js,.mjs,.ts,.jsx,.tsx)")
    parser.add_argument("--output", default=None, help="Output findings.jsonl path")
    parser.add_argument("--dry-run", action="store_true", help="List files that would be scanned without executing")
    args = parser.parse_args()

    ctx = {}
    if args.context and os.path.exists(args.context):
        try:
            with open(args.context, "r") as f:
                ctx = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[warn] Failed to load context: {e}", file=sys.stderr)

    js_dir = args.js_dir
    if not os.path.isdir(js_dir):
        print(f"[error] --js-dir '{js_dir}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    extensions = [ext.strip() for ext in args.extensions.split(",") if ext.strip()]
    if not extensions:
        extensions = [".js", ".mjs", ".ts", ".jsx", ".tsx"]

    outdir = ctx.get("outdir", os.getcwd())
    output_path = args.output
    if not output_path:
        output_path = os.path.join(outdir, "dom_xss_findings.jsonl")

    js_files = []
    for root, dirs, files in os.walk(js_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "dist", "build", "bower_components")]
        for f in files:
            if any(f.endswith(ext) for ext in extensions):
                js_files.append(os.path.join(root, f))

    if not js_files:
        print(f"[error] No JS files found in '{js_dir}' with extensions {extensions}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print(f"[dry-run] Would scan {len(js_files)} JS files:", file=sys.stderr)
        for f in js_files[:20]:
            print(f"  {f}", file=sys.stderr)
        if len(js_files) > 20:
            print(f"  ... and {len(js_files) - 20} more", file=sys.stderr)
        return

    all_findings = []
    with open(output_path, "w") as outfile:
        for idx, fpath in enumerate(js_files):
            findings = scan_file(fpath)
            for finding in findings:
                outfile.write(json.dumps(finding) + "\n")
                if finding.get("confidence", 0) >= 0.3:
                    all_findings.append(finding)
            if (idx + 1) % 100 == 0:
                print(f"[progress] Scanned {idx + 1}/{len(js_files)} files", file=sys.stderr)

    high_conf = sum(1 for f in all_findings if f.get("confidence", 0) >= 0.7)
    med_conf = sum(1 for f in all_findings if 0.3 <= f.get("confidence", 0) < 0.7)

    summary = {
        "total_files_scanned": len(js_files),
        "total_findings": len(all_findings),
        "high_confidence": high_conf,
        "medium_confidence": med_conf,
        "output_path": output_path,
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[done] Findings written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()