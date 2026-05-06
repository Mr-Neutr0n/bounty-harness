#!/usr/bin/env python3
"""WASM Module Analyzer — parses WebAssembly binaries to surface capability exposure and suspicious imports."""

import argparse
import json
import os
import struct
import sys
import re
import tempfile
import hashlib
from datetime import datetime, timezone


SUSPICIOUS_IMPORTS = {
    "env.memory.grow": "Dynamic memory growth",
    "env.emscripten_sleep": "Emscripten async sleep — timing primitive",
    "env.emscripten_memcpy_big": "Large memory copy primitive",
    "env.__sys_open": "File system open (Emscripten FS layer)",
    "env.__sys_read": "File system read",
    "env.__sys_write": "File system write",
    "env.__sys_close": "File system close",
    "env.__sys_unlink": "File system unlink",
    "env.__sys_stat": "File stat",
    "env.__sys_fstat": "File fstat",
    "env.__sys_lseek": "File seek",
    "env.__sys_getpid": "Process ID access",
    "env.__sys_getcwd": "Current working directory",
    "env.__sys_chdir": "Change directory",
    "env.__sys_rename": "File rename",
    "env.__sys_mkdir": "Create directory",
    "env.__sys_rmdir": "Remove directory",
    "env.__sys_access": "File access check",
    "env.__sys_getenv": "Environment variable access",
    "env.__sys_execve": "Process execution",
    "env.__sys_poll": "Poll syscall",
    "env.__sys_socket": "Socket creation",
    "env.__sys_connect": "Socket connect",
    "env.__sys_sendto": "Network send",
    "env.__sys_recvfrom": "Network receive",
    "env.__sys_ioctl": "Device control",
    "env.__sys_fcntl": "File control",
    "env.emscripten_run_script": "Emscripten JS eval bridge — code execution risk",
    "env.emscripten_run_script_string": "Emscripten JS eval bridge (string)",
    "env.dynCall": "Dynamic function call bridge",
    "wasi_snapshot_preview1.fd_write": "WASI file write",
    "wasi_snapshot_preview1.fd_read": "WASI file read",
    "wasi_snapshot_preview1.fd_close": "WASI file close",
    "wasi_snapshot_preview1.fd_seek": "WASI file seek",
    "wasi_snapshot_preview1.path_open": "WASI path open",
    "wasi_snapshot_preview1.environ_get": "WASI environment access",
    "wasi_snapshot_preview1.environ_sizes_get": "WASI environment access",
    "wasi_snapshot_preview1.args_get": "WASI argument access",
    "wasi_snapshot_preview1.proc_exit": "WASI process exit",
    "wasi_snapshot_preview1.random_get": "WASI random data",
    "wasi_snapshot_preview1.clock_time_get": "WASI clock access",
    "wasi_snapshot_preview1.sched_yield": "WASI yield",
}

SUSPICIOUS_IMPORT_PATTERNS = [
    (re.compile(r"__sys_\w+"), "Emscripten syscall bridge (file/process/network)"),
    (re.compile(r"emscripten_run_script"), "Emscripten JS eval bridge"),
    (re.compile(r"wasi_snapshot_preview1\.\w+"), "WASI syscall capability exposure"),
    (re.compile(r"env\.invoke_\w+"), "Emscripten invoke bridge — dynamic dispatch"),
    (re.compile(r"env\._emscripten_\w+"), "Emscripten internal bridge"),
]


def build_parser():
    p = argparse.ArgumentParser(description="Analyze WASM modules for capability exposure")
    p.add_argument("--urls-file", default=None, help="File containing URLs (one per line) linking to .wasm files")
    p.add_argument("--js-dir", default=None, help="Directory of JS files to scan for .wasm URLs")
    p.add_argument("--wasm-file", default=None, action="append", dest="wasm_files", help="Direct path to .wasm file(s)")
    p.add_argument("--context", default="default", help="Assessment context label")
    p.add_argument("--output", default=None, help="Output path for findings.jsonl")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--timeout", type=int, default=30, help="Download timeout in seconds")
    return p


def leb128_decode(data, offset):
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        shift += 7
        offset += 1
        if not (byte & 0x80):
            break
    return result, offset


def read_name(data, offset):
    length, offset = leb128_decode(data, offset)
    name = data[offset:offset + length].decode("utf-8", errors="replace")
    return name, offset + length


def parse_wasm_sections(wasm_bytes):
    if len(wasm_bytes) < 8:
        return {"error": "File too small to be valid WASM", "sections": []}
    magic = struct.unpack("<I", wasm_bytes[0:4])[0]
    version = struct.unpack("<I", wasm_bytes[4:8])[0]
    if magic != 0x6D736100:
        return {"error": f"Bad magic number: 0x{magic:08x}, expected 0x6D736100", "sections": [], "magic": hex(magic), "version": version}

    sections = []
    offset = 8
    section_id_map = {
        0: "custom", 1: "type", 2: "import", 3: "function",
        4: "table", 5: "memory", 6: "global", 7: "export",
        8: "start", 9: "element", 10: "code", 11: "data",
        12: "data_count"
    }

    imports_list = []
    exports_list = []
    memory_limits = []

    while offset < len(wasm_bytes):
        if offset + 1 > len(wasm_bytes):
            break
        section_id = wasm_bytes[offset]
        offset += 1
        section_size, offset = leb128_decode(wasm_bytes, offset)
        section_data = wasm_bytes[offset:offset + section_size]

        section_name = section_id_map.get(section_id, f"section_{section_id}")
        section_info = {
            "id": section_id,
            "name": section_name,
            "size": section_size,
        }

        if section_id == 2:
            s_off = 0
            import_count, s_off = leb128_decode(section_data, s_off)
            for _ in range(import_count):
                module_name, s_off = read_name(section_data, s_off)
                field_name, s_off = read_name(section_data, s_off)
                if s_off < len(section_data):
                    kind = section_data[s_off]
                else:
                    kind = -1
                s_off += 1
                full_name = f"{module_name}.{field_name}"
                import_entry = {"module": module_name, "field": field_name, "kind": kind, "full_name": full_name}
                is_suspicious = False
                reason = ""
                for pattern, desc in SUSPICIOUS_IMPORT_PATTERNS:
                    if pattern.search(full_name):
                        is_suspicious = True
                        reason = desc
                        break
                if not is_suspicious and full_name in SUSPICIOUS_IMPORTS:
                    is_suspicious = True
                    reason = SUSPICIOUS_IMPORTS[full_name]
                import_entry["suspicious"] = is_suspicious
                import_entry["suspicious_reason"] = reason
                imports_list.append(import_entry)
            section_info["import_count"] = import_count

        if section_id == 7:
            s_off = 0
            export_count, s_off = leb128_decode(section_data, s_off)
            for _ in range(export_count):
                name, s_off = read_name(section_data, s_off)
                kind = section_data[s_off] if s_off < len(section_data) else -1
                s_off += 1
                export_idx, s_off = leb128_decode(section_data, s_off)
                exports_list.append({"name": name, "kind": kind, "index": export_idx})
            section_info["export_count"] = export_count

        if section_id == 5:
            s_off = 0
            memory_count, s_off = leb128_decode(section_data, s_off)
            for _ in range(memory_count):
                flags = section_data[s_off] if s_off < len(section_data) else 0
                s_off += 1
                if flags & 0x01:
                    initial, s_off = leb128_decode(section_data, s_off)
                    maximum, s_off = leb128_decode(section_data, s_off)
                    memory_limits.append({"initial_pages": initial, "maximum_pages": maximum, "initial_bytes": initial * 65536, "maximum_bytes": maximum * 65536})
                else:
                    initial, s_off = leb128_decode(section_data, s_off)
                    memory_limits.append({"initial_pages": initial, "maximum_pages": None, "initial_bytes": initial * 65536})
            section_info["memory_count"] = memory_count

        if section_id == 4:
            s_off = 0
            table_count, s_off = leb128_decode(section_data, s_off)
            section_info["table_count"] = table_count

        if section_id == 12:
            s_off = 0
            data_count, s_off = leb128_decode(section_data, s_off)
            section_info["data_count"] = data_count

        if section_id == 0:
            try:
                s_off = 0
                name_str, s_off = read_name(section_data, s_off)
                section_info["custom_name"] = name_str
            except Exception:
                section_info["custom_name"] = "<parse error>"

        sections.append(section_info)
        offset += section_size

    return {
        "magic": hex(magic),
        "version": version,
        "file_size": len(wasm_bytes),
        "sections": sections,
        "imports": imports_list,
        "exports": exports_list,
        "memory_limits": memory_limits,
        "import_count": len(imports_list),
        "export_count": len(exports_list),
        "suspicious_import_count": sum(1 for i in imports_list if i.get("suspicious")),
    }


def find_wasm_urls_in_js(js_dir):
    wasm_urls = []
    pattern = re.compile(r"""['"`]([^'"`\s]+\.wasm)['"`]""", re.IGNORECASE)
    for root, _dirs, files in os.walk(js_dir):
        for fname in files:
            if fname.lower().endswith((".js", ".mjs", ".ts", ".tsx", ".html", ".htm")):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read()
                    for m in pattern.finditer(content):
                        wasm_urls.append(m.group(1))
                except Exception:
                    continue
    return list(set(wasm_urls))


def download_wasm(url, timeout_sec):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "wasm_analyzer/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return resp.read()
    except Exception as exc:
        raise RuntimeError(f"Download failed: {exc}")


def compute_risk(parsed):
    score = 0
    reasons = []
    susp_count = parsed.get("suspicious_import_count", 0)
    if susp_count > 0:
        reasons.append(f"{susp_count} suspicious import(s)")
        score += susp_count * 5
    import_count = parsed.get("import_count", 0)
    if import_count > 10:
        reasons.append(f"High import count ({import_count}) — broad host environment coupling")
        score += 2
    mem_limits = parsed.get("memory_limits", [])
    for ml in mem_limits:
        if ml.get("maximum_bytes") and ml["maximum_bytes"] > 256 * 1024 * 1024:
            reasons.append(f"Large max memory ({ml['maximum_bytes'] // 1048576} MB)")
            score += 1
        if ml.get("maximum_pages") is None:
            reasons.append("Memory has no maximum — unbounded growth possible")
            score += 2
    if score <= 0:
        return "none", "No concerning imports or memory configurations detected"
    elif score <= 5:
        return "low", "; ".join(reasons)
    elif score <= 15:
        return "medium", "; ".join(reasons)
    else:
        return "high", "; ".join(reasons)


def main():
    parser = build_parser()
    args = parser.parse_args()

    targets = []
    if args.urls_file:
        if os.path.isfile(args.urls_file):
            with open(args.urls_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        else:
            print(f"Error: urls-file not found: {args.urls_file}", file=sys.stderr)
            sys.exit(1)

    if args.js_dir:
        if os.path.isdir(args.js_dir):
            urls = find_wasm_urls_in_js(args.js_dir)
            targets.extend(urls)
        else:
            print(f"Error: js-dir not found: {args.js_dir}", file=sys.stderr)

    if args.wasm_files:
        targets.extend(args.wasm_files)

    if not targets:
        print("Error: No WASM sources provided (--urls-file, --js-dir, or --wasm-file)", file=sys.stderr)
        sys.exit(1)

    findings = []

    for target in targets:
        finding = {
            "tool": "wasm_analyzer",
            "context": args.context,
            "target": target,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "risk_level": "none",
            "risk_notes": "",
            "imports": [],
            "exports": [],
            "memory_limits": [],
            "suspicious_imports": [],
            "sections": [],
            "errors": [],
            "sha256": None,
        }

        if args.dry_run:
            finding["dry_run"] = True
            finding["risk_notes"] = "DRY RUN — would download and analyze WASM module"
            findings.append(finding)
            continue

        try:
            if os.path.isfile(target):
                with open(target, "rb") as f:
                    wasm_bytes = f.read()
            elif target.startswith("http://") or target.startswith("https://"):
                wasm_bytes = download_wasm(target, args.timeout)
            else:
                finding["errors"].append(f"Cannot resolve source: {target}")
                findings.append(finding)
                continue

            finding["sha256"] = hashlib.sha256(wasm_bytes).hexdigest()
            parsed = parse_wasm_sections(wasm_bytes)

            if "error" in parsed and "sections" not in parsed:
                finding["errors"].append(parsed["error"])
                finding["risk_level"] = "unknown"
                finding["risk_notes"] = "Could not parse WASM binary"
                findings.append(finding)
                continue

            finding["sections"] = parsed.get("sections", [])
            finding["imports"] = parsed.get("imports", [])
            finding["exports"] = parsed.get("exports", [])
            finding["memory_limits"] = parsed.get("memory_limits", [])
            finding["suspicious_imports"] = [i for i in parsed.get("imports", []) if i.get("suspicious")]
            finding["risk_level"], finding["risk_notes"] = compute_risk(parsed)
            finding["errors"] = parsed.get("errors", [])

        except Exception as exc:
            finding["errors"].append(str(exc))
            finding["risk_level"] = "unknown"
            finding["risk_notes"] = f"Analysis error: {exc}"

        findings.append(finding)

    out_fh = sys.stdout
    close_out = False
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        out_fh = open(args.output, "a")
        close_out = True

    try:
        for f in findings:
            out_fh.write(json.dumps(f, default=str) + "\n")
        out_fh.flush()
    finally:
        if close_out:
            out_fh.close()

    high_count = sum(1 for f in findings if f["risk_level"] == "high")
    if high_count:
        print(f"WARNING: {high_count} HIGH-risk WASM module(s) found", file=sys.stderr)


if __name__ == "__main__":
    main()