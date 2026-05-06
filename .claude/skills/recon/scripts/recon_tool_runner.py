#!/usr/bin/env python3
"""Thin wrappers for optional recon tools with normalized JSONL output."""

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_context(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(set(lines))) + ("\n" if lines else ""), encoding="utf-8")


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


def host_from_value(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/", 1)[0]
    return host.strip().lower()


def run_command(cmd: list[str], stdin: str | None = None, timeout: int = 600) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def base_record(ctx: dict, tool: str, finding_type: str, raw: dict) -> dict:
    return {
        "tool": tool,
        "target": ctx.get("target") or ctx.get("target_host") or "",
        "finding_type": finding_type,
        "severity": "info",
        "confidence": 0.5,
        "evidence": raw,
        "raw": raw,
        "timestamp": now_iso(),
        "run_id": ctx.get("run_id", ""),
        "scope_status": "unknown",
    }


def dns_resolution(args: argparse.Namespace, ctx: dict) -> None:
    outdir = Path(args.output_dir)
    subs_file = Path(args.input)
    resolved_path = outdir / "resolved.txt"
    findings_path = outdir / "findings.jsonl"
    raw_path = outdir / "dnsx_raw.txt"
    outdir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    resolved: list[str] = []
    if shutil.which("dnsx") and subs_file.exists():
        rc, stdout, stderr = run_command(["dnsx", "-l", str(subs_file), "-silent"])
        raw_path.write_text(stdout + stderr, encoding="utf-8")
        if rc == 0:
            resolved = [line.strip() for line in stdout.splitlines() if line.strip()]
    for host in resolved:
        rec = base_record(ctx, "dnsx", "dns_resolved", {"host": host})
        rec.update({"host": host, "url": ""})
        records.append(rec)
    write_lines(resolved_path, resolved)
    write_jsonl(findings_path, records)


def port_scan(args: argparse.Namespace, ctx: dict) -> None:
    outdir = Path(args.output_dir)
    live_file = Path(args.input)
    hosts = sorted({host_from_value(line) for line in read_lines(live_file) if host_from_value(line)})
    hosts_file = outdir / "hosts.txt"
    ports_path = outdir / "open_ports.txt"
    findings_path = outdir / "findings.jsonl"
    raw_path = outdir / "naabu_raw.txt"
    write_lines(hosts_file, hosts)
    found: list[str] = []
    records: list[dict] = []
    if shutil.which("naabu") and hosts:
        rc, stdout, stderr = run_command(["naabu", "-list", str(hosts_file), "-silent"])
        raw_path.write_text(stdout + stderr, encoding="utf-8")
        if rc == 0:
            found = [line.strip() for line in stdout.splitlines() if line.strip()]
    for item in found:
        host, _, port = item.partition(":")
        rec = base_record(ctx, "naabu", "open_port", {"endpoint": item, "host": host, "port": port})
        rec.update({"host": host, "url": ""})
        records.append(rec)
    write_lines(ports_path, found)
    write_jsonl(findings_path, records)


def url_discovery(args: argparse.Namespace, ctx: dict) -> None:
    outdir = Path(args.output_dir)
    live_file = Path(args.input)
    domains = sorted({host_from_value(line) for line in read_lines(live_file) if host_from_value(line)})
    outdir.mkdir(parents=True, exist_ok=True)
    stdin = "\n".join(domains) + ("\n" if domains else "")
    all_urls: set[str] = set()
    records: list[dict] = []
    for tool, output_name in (("gau", "gau_urls.txt"), ("waybackurls", "wayback_urls.txt")):
        urls: list[str] = []
        if shutil.which(tool) and domains:
            rc, stdout, stderr = run_command([tool], stdin=stdin, timeout=900)
            (outdir / f"{tool}_raw.txt").write_text(stdout + stderr, encoding="utf-8")
            if rc == 0:
                urls = [line.strip() for line in stdout.splitlines() if line.strip().startswith(("http://", "https://"))]
        write_lines(outdir / output_name, urls)
        all_urls.update(urls)
        for url in urls:
            rec = base_record(ctx, tool, "url_discovered", {"url": url})
            rec.update({"url": url, "host": host_from_value(url)})
            records.append(rec)
    write_lines(outdir / "all_urls.txt", sorted(all_urls))
    write_jsonl(outdir / "findings.jsonl", records)


def tls_profile(args: argparse.Namespace, ctx: dict) -> None:
    outdir = Path(args.output_dir)
    live_file = Path(args.input)
    hosts = sorted({host_from_value(line) for line in read_lines(live_file) if host_from_value(line)})
    hosts_file = outdir / "hosts.txt"
    raw_path = outdir / "tlsx_raw.jsonl"
    findings_path = outdir / "findings.jsonl"
    write_lines(hosts_file, hosts)
    records: list[dict] = []
    raw_lines: list[str] = []
    if shutil.which("tlsx") and hosts:
        rc, stdout, stderr = run_command(["tlsx", "-l", str(hosts_file), "-silent", "-json"])
        raw_path.write_text(stdout + stderr, encoding="utf-8")
        if rc == 0:
            raw_lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    for line in raw_lines:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            raw = {"line": line}
        host = str(raw.get("host") or raw.get("input") or raw.get("line") or "")
        rec = base_record(ctx, "tlsx", "tls_profile", raw)
        rec.update({"host": host_from_value(host), "url": ""})
        records.append(rec)
    write_jsonl(findings_path, records)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run optional recon tools with normalized output")
    parser.add_argument("--mode", required=True, choices=["dns-resolution", "port-scan", "url-discovery", "tls-profile"])
    parser.add_argument("--context", default=".bb/context.json")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    ctx = load_context(args.context)
    if args.mode == "dns-resolution":
        dns_resolution(args, ctx)
    elif args.mode == "port-scan":
        port_scan(args, ctx)
    elif args.mode == "url-discovery":
        url_discovery(args, ctx)
    elif args.mode == "tls-profile":
        tls_profile(args, ctx)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
