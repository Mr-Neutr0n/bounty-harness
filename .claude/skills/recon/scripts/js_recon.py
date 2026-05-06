#!/usr/bin/env python3
"""JavaScript reconnaissance — extract JS URLs, download files, scan for secrets & endpoints.

Usage:
    js_recon.py --urls-file all_urls.txt --context output/example
    js_recon.py --urls-file all_urls.txt --context output/example --dry-run
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

try:
    import requests
except ImportError:
    requests = None

try:
    from urllib.parse import urljoin, urlparse
except ImportError:
    from urlparse import urljoin, urlparse


def which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, cmd)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def cmd_exists(name: str) -> bool:
    return which(name) is not None


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def run(cmd: list[str], timeout: int = 120, dry_run: bool = False) -> tuple[int, str, str]:
    if dry_run:
        log(f"DRY-RUN: {' '.join(cmd)}")
        return 0, "", ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


JS_EXTENSION_RE = re.compile(r"\.js(?:\?.*)?$|\.mjs(?:\?.*)?$|\.cjs(?:\?.*)?$")

SECRET_PATTERN = re.compile(
    r"(?:api[Kk]ey|token|secret|password|auth|bearer|ghp_|AKIA[0-9A-Z]{16}|"
    r"sk-[a-zA-Z0-9]{32}|pk\.[a-zA-Z0-9_-]{24}\.|"
    r"(?:-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)\sPRIVATE KEY-----)|"
    r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"
)

ENDPOINT_PATTERN = re.compile(r"""['"]((?:/[a-zA-Z0-9_%\-\.~:@!$&'()*+,;=]+)+)['"]""")


def extract_js_urls(urls_file: Path) -> List[str]:
    js_urls: list[str] = []
    if not urls_file.exists():
        return js_urls

    raw = urls_file.read_text(encoding="utf-8", errors="replace")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if JS_EXTENSION_RE.search(stripped):
            js_urls.append(stripped)
        if "application/javascript" in stripped.lower():
            for token in stripped.split():
                if token.startswith(("http://", "https://")):
                    js_urls.append(token)
    deduped = sorted(set(js_urls))
    return deduped


def download_js(js_urls: list[str], download_dir: Path, dry: bool) -> list[dict]:
    results: list[dict] = []
    download_dir.mkdir(parents=True, exist_ok=True)

    for url in js_urls:
        record = {"url": url, "downloaded": False, "file": None, "error": None, "size": 0}
        parsed = urlparse(url)
        fname = parsed.path.rsplit("/", 1)[-1] or "index.js"
        if not fname.endswith(".js"):
            fname += ".js"
        dest = download_dir / fname
        counter = 1
        stem = fname.replace(".js", "")
        while dest.exists():
            dest = download_dir / f"{stem}_{counter}.js"
            counter += 1

        if dry:
            log(f"DRY-RUN: wget {url} -O {dest}")
            results.append(record)
            continue

        try:
            resp = requests.get(
                url,
                timeout=30,
                headers={"User-Agent": "Mozilla/5.0 (compatible; JSRecon/1.0)"},
                allow_redirects=True,
            )
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            record["downloaded"] = True
            record["file"] = str(dest)
            record["size"] = len(resp.content)
        except Exception as e:
            record["error"] = str(e)

        results.append(record)
    return results


def scan_secrets(search_dir: Path) -> list[dict]:
    findings: list[dict] = []
    if not search_dir.exists():
        return findings

    for js_file in sorted(search_dir.glob("*.js")):
        try:
            content = js_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for match in SECRET_PATTERN.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            findings.append({
                "file": str(js_file),
                "line": line_no,
                "match": match.group(0)[:200],
                "type": "secret",
            })
    return findings


def scan_endpoints(search_dir: Path) -> list[dict]:
    findings: list[dict] = []
    if not search_dir.exists():
        return findings

    for js_file in sorted(search_dir.glob("*.js")):
        try:
            content = js_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for match in ENDPOINT_PATTERN.finditer(content):
            path = match.group(1)
            if len(path) < 2:
                continue
            line_no = content[: match.start()].count("\n") + 1
            findings.append({
                "file": str(js_file),
                "line": line_no,
                "endpoint": path,
                "type": "endpoint",
            })
    return findings


def write_lines_file(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="JavaScript reconnaissance — extract, download, scan secrets & endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  js_files.txt         All JS file URLs found
  js_downloads/        Downloaded JS files
  js_secrets.txt       Found secrets (human-readable)
  js_endpoints.txt     Found API endpoints
  findings.jsonl       All findings in JSON lines
""",
    )
    p.add_argument("--urls-file", "-u", required=True, help="File with all crawled URLs")
    p.add_argument("--context", "-c", default=".", help="Output directory (default: .)")
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return p


def run_crawler(hosts_file: Path, crawl_out: Path, dry: bool, target_url: str = "") -> None:
    if not cmd_exists("katana"):
        log("katana not installed; skipping crawl")
        return
    if not target_url:
        hosts = []
        if hosts_file.exists():
            hosts = [l.strip() for l in hosts_file.read_text(encoding="utf-8").splitlines() if l.strip() and l.strip().startswith("http")]
        target_url = hosts[0] if hosts else ""
    if not target_url:
        log("No target URL to crawl")
        return
    log(f"Crawling {target_url} with katana...")
    rc, out, err = run(
        ["katana", "-u", target_url, "-jc", "-d", "3", "-c", "10", "-silent", "-o", str(crawl_out)],
        timeout=600, dry_run=dry)
    if rc != 0 and not dry:
        log(f"katana crawl warning: {err.strip() or 'exit ' + str(rc)}")

def crawl_and_extract(hosts_file: Path, crawls_dir: Path, dry: bool, target_url: str = "") -> list[str]:
    crawls_dir.mkdir(parents=True, exist_ok=True)
    crawl_out = crawls_dir / "katana_crawl.txt"
    if not crawl_out.exists() or os.path.getsize(str(crawl_out)) == 0:
        run_crawler(hosts_file, crawl_out, dry, target_url=target_url)
    js_urls: list[str] = []
    if crawl_out.exists():
        js_urls = extract_js_urls(crawl_out)
    if not js_urls:
        js_urls = extract_js_urls(hosts_file)
    return js_urls


def load_target_url() -> str:
    env_target_url = os.environ.get("TARGET_URL", "").strip()
    if env_target_url:
        return env_target_url

    context_path = Path(".bb/context.json")
    if not context_path.exists():
        return ""

    try:
        context = json.loads(context_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"Could not read target_url from {context_path}: {exc}")
        return ""

    return str(context.get("target_url") or context.get("TARGET_URL") or "").strip()


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    urls_file = Path(args.urls_file).resolve()
    live_file = Path(str(urls_file))
    if not live_file.exists() and not urls_file.exists():
        log(f"URLs file not found: {urls_file}")
        sys.exit(1)

    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)
    dry = args.dry_run

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_ts = now_iso()
    log(f"URLs file: {live_file}  Context: {ctx}  Dry: {dry}")

    crawls_dir = ctx / "crawls"
    target_url = load_target_url()
    js_urls = crawl_and_extract(live_file, crawls_dir, dry, target_url=target_url)
    log(f"Extracted {len(js_urls)} JS URLs")

    js_txt = ctx / "js_files.txt"
    write_lines_file(js_txt, js_urls)

    dl_dir = ctx / "js_downloads"
    dl_results: list[dict] = []
    if js_urls:
        if requests is None:
            log("requests library missing; skipping JS downloads (pip3 install requests)")
        else:
            dl_results = download_js(js_urls, dl_dir, dry)
            succeeded = sum(1 for r in dl_results if r["downloaded"])
            log(f"Downloaded {succeeded}/{len(js_urls)} JS files")

    secrets = scan_secrets(dl_dir)
    log(f"Secret scan: {len(secrets)} hits")
    secrets_txt = ctx / "js_secrets.txt"
    write_lines_file(secrets_txt, [f"{s['file']}:{s['line']} {s['match']}" for s in secrets])

    endpoints = scan_endpoints(dl_dir)
    log(f"Endpoint scan: {len(endpoints)} hits")
    ep_txt = ctx / "js_endpoints.txt"
    write_lines_file(ep_txt, [f"{e['file']}:{e['line']} {e['endpoint']}" for e in endpoints])

    all_findings = secrets + endpoints
    for f in all_findings:
        f["timestamp"] = now_iso()
        f["run_id"] = run_id
    findings_file = ctx / "findings.jsonl"
    write_jsonl(findings_file, all_findings)

    metadata = {
        "run_id": run_id,
        "urls_file": str(urls_file),
        "started": start_ts,
        "completed": now_iso(),
        "js_urls_count": len(js_urls),
        "downloaded_count": sum(1 for r in dl_results if r.get("downloaded")),
        "secrets_count": len(secrets),
        "endpoints_count": len(endpoints),
        "files": {
            "js_files": str(js_txt),
            "secrets": str(secrets_txt),
            "endpoints": str(ep_txt),
            "findings": str(findings_file),
        },
    }
    meta_path = ctx / "js_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(json.dumps({"js_urls": len(js_urls), "secrets": len(secrets), "endpoints": len(endpoints)}))


if __name__ == "__main__":
    main()
