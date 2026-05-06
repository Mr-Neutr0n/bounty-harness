#!/usr/bin/env python3
"""APK static analysis — decompile, extract secrets, analyze manifest.

Usage:
    apk_analyzer.py --apk target.apk --context output/target
    apk_analyzer.py --apk target.apk --context output/target --dry-run
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List


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


SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("firebase_url", re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com")),
    ("firebase_app", re.compile(r"https?://[a-z0-9-]+\.firebaseapp\.com")),
    ("generic_api", re.compile(r"(?:api[Kk]ey|[Aa]ccess[Kk]ey|[Ss]ecret[Kk]ey)['\\\"]?\s*[:=]\\s*['\\\"]?([A-Za-z0-9+/=_-]{20,60})")),
    ("jwt_token", re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")),
    ("oauth_client", re.compile(r"[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com")),
    ("url_endpoint", re.compile(r"https?://[a-zA-Z0-9._/-]+(?:/api/|/v[0-9]+/|/graphql)[a-zA-Z0-9._/-]*")),
    ("password", re.compile(r"(?:password|passwd|pwd)['\\\"]?\s*[:=]\s*['\\\"]([^'\\\"]+)['\\\"]")),
    ("private_key", re.compile(r"-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)\sPRIVATE KEY-----")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]+")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
]


def decompile_apk(apk_path: Path, out_dir: Path, dry: bool) -> Optional[Path]:
    if not cmd_exists("apktool"):
        log("apktool not installed; install via brew install apktool")
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"Decompiling {apk_path} → {out_dir}")
    rc, out, err = run(
        ["apktool", "d", str(apk_path), "-f", "-o", str(out_dir)],
        timeout=300,
        dry_run=dry,
    )
    if rc != 0 and not dry:
        log(f"apktool failed: {err.strip()}")
        return None
    return out_dir


def parse_manifest(manifest_path: Path) -> dict:
    result: dict = {
        "package": "",
        "version": "",
        "permissions": [],
        "exported_components": [],
        "deeplinks": [],
        "intent_filters": [],
    }
    if not manifest_path.exists():
        return result

    try:
        ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
        tree = ET.parse(str(manifest_path))
        root = tree.getroot()

        result["package"] = root.get("package", "")
        result["version"] = root.get("{http://schemas.android.com/apk/res/android}versionName", "")

        for elem in root.iter():
            if elem.tag == "uses-permission":
                perm = elem.get("{http://schemas.android.com/apk/res/android}name", "")
                if perm:
                    result["permissions"].append(perm)

            tag_local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            exported = elem.get("{http://schemas.android.com/apk/res/android}exported", "")
            if tag_local in ("activity", "service", "receiver", "provider"):
                comp = {
                    "type": tag_local,
                    "name": elem.get("{http://schemas.android.com/apk/res/android}name", ""),
                    "exported": exported.lower() == "true",
                }
                result["exported_components"].append(comp)

                for child in elem.iter():
                    if child.tag == "action":
                        action_name = child.get("{http://schemas.android.com/apk/res/android}name", "")
                        if action_name and "VIEW" in action_name:
                            result["intent_filters"].append(action_name)
                    if child.tag == "data":
                        scheme = child.get("{http://schemas.android.com/apk/res/android}scheme", "")
                        host = child.get("{http://schemas.android.com/apk/res/android}host", "")
                        if scheme and host:
                            result["deeplinks"].append(f"{scheme}://{host}")

    except Exception as e:
        log(f"Manifest parse error: {e}")

    return result


def extract_strings(decompiled_dir: Path) -> str:
    all_text: list[str] = []
    for f in decompiled_dir.rglob("*"):
        if f.is_file() and f.suffix in (".smali", ".xml", ".txt", ".json", ".js", ".html", ".yml", ".yaml", ".properties"):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                all_text.append(text)
            except Exception:
                pass
    return "\n".join(all_text)


def scan_secrets(text: str) -> list[dict]:
    findings: list[dict] = []
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if len(value) > 200:
                value = value[:200]
            findings.append({
                "type": name,
                "value": value,
                "match": value,
            })
    return findings


def parse_firebase_urls(text: str) -> list[str]:
    urls: list[str] = []
    for m in re.finditer(r"https?://[a-z0-9-]+\.(?:firebaseio\.com|firebaseapp\.com|web\.app)", text):
        urls.append(m.group(0))
    return sorted(set(urls))


def find_api_endpoints(text: str) -> list[str]:
    eps: list[str] = []
    for m in re.finditer(r"""['"](https?://[a-zA-Z0-9._/-]+(?:/api/|/v[0-9]+/|/graphql)[a-zA-Z0-9._\-/?:&=]*)['"]""", text):
        eps.append(m.group(1))
    return sorted(set(eps))


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="APK static analysis — decompile, extract secrets, analyze manifest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  apk_analysis.json    Full analysis results
  findings.jsonl       JSON lines with individual findings
  decompiled/          apktool decompile output
""",
    )
    p.add_argument("--apk", "-a", required=True, help="Path to APK file")
    p.add_argument("--context", "-c", default=".", help="Output directory (default: .)")
    p.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    apk_path = Path(args.apk).resolve()
    if not apk_path.exists():
        log(f"APK not found: {apk_path}")
        sys.exit(1)

    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)
    dry = args.dry_run

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_ts = now_iso()
    log(f"APK: {apk_path}  Context: {ctx}  Dry: {dry}")

    dec_dir = ctx / "decompiled"
    dec = decompile_apk(apk_path, dec_dir, dry)

    manifest = {}
    if dec and (dec / "AndroidManifest.xml").exists():
        manifest = parse_manifest(dec / "AndroidManifest.xml")
        log(f"Manifest: package={manifest['package']}, perms={len(manifest['permissions'])}")

    full_text = ""
    secrets: list[dict] = []
    firebase: list[str] = []
    api_eps: list[str] = []

    if dec:
        full_text = extract_strings(dec)
        secrets = scan_secrets(full_text)
        firebase = parse_firebase_urls(full_text)
        api_eps = find_api_endpoints(full_text)

    log(f"Secrets found: {len(secrets)}")
    log(f"Firebase URLs: {len(firebase)}")
    log(f"API endpoints: {len(api_eps)}")

    analysis = {
        "run_id": run_id,
        "apk": str(apk_path),
        "started": start_ts,
        "completed": now_iso(),
        "manifest": manifest,
        "secrets": secrets,
        "firebase_urls": firebase,
        "api_endpoints": api_eps,
        "stats": {
            "secrets_count": len(secrets),
            "firebase_urls_count": len(firebase),
            "api_endpoints_count": len(api_eps),
            "exported_components": len(manifest.get("exported_components", [])),
            "deeplinks": len(manifest.get("deeplinks", [])),
            "permissions": len(manifest.get("permissions", [])),
        },
    }

    out_path = ctx / "apk_analysis.json"
    out_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    log(f"Analysis → {out_path}")

    findings: list[dict] = []
    for s in secrets:
        findings.append({**s, "source": "apk_secret", "timestamp": now_iso(), "run_id": run_id})
    for url in firebase:
        findings.append({"type": "firebase_url", "value": url, "source": "apk", "timestamp": now_iso(), "run_id": run_id})
    for ep in api_eps:
        findings.append({"type": "api_endpoint", "value": ep, "source": "apk", "timestamp": now_iso(), "run_id": run_id})
    if manifest.get("exported_components"):
        for comp in manifest["exported_components"]:
            if comp.get("exported"):
                findings.append({"type": "exported_component", "value": comp["name"], "component_type": comp["type"], "source": "manifest", "timestamp": now_iso(), "run_id": run_id})
    if manifest.get("deeplinks"):
        for dl in manifest["deeplinks"]:
            findings.append({"type": "deeplink", "value": dl, "source": "manifest", "timestamp": now_iso(), "run_id": run_id})

    f_path = ctx / "findings.jsonl"
    with open(f_path, "w", encoding="utf-8") as f:
        for record in findings:
            f.write(json.dumps(record) + "\n")
    log(f"Findings JSONL → {f_path}")

    print(json.dumps(analysis["stats"]))


if __name__ == "__main__":
    main()