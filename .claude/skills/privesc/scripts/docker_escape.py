#!/usr/bin/env python3
"""Docker / Kubernetes escape enumeration.

Checks for common breakout primitives in containerized environments.

Usage:
    docker_escape.py --context output/target
    docker_escape.py --context output/target --dry-run
"""

import argparse
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def run(cmd: list[str], timeout: int = 10, dry: bool = False) -> tuple[int, str, str]:
    if dry:
        log(f"DRY-RUN: {' '.join(cmd)}")
        return 0, "", ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def read_file(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def check_socket(path: str) -> bool:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(path)
        s.close()
        return True
    except Exception:
        return False


def am_i_container() -> tuple[bool, str]:
    evidence: list[str] = []
    is_container = False

    if os.path.exists("/.dockerenv"):
        evidence.append("/.dockerenv exists")
        is_container = True

    cgroup = read_file("/proc/1/cgroup") or ""
    for needle in ("docker", "lxc", "kubepods", "libpod", "containerd"):
        if needle in cgroup:
            evidence.append(f"cgroup contains '{needle}'")
            is_container = True

    if os.path.exists("/proc/vz") and not os.path.exists("/proc/bc"):
        evidence.append("/proc/vz exists (OpenVZ)")
        is_container = True

    return is_container, "; ".join(evidence) if evidence else "not detected"


def check_docker_socket() -> tuple[bool, str]:
    paths = ["/var/run/docker.sock", "/run/docker.sock", "/var/run/dockershim.sock"]
    for p in paths:
        if os.path.exists(p):
            if check_socket(p):
                return True, f"{p} mounted and accessible"
            return False, f"{p} mounted but not reachable"
    return False, "no docker socket found"


def check_capabilities() -> list[str]:
    caps_file = f"/proc/{os.getpid()}/status" if not os.path.exists(f"/proc/{os.getpid()}/status") else f"/proc/{os.getpid()}/status"
    content = read_file(caps_file) or ""
    interesting_caps: list[str] = []
    cap_names = [
        "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
        "CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE",
        "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_RAWIO",
        "CAP_SYS_BOOT", "CAP_SYS_TIME", "CAP_SYSLOG",
        "CAP_SETUID", "CAP_SETGID", "CAP_SETFCAP",
    ]
    for cap in cap_names:
        for line in content.splitlines():
            if cap in line and "0000000000000000" not in line:
                interesting_caps.append(cap)
                break
    return interesting_caps


def check_mounted_hostfs() -> list[dict]:
    mounts: list[dict] = []
    mtab = read_file("/proc/mounts") or read_file("/etc/mtab") or ""
    for line in mtab.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        device, mount_point = parts[0], parts[1]
        if any(d in device for d in ("/dev/sd", "/dev/xvd", "/dev/nvme", "/dev/vd", "/dev/mapper")):
            mounts.append({"device": device, "mount": mount_point, "reason": "host block device"})
        if mount_point in ("/", "/host", "/rootfs", "/host-root", "/proc/1/root"):
            mounts.append({"device": device, "mount": mount_point, "reason": "potential host root mount"})
    return mounts


def check_privileged() -> tuple[bool, str]:
    if not os.path.exists("/dev"):
        return False, "/dev not accessible"
    dev_count = len(list(Path("/dev").iterdir()))
    if dev_count > 100:
        return True, f"/dev has {dev_count} entries (likely --privileged)"
    return False, f"/dev has {dev_count} entries (likely non-privileged)"


def check_k8s_token() -> tuple[bool, str]:
    paths = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/token",
    ]
    for p in paths:
        if os.path.isfile(p):
            token = read_file(p) or ""
            return True, f"token at {p} ({len(token)} bytes)"
    return False, "no K8s service account token found"


def check_k8s_namespace() -> Optional[str]:
    for p in ["/var/run/secrets/kubernetes.io/serviceaccount/namespace", "/run/secrets/kubernetes.io/serviceaccount/namespace"]:
        ns = read_file(p)
        if ns:
            return ns.strip()
    return None


def check_k8s_ca() -> Optional[str]:
    for p in ["/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "/run/secrets/kubernetes.io/serviceaccount/ca.crt"]:
        if os.path.isfile(p):
            return p
    return None


def check_cgroup_v1_release_agent() -> bool:
    cgroup_path = "/tmp/cgrp"
    if os.path.exists(cgroup_path):
        return True
    try:
        os.makedirs(cgroup_path, exist_ok=True)
        return True
    except Exception:
        return False


def check_seccomp() -> str:
    content = read_file(f"/proc/{os.getpid()}/status") or ""
    for line in content.splitlines():
        if "Seccomp" in line:
            return line.strip()
    return "unknown"


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Docker/Kubernetes escape enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outputs (in --context dir):
  findings.jsonl    JSON lines with all escape-related findings
  escape_report.json  Full analysis report
""",
    )
    p.add_argument("--context", "-c", default=".", help="Output directory (default: .)")
    p.add_argument("--dry-run", action="store_true", help="Print checks without executing")
    return p


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    ctx = Path(args.context).resolve()
    ctx.mkdir(parents=True, exist_ok=True)
    dry = args.dry_run

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_ts = now_iso()
    log(f"Context: {ctx}  Dry: {dry}")

    if dry:
        log("DRY-RUN mode — all checks skipped")
        print(json.dumps({"dry_run": True, "context": str(ctx)}))
        return

    findings: list[dict] = []

    is_cont, evidence = am_i_container()
    log(f"Container detection: {is_cont} → {evidence}")
    findings.append({"type": "container_detection", "in_container": is_cont, "evidence": evidence, "timestamp": now_iso(), "severity": "info"})

    sock_ok, sock_msg = check_docker_socket()
    log(f"Docker socket: {sock_ok} → {sock_msg}")
    if sock_ok:
        findings.append({"type": "docker_socket", "accessible": True, "path": sock_msg.split()[0], "timestamp": now_iso(), "severity": "critical", "impact": "Can be used to escape container or spawn privileged containers"})

    caps = check_capabilities()
    log(f"Capabilities: {caps}")
    for cap in caps:
        sev = "high" if cap in ("CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE") else "medium"
        findings.append({"type": "dangerous_capability", "capability": cap, "timestamp": now_iso(), "severity": sev})

    host_mounts = check_mounted_hostfs()
    log(f"Host filesystem mounts: {len(host_mounts)}")
    for m in host_mounts:
        findings.append({"type": "host_filesystem_mount", "device": m["device"], "mount": m["mount"], "reason": m["reason"], "timestamp": now_iso(), "severity": "critical", "impact": "Potential host filesystem access"})

    priv, priv_msg = check_privileged()
    log(f"Privileged: {priv} → {priv_msg}")
    if priv:
        findings.append({"type": "privileged_container", "evidence": priv_msg, "timestamp": now_iso(), "severity": "critical", "impact": "Container running with --privileged flag"})

    k8s_token, k8s_tmsg = check_k8s_token()
    log(f"K8s token: {k8s_token} → {k8s_tmsg}")
    if k8s_token:
        k8s_ns = check_k8s_namespace()
        k8s_ca = check_k8s_ca()
        findings.append({"type": "k8s_service_account_token", "namespace": k8s_ns, "ca_cert": k8s_ca, "evidence": k8s_tmsg, "timestamp": now_iso(), "severity": "high", "impact": "K8s service account token may allow API server access"})

    seccomp = check_seccomp()
    log(f"Seccomp: {seccomp}")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "run_id": run_id,
        "started": start_ts,
        "completed": now_iso(),
        "container": is_cont,
        "container_evidence": evidence,
        "docker_socket_accessible": sock_ok,
        "dangerous_capabilities": caps,
        "host_mounts": host_mounts,
        "privileged": priv,
        "k8s_service_account": k8s_token,
        "seccomp": seccomp,
        "findings_count": len(findings),
        "severity_summary": severity_counts,
    }

    report_path = ctx / "escape_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"Report → {report_path}")

    jl_path = ctx / "findings.jsonl"
    with open(jl_path, "w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")
    log(f"Findings JSONL → {jl_path}")

    print(json.dumps({"findings": len(findings), "severity_summary": severity_counts, "context": str(ctx)}))


if __name__ == "__main__":
    main()