#!/usr/bin/env bash
# Quick Linux privilege escalation enumeration.
#
# Usage:
#   ./linux_enum.sh --context output/target
#   ./linux_enum.sh --context output/target --dry-run
#
# Outputs a timestamped file with all enumeration data.

set -euo pipefail

DRY_RUN=false
CONTEXT="."

usage() {
    cat <<'EOF'
Quick Linux privilege escalation enumeration.

Usage:
  linux_enum.sh --context <dir> [--dry-run]

Options:
  --context <dir>   Output directory (required)
  --dry-run         Print commands without executing
  --help            Show this help

Output:
  <context>/linux_enum_<timestamp>.txt  Full enumeration report
  <context>/findings.jsonl              Machine-readable findings
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --context) CONTEXT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage ;;
        *) echo "Unknown: $1"; usage ;;
    esac
done

mkdir -p "$CONTEXT"

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTFILE="$CONTEXT/linux_enum_$TS.txt"
JSONL="$CONTEXT/findings.jsonl"

if $DRY_RUN; then
    echo "DRY-RUN: would write to $OUTFILE"
    echo "DRY-RUN: would write to $JSONL"
    exit 0
fi

{
    echo "===== Linux Privilege Escalation Enumeration ====="
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Hostname: $(hostname 2>/dev/null || echo 'N/A')"
    echo ""

    # ── Basic Identity ──
    echo "===== IDENTITY ====="
    echo "User: $(whoami 2>/dev/null || id -un 2>/dev/null || echo 'N/A')"
    echo ""
    id 2>/dev/null || true
    echo ""

    # ── Kernel / OS ──
    echo "===== SYSTEM INFO ====="
    uname -a 2>/dev/null || true
    cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null || true
    echo ""

    # ── Sudo ──
    echo "===== SUDO ====="
    sudo -l 2>/dev/null || echo "sudo -l failed (no tty or NOPASSWD not set)"
    echo ""

    # ── SUID Binaries ──
    echo "===== SUID BINARIES ====="
    find / -perm -u=s -type f 2>/dev/null || true
    echo ""

    # ── SGID Binaries ──
    echo "===== SGID BINARIES ====="
    find / -perm -g=s -type f 2>/dev/null || true
    echo ""

    # ── Capabilities ──
    echo "===== CAPABILITIES ====="
    getcap -r / 2>/dev/null || echo "getcap not available"
    echo ""

    # ── Cron Jobs ──
    echo "===== CRON JOBS ====="
    cat /etc/crontab 2>/dev/null || true
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$d" ]; then
            echo "--- $d ---"
            ls -la "$d" 2>/dev/null || true
        fi
    done
    crontab -l 2>/dev/null || true
    echo ""

    # ── Writable Files / Directories ──
    echo "===== WORLD-WRITABLE FILES ====="
    find / -writable -type f 2>/dev/null | head -100 || true
    echo ""

    echo "===== WORLD-WRITABLE DIRS ====="
    find / -writable -type d 2>/dev/null | head -100 || true
    echo ""

    # ── PATH ──
    echo "===== PATH ====="
    echo "$PATH"
    for entry in $(echo "$PATH" | tr ':' '\n'); do
        if [ -w "$entry" ]; then
            echo "WARNING: $entry is writable!"
        fi
    done
    echo ""

    # ── Interesting Files ──
    echo "===== CONFIG / CREDENTIAL FILES ====="
    find / -maxdepth 4 -type f \( \
        -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o \
        -name "*.ini" -o -name "*.env" -o -name ".env" -o \
        -name "*.key" -o -name "*.pem" -o -name "*.p12" -o \
        -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
    \) 2>/dev/null | grep -v "/usr/share" | grep -v "/proc" | head -100 || true
    echo ""

    # ── Network ──
    echo "===== NETWORK ====="
    ip a 2>/dev/null || ifconfig 2>/dev/null || true
    echo ""
    netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null || true
    echo ""
    arp -a 2>/dev/null || true
    echo ""

    # ── Processes ──
    echo "===== RUNNING PROCESSES ====="
    ps aux 2>/dev/null || ps -ef 2>/dev/null || true
    echo ""

    # ── Mounts ──
    echo "===== MOUNTS ====="
    mount 2>/dev/null || cat /proc/mounts 2>/dev/null || true
    echo ""
    df -h 2>/dev/null || true
    echo ""

    # ── Container / VM Check ──
    echo "===== CONTAINER / VM ====="
    if [ -f /.dockerenv ]; then echo "IN DOCKER CONTAINER"; fi
    if grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
        echo "Container detected in cgroup"
        grep "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null || true
    fi
    echo ""

    # ── K8s Service Account ──
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        echo "K8s service account token found"
        cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true
    fi
    echo ""

    # ── Docker Socket ──
    if [ -S /var/run/docker.sock ]; then
        echo "Docker socket accessible: /var/run/docker.sock"
    fi
    echo ""

    # ── NFS / Network Shares ──
    echo "===== NFS SHARES ====="
    showmount -e localhost 2>/dev/null || true
    showmount -e 127.0.0.1 2>/dev/null || true
    echo ""

    # ── History Files ──
    echo "===== SHELL HISTORY ====="
    for hf in ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history ~/.python_history; do
        if [ -f "$hf" ]; then
            echo "--- $hf ---"
            tail -20 "$hf" 2>/dev/null || true
        fi
    done
    echo ""

    echo "===== ENUMERATION COMPLETE ====="
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

} > "$OUTFILE"

echo "Enumeration saved to: $OUTFILE"

# ── Generate JSONL findings ──
{
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$OUTFILE" "$JSONL" << 'PYEOF'
import json, sys, re
from datetime import datetime, timezone

infile = sys.argv[1]
outfile = sys.argv[2]
ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(infile) as f:
    text = f.read()

findings = []

kw = [
    ("sudo_all", "sudo -l shows (ALL) NOPASSWD"),
    ("docker_socket", "Docker socket accessible"),
    ("in_docker", "IN DOCKER CONTAINER"),
    ("k8s_token", "K8s service account token found"),
    ("writable_path", "WARNING:"),
    ("writable_etc_passwd", re.findall(r"/etc/(?:passwd|shadow).*writable", text)),
    ("cap_dac_read_search", "cap_dac_read_search"),
    ("cap_dac_override", "cap_dac_override"),
    ("cap_setuid", "cap_setuid"),
    ("cap_sys_admin", "cap_sys_admin"),
    ("cap_sys_ptrace", "cap_sys_ptrace"),
    ("cap_net_admin", "cap_net_admin"),
    ("cap_net_raw", "cap_net_raw"),
]

for finding_type, pattern in kw:
    if isinstance(pattern, list):
        for m in pattern:
            findings.append({"type": finding_type, "evidence": m, "timestamp": ts})
    elif pattern in text:
        findings.append({"type": finding_type, "evidence": pattern[:200], "timestamp": ts})

with open(outfile, "w") as f:
    for finding in findings:
        f.write(json.dumps(finding) + "\n")

print(f"JSONL findings: {outfile}")
PYEOF
    fi
} || true

echo "Done. Context: $CONTEXT"