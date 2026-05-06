# Privilege Escalation — False Positive Filter

## Purpose
Validate that discovered privilege escalation vectors actually lead to root and are not false leads, misconfigurations without impact, or patched vulnerabilities.

## Required Variables
- \$LHOST: attacker IP for reverse shells
- \$LPORT: attacker listener port

## Commands

```bash
ls -la /usr/bin/find
file /usr/bin/find
stat /usr/bin/find
```

For each SUID binary flagged, verify it is both SUID and executable by current user:

```bash
for bin in $(cat /tmp/discovery_suid.txt 2>/dev/null); do
    perms=$(stat -c '%a' "$bin" 2>/dev/null)
    owner=$(stat -c '%U' "$bin" 2>/dev/null)
    filetype=$(file "$bin" 2>/dev/null)
    echo "$bin | perms:$perms | owner:$owner | type:$filetype"
done | tee /tmp/suid_verified.txt
```

Distinguish real binaries from shell scripts (scripts ignore SUID on most systems):

```bash
for bin in $(cat /tmp/discovery_suid.txt 2>/dev/null); do
    type=$(file "$bin" 2>/dev/null)
    echo "$type" | grep -qiE 'script|text|ASCII|shell' && echo "WARNING: $bin is a script, SUID likely ignored" | tee -a /tmp/suid_scripts.txt
done
```

Verify compilation for kernel exploits works before assuming vulnerability:

```bash
gcc --version 2>/dev/null || apt-get install -y gcc 2>/dev/null || yum install -y gcc 2>/dev/null
which gcc > /dev/null 2>&1 || echo "Compiler absent — kernel exploits requiring compilation cannot be used" | tee /tmp/no_compiler.txt
```

Verify Docker socket access actually grants root:

```bash
id | grep docker && echo "In docker group" | tee /tmp/docker_check.txt
docker ps 2>/dev/null || echo "Docker command exists but socket inaccessible" | tee -a /tmp/docker_check.txt
curl --unix-socket /var/run/docker.sock http:/containers/json 2>/dev/null | head -c 200 | tee /tmp/docker_socket_test.txt
```

For writable files in PATH, verify PATH traversal is exploitable:

```bash
echo $PATH | tr ':' '\n' | while read dir; do
    ls -ld "$dir" 2>/dev/null | grep -q '^d.*w' && echo "Writable PATH dir: $dir" | tee -a /tmp/writable_path_dirs.txt
done
```

For cron-based vectors, verify cron actually executes as root:

```bash
ps aux | grep [c]ron || echo "cron daemon not running — cron vectors are inactive" | tee -a /tmp/cron_daemon_check.txt
grep -v '^#' /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^$' | tee /tmp/active_cron_jobs.txt
```

Check if kernel is patched for known CVEs:

```bash
cat /proc/version | grep -i 'kali\|ubuntu' | grep -oP '\d+\.\d+\.\d+-\d+' | while read ver; do
    echo "Kernel: $ver — cross-reference with exploit-db for patched status" >> /tmp/kernel_patch_check.txt
done
```

## Detection Signals
- SUID binary is a shell script — SUID bit ignored by kernel on scripts, false positive
- SUID binary not executable by current user (permission denied), no `x` bit for group/other
- Docker socket returns empty body — socket exists but user lacks read access
- `cron` process not running — writable cron files cannot be exploited
- `gcc` not found and no package manager — kernel exploits requiring compilation cannot be used
- PATH directory writable but not traversed by root cron or SUID process — no impact

## Next
├── If vector confirmed viable → go to 03-verify for exploitation
├── If kernel patch check confirms unpatched → go to 04-impact-escalation
├── If all vectors are false positives → go to 02-probe for deeper scan
├── If false positives filtered, new vectors identified → go to 03-verify
├── If all vectors exhausted and all are false positives → report no privesc path found