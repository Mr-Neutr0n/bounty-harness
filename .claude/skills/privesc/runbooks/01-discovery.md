# Privilege Escalation — Discovery

## Purpose
Initial enumeration of a compromised Linux host. Collects identity, kernel version, sudo rights, SUID binaries, capabilities, writable files, cron jobs, active services, and world-writable files to build a privesc vector list.

## Required Variables
- \$LHOST: attacker IP for reverse shells
- \$LPORT: attacker listener port

## Commands

```bash
id && whoami && hostname && uname -a | tee /tmp/discovery_id.txt

cat /etc/os-release && cat /proc/version | tee -a /tmp/discovery_id.txt

sudo -l 2>/dev/null | tee /tmp/discovery_sudo.txt

find / -perm -4000 -type f 2>/dev/null | tee /tmp/discovery_suid.txt

getcap -r / 2>/dev/null | tee /tmp/discovery_caps.txt

find / -writable -type f 2>/dev/null | grep -v '/proc\|/sys' | tee /tmp/discovery_writable.txt

cat /etc/crontab && ls -laR /etc/cron* 2>/dev/null | tee /tmp/discovery_cron.txt

ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null | tee /tmp/discovery_ports.txt

ps aux | grep -iE 'root|mysql|postgres|nginx|docker' | tee /tmp/discovery_services.txt

find / -perm -2 -type f -not -path '/proc/*' 2>/dev/null | tee /tmp/discovery_wwf.txt
```

## Detection Signals
- `(ALL) NOPASSWD:` in sudo -l output — instant root via any listed binary
- SUID binary owned by root with known GTFOBins path (bash, vim, find, python, etc.)
- cap_dac_read_search, cap_sys_admin, cap_sys_ptrace capabilities set on binaries
- Writable /etc/passwd, /etc/shadow, or /etc/sudoers
- Docker socket accessible (/var/run/docker.sock) by current user
- Cron job executing writable script as root

## Next
├── If root obtained via sudo or SUID → go to 05-evidence-collection
├── If vectors identified but not exploited → go to 02-probe
├── If service/database root creds found → go to 03-verify
├── If Docker socket found → go to 04-impact-escalation
├── If no clear vector → go to 02-probe for automated deeper scan