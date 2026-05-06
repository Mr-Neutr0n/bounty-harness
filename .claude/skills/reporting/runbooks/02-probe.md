# Reporting — Probe (CVSS Scoring)

## Purpose
Compute CVSS v3.1 and v4.0 scores for each finding. Use lookup defaults for common vulnerability classes when full vectors are unavailable, and produce both quantitative scores and qualitative mappings for the final report.

## Required Variables
- `$OUTDIR`: output directory for reports
- `$FINDING_TITLE`: title of the finding
- `$CVSS_SCORE`: computed score
- `$SEVERITY`: severity label (Critical/High/Medium/Low/Info)

## Commands

```bash
python3 - "$OUTDIR/inventory/finding_inventory.json" "$OUTDIR/inventory/findings_scored.json" << 'PYEOF'
import sys, json

CVSS_DEFAULTS = {
    "sqli":     {"v31": 9.8, "v40": 9.3, "severity": "Critical"},
    "rce":      {"v31": 10.0, "v40": 10.0, "severity": "Critical"},
    "ssrf":     {"v31": 8.6, "v40": 8.7, "severity": "High"},
    "xss":      {"v31": 6.1, "v40": 6.3, "severity": "Medium"},
    "idor":     {"v31": 6.5, "v40": 6.5, "severity": "Medium"},
    "idor-bola":{"v31": 6.5, "v40": 6.5, "severity": "Medium"},
    "auth-bypass":{"v31": 9.8, "v40": 9.3, "severity": "Critical"},
    "file-upload":{"v31": 8.8, "v40": 8.8, "severity": "High"},
    "xxe":      {"v31": 7.5, "v40": 7.5, "severity": "High"},
    "csrf":     {"v31": 6.5, "v40": 6.5, "severity": "Medium"},
    "cors":     {"v31": 5.3, "v40": 5.3, "severity": "Medium"},
    "open-redirect":{"v31": 4.7, "v40": 4.7, "severity": "Low"},
    "info-disclosure":{"v31": 5.3, "v40": 5.3, "severity": "Medium"},
}

SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

def classify(template_str):
    t = template_str.lower()
    for key in CVSS_DEFAULTS:
        if key in t:
            return key
    return None

with open(sys.argv[1]) as fh:
    findings = json.load(fh)

for f in findings:
    cls = classify(f.get("template", ""))
    if cls:
        f["cvss_v31"] = CVSS_DEFAULTS[cls]["v31"]
        f["cvss_v40"] = CVSS_DEFAULTS[cls]["v40"]
        f["severity"] = CVSS_DEFAULTS[cls]["severity"]
    else:
        f["cvss_v31"] = 5.0
        f["cvss_v40"] = 5.0
        f["severity"] = "Medium"

findings.sort(key=lambda x: SEVERITY_RANK.get(x["severity"], 0), reverse=True)

with open(sys.argv[2], 'w') as fh:
    json.dump(findings, fh, indent=2)

print(f"Scored {len(findings)} findings. Output: {sys.argv[2]}")
PYEOF

jq -r '.[]|"\(.severity|rpadstr(10)) CVSSv3.1=\(.cvss_v31)  CVSSv4.0=\(.cvss_v40)  \(.title)"' "$OUTDIR/inventory/findings_scored.json" > "$OUTDIR/inventory/score_summary.txt"
cat "$OUTDIR/inventory/score_summary.txt"
```

## CVSS Calculator Formula

```
Base Score = min[ (Impact * Exploitability * Scope + Exploitability), 10 ]
where:
  Impact    = 1 - (1 - C) * (1 - I) * (1 - A)
  Exploitability = 8.22 * AV * AC * PR * UI
  Scope modifier = 1.08 if changed, else 1.0

Mapping: AV:N=0.85, AV:A=0.62, AV:L=0.55
         AC:L=0.77, AC:H=0.44
         PR:N=0.85, PR:L=0.62, PR:H=0.27
         UI:N=0.85, UI:R=0.62
         C/I/A:H=0.56, C/I/A:L=0.22, C/I/A:N=0
```

## Detection Signals
- All findings have a non-null CVSS score
- `Critical` findings scored ≥ 9.0
- `High` findings scored 7.0 – 8.9
- Severity distribution makes sense for target type

## Next
├── If all scored → `03-verify.md`
├── If custom CVSS vectors needed from analyst → flag for manual input
└── If findings disagree with lookup defaults → annotate, continue