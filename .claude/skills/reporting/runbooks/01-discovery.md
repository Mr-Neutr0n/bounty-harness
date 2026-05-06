# Reporting — Discovery

## Purpose
Gather raw findings from nuclei, sqlmap, and ffuf output; parse each into a structured inventory with severity, title, template ID, and target URL. Aggregate all sources into a single JSON manifest for downstream phases.

## Required Variables
- `$OUTDIR`: output directory for reports
- `$TARGET_URL`: primary target URL or domain

## Commands

```bash
mkdir -p "$OUTDIR/inventory"

nuclei_output="$OUTDIR/../nuclei_output.jsonl"
if [ -f "$nuclei_output" ]; then
  jq -r '.[]|"\(.info.severity): \(.info.name) [\(.template-id)] → \(.matched-at)"' "$nuclei_output" > "$OUTDIR/inventory/nuclei_parsed.txt"
fi

for f in "$OUTDIR/raw/sqlmap"/*.json; do
  [ -f "$f" ] && jq -r '"SQLi: " + .info.payload + " [" + .info.parameter + "] → " + .info.url' "$f" >> "$OUTDIR/inventory/sqlmap_parsed.txt"
done

for f in "$OUTDIR/raw/ffuf"/*.json; do
  [ -f "$f" ] && jq -r '.results[]|"Content-Discovery: \(.url) [\(.status)]"' "$f" >> "$OUTDIR/inventory/ffuf_parsed.txt"
done

cat "$OUTDIR/inventory/nuclei_parsed.txt" "$OUTDIR/inventory/sqlmap_parsed.txt" "$OUTDIR/inventory/ffuf_parsed.txt" > "$OUTDIR/inventory/all_findings_raw.txt" 2>/dev/null

python3 - "$OUTDIR/inventory/all_findings_raw.txt" "$OUTDIR/inventory/finding_inventory.json" << 'PYEOF'
import sys, json, re
infile, outfile = sys.argv[1], sys.argv[2]
findings = []
with open(infile) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^(\S+):\s*(.+?)\s*\[(.+?)\]\s*→?\s*(.*)', line)
        if m:
            findings.append({"severity": m.group(1), "title": m.group(2).strip(), "template": m.group(3).strip(), "url": m.group(4).strip()})
with open(outfile, 'w') as fh:
    json.dump(findings, fh, indent=2)
print(f"Wrote {len(findings)} findings to {outfile}")
PYEOF

jq -r 'group_by(.severity)[]|"\(.[0].severity): \(length) findings"' "$OUTDIR/inventory/finding_inventory.json" > "$OUTDIR/inventory/severity_summary.txt"
cat "$OUTDIR/inventory/severity_summary.txt"
```

## Detection Signals
- Finding count per severity tier present and non-zero
- No duplicate template-id + URL combinations
- Inventory JSON is valid and non-empty

## Next
├── If inventory has findings → proceed to `02-probe.md`
├── If inventory is empty → re-run recon + scan workflows
└── If raw files missing → skip that source, warn in summary