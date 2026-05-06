# Nuclei Scanner — Discovery & Template Inventory

## Purpose
Prepare the template library, inventory available templates by severity and category, and select the correct severity profile for the target's risk level.

## Required Variables
- $TARGET_URL: target URL or file of live URLs (one per line)
- $OUTDIR: output directory for scan results (e.g., ./output/TARGET/2026-05-05/nuclei)
- $EVIDENCE_DIR: evidence directory inside $OUTDIR (e.g., $OUTDIR/evidence)

## Commands

### Build and update template library

```bash
export PATH="/opt/homebrew/bin:$HOME/go/bin:$HOME/Library/Python/3.14/bin:$PATH"
mkdir -p "$OUTDIR"/{scans,results,evidence,diff}

TEMPLATES_DIR=""
for d in "/opt/homebrew/share/nuclei-templates" "$HOME/nuclei-templates" "templates/nuclei-templates" "./nuclei-templates"; do
  if [ -d "$d" ]; then TEMPLATES_DIR="$d"; break; fi
done
if [ -z "$TEMPLATES_DIR" ]; then
  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$HOME/nuclei-templates"
  TEMPLATES_DIR="$HOME/nuclei-templates"
fi
echo "Templates: $TEMPLATES_DIR"
```

```bash
/opt/homebrew/bin/nuclei -update-templates 2>&1 | tee "$OUTDIR/discovery_update.log"
```

### Inventory templates by category and severity

```bash
/opt/homebrew/bin/nuclei -tl -templates "$TEMPLATES_DIR" 2>&1 | tee "$OUTDIR/discovery_template_list.txt"
echo "Total templates available: $(wc -l < "$OUTDIR/discovery_template_list.txt")"
```

```bash
/opt/homebrew/bin/nuclei -tl -templates "$TEMPLATES_DIR/http/cves/" 2>&1 | tee "$OUTDIR/discovery_cve_templates.txt"
echo "CVE templates: $(wc -l < "$OUTDIR/discovery_cve_templates.txt")"
```

```bash
/opt/homebrew/bin/nuclei -tl -templates "$TEMPLATES_DIR/http/exposures/" 2>&1 | tee "$OUTDIR/discovery_exposure_templates.txt"
echo "Exposure templates: $(wc -l < "$OUTDIR/discovery_exposure_templates.txt")"
```

```bash
/opt/homebrew/bin/nuclei -tl -templates "$TEMPLATES_DIR/http/technologies/" 2>&1 | tee "$OUTDIR/discovery_tech_templates.txt"
echo "Technology templates: $(wc -l < "$OUTDIR/discovery_tech_templates.txt")"
```

### Record template repo commit for reproducibility

```bash
git -C "$TEMPLATES_DIR" rev-parse HEAD 2>/dev/null | tee "$OUTDIR/discovery_template_commit.txt"
git -C "$TEMPLATES_DIR" log -1 --format='%ci' 2>/dev/null | tee -a "$OUTDIR/discovery_template_commit.txt"
```

### Quick critical-only scan for first-pass triage

```bash
/opt/homebrew/bin/nuclei -l "$TARGET_URL" -templates "$TEMPLATES_DIR/http/cves/" -severity critical,high -timeout 10 -retries 1 -bulk-size 50 -silent -stats -stats-interval 30 -o "$OUTDIR/discovery_critical.txt"
```

### Severity breakdown of templates available

```bash
python3 -c "
import subprocess, sys
result = subprocess.run(['/opt/homebrew/bin/nuclei', '-tl', '-templates', '$TEMPLATES_DIR'], capture_output=True, text=True)
tags = {'critical':0,'high':0,'medium':0,'low':0,'info':0}
for line in result.stdout.split('\n'):
    line_lower = line.lower()
    if 'critical' in line_lower: tags['critical'] += 1
    elif 'high' in line_lower: tags['high'] += 1
    elif 'medium' in line_lower: tags['medium'] += 1
    elif 'low' in line_lower: tags['low'] += 1
    elif 'info' in line_lower: tags['info'] += 1
for k,v in tags.items(): print(f'{k}: {v}')
" 2>/dev/null | tee "$OUTDIR/discovery_severity_breakdown.txt"
```

## Detection Signals
- Template repo outdated (commit older than 72h) — run `nuclei -update-templates` again
- Zero critical CVE templates available — repo clone may be shallow or incomplete
- Template list shows unexpected categories — verify `TEMPLATES_DIR` path
- Critical-only scan produces >0 results — proceed to probe immediately

## Next
├── If template list populated → go to `02-probe.md` for initial scan
├── If template update fails → verify GitHub access, retry with `git clone --depth 1`
├── If no critical findings in quick scan → proceed to medium+ depth in `02-probe.md`