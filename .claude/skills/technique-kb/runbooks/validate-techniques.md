# How to Validate Techniques

## Quick validate (all files)

```bash
python3 .claude/skills/technique-kb/scripts/technique_validator.py \
  --techniques-dir .claude/skills/technique-kb/techniques \
  --schema .claude/skills/technique-kb/technique_schema.yaml
```

## Expected output

```
[PASS] xss/reflected_get.yaml
[PASS] xss/stored.yaml
...
--- Summary: N passed, 0 failed, N total ---
```

## On failure

If a file fails validation, the validator prints the specific error:

```
[FAIL] xss/broken.yaml
        Validation error at applies_to.surfaces: [] is too short
```

Fix the technique YAML file, then re-run the validator.

## Schema check

To check the schema itself is valid YAML:

```bash
python3 -c "import yaml; yaml.safe_load(open('.claude/skills/technique-kb/technique_schema.yaml'))"
```

## Common validation errors

| Error | Fix |
|---|---|
| `is required` | Add the missing required key |
| `is not of type` | Check the value type (string vs array vs boolean) |
| `is not one of enum values` | Category or severity doesn't match allowed values |
| `YAML parse error` | Fix YAML syntax (indentation, quotes, colons) |
| `is too short` | Array fields need at least one item |
| `does not match pattern` | ID must be lowercase with hyphens only |
