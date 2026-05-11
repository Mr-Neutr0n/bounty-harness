# Workflow: Validate URL

## Purpose
Quickly check if a specific URL is within scope before testing.

## Execution
```bash
export VALIDATE_URL=https://api.example.com/v1/users
bin/bb-run scope-manager validate-url
```

## What It Does
1. Parses the scope file for in-scope and out-of-scope patterns
2. Checks if the URL matches any pattern
3. Returns allowed/disallowed status with reason

## Exit Codes
- 0: URL is in scope
- 1: URL is out of scope

## Integration
Use in wrapper scripts before sending requests:
```bash
if bin/bb-run scope-manager validate-url; then
    curl -s "$VALIDATE_URL"
else
    echo "Skipping out-of-scope URL"
fi
```
