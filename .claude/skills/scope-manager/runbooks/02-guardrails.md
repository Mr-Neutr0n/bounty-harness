# Workflow: Scope Guardrails

## Purpose
Prevent accidental out-of-scope testing by validating URLs and requests before execution.

## Execution
```bash
# Validate a single URL
bin/bb-run scope-manager validate-url
# (set VALIDATE_URL=https://api.example.com/v1/users in context)

# Guard an HTTP request file
bin/bb-run scope-manager guard-request
# (set REQUEST_FILE=/path/to/request.txt in context)
```

## What It Does
1. Parses the scope file for in-scope and out-of-scope patterns
2. Compiles patterns into regex matchers
3. Checks if URL/request matches any pattern
4. Returns allowed/disallowed status with reason

## Exit Codes
- 0: URL/request is in scope
- 1: URL/request is out of scope

## Integration Example
```bash
# In a wrapper script
if bin/bb-run scope-manager guard-request; then
    bin/bb-run api bola-idor
else
    echo "Skipping out-of-scope request"
fi
```

## Next Steps
- Integrate `guard-request` into custom wrapper scripts
- Use `track-scope` before each session
