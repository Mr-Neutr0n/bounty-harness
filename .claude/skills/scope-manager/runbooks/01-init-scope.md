# Workflow: Initialize Scope

## Purpose
Generate a structured, commented scope file for a new bug bounty engagement.

## Execution
```bash
bin/bb-run scope-manager init-scope
```

## What It Does
1. Creates `$OUTDIR/scope/scope.txt`
2. Adds target domain and wildcard subdomains
3. Adds common API and mobile app placeholders
4. Includes out-of-scope section if provided
5. Adds safety notes and comments

## Customization
Edit the generated file to add:
- Specific out-of-scope endpoints
- Rate limits or testing constraints
- Special instructions from the program

## Next Steps
- Edit `$OUTDIR/scope/scope.txt` manually for program-specific details
- Run `track-scope` to save baseline
- Use `validate-url` before testing any endpoint
