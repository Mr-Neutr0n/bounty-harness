.PHONY: init validate test clean audit secrets release-check doctor

init:
	@echo "Run: bin/bb-init <target>"

validate:
	python3 tools/validate_skills.py

test:
	@status=0; \
	for skill in $$(ls .claude/skills/); do \
		echo "--- Testing $$skill ---"; \
		python3 -c "import yaml; yaml.safe_load(open('.claude/skills/$$skill/skill.yaml'))" 2>/dev/null && echo "  skill.yaml OK" || { echo "  skill.yaml FAIL"; status=1; }; \
		for script in .claude/skills/$$skill/scripts/*.py; do \
			[ -f "$$script" ] && python3 -m py_compile "$$script" 2>/dev/null && echo "  $$script OK" || { echo "  $$script FAIL"; status=1; }; \
		done; \
	done; \
	exit $$status

clean:
	rm -rf output/test-* output/quality_report.json

audit:
	python3 tools/validate_skills.py audit-workflows
	python3 tools/validate_skills.py audit-security

secrets:
	gitleaks detect --source . --no-git -v

release-check: test validate secrets
	python3 tools/validate_skills.py audit-release
	@echo "=== Release gate passed ==="

doctor:
	bin/bb-tools doctor