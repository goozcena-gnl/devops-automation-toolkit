.PHONY: install-dev format lint typecheck test test-unit test-integration security dependency-audit self-audit native-validate docs-check contracts validate build catalog clean

install-dev:
	python -m pip install -e '.[dev]'

format:
	ruff format .
	ruff check --fix .

lint:
	ruff format --check .
	ruff check .

typecheck:
	mypy src

test-unit:
	pytest tests/unit tests/contract

test-integration:
	pytest -m integration --no-cov

test: test-unit test-integration

security:
	bandit -q -c pyproject.toml -r src

dependency-audit:
	pip-audit --progress-spinner off

self-audit:
	devops-toolkit secret-sentinel src --format json --output reports/self-audit/secret-source.json
	devops-toolkit secret-sentinel scripts --format json --output reports/self-audit/secret-scripts.json
	devops-toolkit gha-guard . --format json --output reports/self-audit/gha-guard.json

native-validate:
	bash -n scripts/linux/linux-triage.sh
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck scripts/linux/linux-triage.sh; else echo "ShellCheck unavailable; Linux CI performs validation"; fi
	@if command -v pwsh >/dev/null 2>&1; then \
		pwsh -NoProfile -Command '$$tokens = $$null; $$errors = $$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path "scripts/workstation/devops-workstation-audit.ps1"), [ref]$$tokens, [ref]$$errors) | Out-Null; if ($$errors.Count -gt 0) { $$errors | ForEach-Object { Write-Error $$_.Message }; exit 1 }'; \
	else \
		echo "PowerShell runtime unavailable; Windows CI performs parser and PSScriptAnalyzer validation"; \
	fi

docs-check:
	python tools/check_docs.py
	python tools/generate_catalog.py
	@if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then git diff --exit-code docs/generated-catalog.md; fi

contracts:
	python tools/validate_examples.py
	python tools/validate_reports.py

validate: lint typecheck test security contracts native-validate docs-check self-audit

build:
	python -m build
	python -m twine check dist/*
	python tools/build_release.py

catalog:
	python tools/generate_catalog.py

clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
