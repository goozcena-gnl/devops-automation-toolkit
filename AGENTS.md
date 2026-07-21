# Agent guide

This repository contains 18 Python commands plus one Bash and one PowerShell collector. Preserve the deterministic, report-first architecture and the read-only default.

## Architecture

- `src/devops_toolkit/cli.py` defines the installed `devops-toolkit` CLI.
- `src/devops_toolkit/commands/` contains tool-specific collection and analysis.
- `src/devops_toolkit/core/` owns configuration, safety, redaction, subprocess, filesystem, finding, and exit-code contracts.
- `src/devops_toolkit/reporters/` renders console, JSON, Markdown, and SARIF output.
- `src/devops_toolkit/resources/schemas/` is packaged data; it must remain byte-for-byte equivalent to `configs/schemas/`.
- `scripts/linux/` and `scripts/workstation/` contain the native collectors.
- `tests/unit`, `tests/contract`, and `tests/integration` are intentionally separate. Integration tests run without inherited coverage instrumentation.

## Validation commands

```bash
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy src
pytest tests/unit tests/contract
pytest -m integration --no-cov
bandit -q -c pyproject.toml -r src
python tools/validate_examples.py
python tools/validate_reports.py
python tools/check_docs.py
python -m build
python -m twine check dist/*
```

Use `make validate` on a POSIX development host. Windows contributors should run the Python gates plus the PowerShell parser and PSScriptAnalyzer; the Linux collector is exercised by Ubuntu CI.

## Non-negotiable constraints

- Do not add cloud, Kubernetes, GitHub, or IaC mutation as a default behavior.
- Never use `shell=True`, interpolate untrusted command strings, serialize credentials, or log unredacted provider output.
- Bound external calls by timeout and output size. Mark incomplete evidence as partial.
- Keep report schema version `1.0`, stable exit codes, finding fingerprints, and configuration precedence compatible unless a documented breaking release changes them.
- Configuration precedence is defaults, then ordered `--config` files, then explicit CLI flags.
- Treat `docs/generated-catalog.md`, built distributions, coverage data, caches, and release archives as generated. Commit only the generated catalog.
- Keep Python, Bash, PowerShell, package, and report metadata versions aligned with `pyproject.toml`.

## Adding or changing a tool

Update the implementation, CLI or native entry point, `catalog.py`, schema-backed configuration, unit tests, contract/integration evidence, `docs/tools/<tool>.md`, `docs/script-catalog.md`, the traceability matrix, and a synthetic example report. Run the self-audits before proposing the change.

Do not weaken thresholds, delete meaningful tests, describe fixtures as live-provider validation, commit diagnostic bundles, or substitute a superficial wrapper for a validated analyzer.
