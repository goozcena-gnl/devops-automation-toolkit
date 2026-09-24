# Development

Install the package in editable mode with development dependencies:

```bash
export PIP_CONSTRAINT="$PWD/requirements/dev-constraints.txt"
python -m pip install -e '.[dev]'
make validate
```

In Windows PowerShell, set `$env:PIP_CONSTRAINT = (Resolve-Path 'requirements/dev-constraints.txt')` before installing.

Regenerate the checked-in CI/dev/release constraints lock with:

```bash
make lock
```

This calls `tools/check_dev_constraints.py generate`, which uses the pinned `uv`
resolver to produce a universal lock anchored at Python 3.11. Python- and
platform-specific dependencies retain their environment markers, so the same file
covers Python 3.11, 3.12, and 3.13 on Linux and Windows. After changing the
dependency ranges or resolver version, review and commit the generated lock.

Verify that `pyproject.toml` and `requirements/dev-constraints.txt` still resolve to the committed locked environment with:

```bash
make lock-check
```

The check resolves into a temporary file and compares every pinned requirement
against the committed lock. It does not write tracked files. On Windows, use
`python tools/check_dev_constraints.py generate` or `python tools/check_dev_constraints.py check`.

## Adding a finding rule

1. Use a stable uppercase finding identifier.
2. Store only bounded, sanitized evidence.
3. Assign severity and confidence independently.
4. Provide a concrete remediation.
5. Add a positive fixture, negative fixture, and schema-contract test.
6. Confirm JSON, Markdown, console, and SARIF rendering where applicable.

## Adding an external executable

Use the shared subprocess runner and document:

- executable discovery;
- command arguments;
- minimum expected capability;
- timeout and output limits;
- whether missing availability is partial or optional;
- required permissions;
- how output is sanitized;
- a disposable integration-test strategy.

Do not use `shell=True`, concatenate untrusted shell strings, or add an automatic
remediation mode without a separate safety design.

## Native scripts

Bash must pass syntax validation and ShellCheck where available. PowerShell must
parse under PowerShell 7 and pass PSScriptAnalyzer in Windows CI. Native scripts
must preserve the common report and exit-code contracts.

## Release-impacting changes

Changes to configuration, findings, reports, command names, or exit codes require contract tests and a changelog entry. Run `python tools/check_docs.py` and verify `python -m twine check dist/*` before proposing a release.
