# Testing strategy

## Test classes

- **Unit tests:** detectors, analysis rules, sanitization, policy, serialization,
  safety, and CLI behavior.
- **Contract tests:** JSON schemas and stable report interfaces for all implemented
  Python tools.
- **Integration tests:** native Linux collection, bounded Git-history scanning,
  Kubernetes collection through a disposable fake `kubectl`, and local TLS smoke testing during release validation.
- **Security regression tests:** synthetic invalid tokens, private-key markers,
  redaction, shell argument handling, and bundle sanitization.
- **Self-audits:** Secret Sentinel scans toolkit source/native scripts and GitHub
  Actions Guard audits the repository workflows.
- **Packaging tests:** wheel/sdist build, metadata check, packaged-schema inspection, and clean virtual-environment install.
- **Release contracts:** version parity, 20-tool catalog completeness, documentation ownership, and repository/package schema parity.

## Evidence boundaries

Mocked and fixture-backed tests validate deterministic behavior but do not prove
compatibility with every real provider version. The validation report explicitly
separates:

- behavior exercised locally;
- behavior parsed or statically analyzed;
- behavior delegated to GitHub-hosted Windows CI;
- behavior requiring a real Kubernetes or workstation environment.

## Commands

```bash
pytest tests/unit tests/contract
pytest -m integration --no-cov
pytest -m contract
python tools/check_docs.py
make self-audit
make validate
```

Tests use invalid synthetic credentials only. No long-lived cloud or cluster
credentials are required.

On Windows, the fake `kubectl`, module-entrypoint, and Git-history integration paths run natively. The Bash collector test is explicitly skipped and remains mandatory on the hosted Ubuntu integration job; a platform skip is not reported as a pass.

## Locked dependency updates

Development and CI installs use `requirements/dev-constraints.txt` through
`PIP_CONSTRAINT`. Keep exact pins and platform markers when updating dependencies.
Dependabot groups mypy with its `librt` and `ast-serialize` runtime dependencies,
and Pydantic with `pydantic-core`, whose version must match Pydantic's metadata.
Grouping reduces split updates; it does not guarantee that every transitive pin
will be refreshed or that the resulting graph is installable.

After an update, install with the committed constraints and run
`python tools/check_dev_constraints.py check` using the pinned uv version. If a
new requirement conflicts with another pin, inspect the package metadata and
update only the affected dependency closure. Do not remove constraints or
regenerate unrelated pins to make installation pass. The offline integration
tests cover incompatible direct/transitive pins and preservation of compatible
pins after upstream releases.

Require the Ubuntu and Windows Python 3.11–3.13 matrix, integration and security
checks on the final PR HEAD. After combining dependency PRs, validate the combined
graph again; individually passing checks do not establish combined compatibility.
