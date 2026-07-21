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
