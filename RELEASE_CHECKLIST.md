# Release checklist

## Code and contracts

- [ ] Version metadata is consistent.
- [ ] The catalog contains 20 unique documented tools.
- [ ] Packaged and repository JSON schemas match.
- [ ] Configuration examples validate.
- [ ] Checked-in JSON and SARIF reports validate.
- [ ] No owner placeholders or generated package metadata remain.

## Quality and security

- [ ] Ruff format and lint pass.
- [ ] Strict mypy passes.
- [ ] Unit and contract tests pass with coverage.
- [ ] Integration tests pass separately without inherited coverage.
- [ ] Bandit passes.
- [ ] Dependency audit passes in a network-enabled CI environment.
- [ ] Secret Sentinel reports zero source/native-script findings.
- [ ] GitHub Actions Guard reports zero workflow findings.
- [ ] Bash syntax and ShellCheck pass.
- [ ] PowerShell parser and PSScriptAnalyzer pass in Windows CI.

## Packaging

- [ ] Wheel and source distribution build.
- [ ] `twine check` passes.
- [ ] Wheel installs in a clean supported Python environment.
- [ ] Packaged schemas are present in the wheel.
- [ ] Complete source ZIP builds reproducibly.
- [ ] SHA-256 checksums are generated.

## Release

- [ ] Changelog entry is dated.
- [ ] Documentation links pass.
- [ ] Known limitations are explicit.
- [ ] Tag matches package version.
- [ ] GitHub Release assets are attached.
