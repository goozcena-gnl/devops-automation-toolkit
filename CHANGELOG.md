# Changelog

All notable changes are documented here. The format follows Keep a Changelog and the project follows semantic versioning.

## [Unreleased]

## [1.0.2] - Unreleased

Release candidate prepared on 2026-10-30. It is not tagged or published; the latest published release remains 1.0.1. Replace `Unreleased` with the release date in the reviewed release commit before the `v1.0.2` tag is created.

### Security

- The shared redactor now masks credentials in structured evidence: quoted, escaped, and Unicode-escaped JSON keys; complete quoted, scalar, object, and array values; private-key blocks inside JSON strings and arrays; and URL userinfo without a password. CI Evidence Collector sanitizes CI metadata, log file names, the `--logs-dir` report target, report copies, and every bundle ZIP member before serialization, with collision-safe sanitized log identities (#57).
- The CLI no longer echoes credential-bearing `--output` or `--bundle` paths unredacted (#57).
- Updated the locked development toolchain for published advisories: uv 0.13.4 (GHSA-hq85-5cpj-mr62) and certifi 2026.10.19 (GHSA-6q48-6c7w-9gw2) (#50); setuptools 84.1.0 (GHSA-xmj3-9gf7-h52w) and filelock 4.2.1 (GHSA-2g95-wg33-c5x2) (#55).
- Added pinned Plumber CI/CD security scanning, an action/binary version-alignment guard, and job-scoped `security-events: write` for its SARIF upload (#13, #39, #40, #58).
- Documented scoped governance for GitHub Actions Guard release-finding waivers; zero findings remains the default release criterion (#51).

### Fixed

- CI Evidence Collector rejects invalid metadata, log identities, or report data before writing a bundle, exits with the existing invalid-input code `2`, and leaves no partial archive (#57).
- Hosted Windows CI accepts Workstation Doctor's documented partial-evidence exit code `5` without masking other failures (#60).
- GitHub Actions Guard type annotations remain strict-mypy clean across PyYAML stub versions without runtime changes (#12).

### Changed

- Added the internal locked toolchain `requirements/dev-constraints.txt`, deterministic drift detection, and grouped coupled Dependabot updates (#15, #32).
- Widened compatible ranges: `rich<16` (runtime), build `setuptools<85`, and development `mypy<3` and `twine<8` (#1, #2, #6, #11).
- Refreshed locked development and CI dependencies, including Pydantic 2.14.1 with pydantic-core 2.50.1, mypy 2.4.0, Ruff 0.17.1, uv 0.13.5, and pinned GitHub Actions updates (#19, #24–#26, #28–#31, #33–#38, #44–#47, #56, #59).
- Added validated GitHub Copilot repository instructions (#41).
- Prepared Python package, native collector, checked-in report example, test, install, and release-process metadata for version 1.0.2 while retaining report schema version `1.0`.

### Validation boundary

- Report schema `1.0`, stable exit codes, the fingerprint algorithm, configuration precedence, and read-only/report-only defaults are unchanged. Redaction coverage uses synthetic credentials and fake-provider fixtures; it is not live-provider validation. Configured redaction-pattern propagation (B03) is not included.

## [1.0.1] - 2026-08-09

### Added

- Fixture-backed report-format evidence and repository social-preview assets, with the existing MIT license surfaced in the README.
- Curated five-tool inspection path and architecture interview walkthrough.

### Changed

- Corrected P0/P1 portfolio maturity and evidence wording without broadening the toolkit's validated scope.
- Aligned current Python package, native collector, checked-in report example, install, and release metadata with version 1.0.1 while retaining report schema version `1.0`.

### Validation boundary

- Tool behavior, stable exit codes, configuration precedence, and read-only/report-only defaults are unchanged; fixture and hosted validation are not presented as live-provider proof.

## [1.0.0] - 2026-07-21

### Added

- Stable CLI, report, finding, configuration, and exit-code contracts for all 20 ranked tools.
- Packaged JSON schemas in the Python wheel.
- Release metadata, documentation-link, catalog, schema-parity, and owner-placeholder contract checks.
- Compatibility matrix, release process, release checklist, and final Phase 7 validation report.
- Reproducible source archive, checksums, wheel, source distribution, and validated tag-build workflow.
- Agent guidance, 20-tool traceability matrix, and one synthetic contract example per tool.
- Hosted actionlint and full-history Gitleaks gates with pinned scanner releases.

### Changed

- Promoted the package from the staged 0.x implementation series to version 1.0.0.
- Split unit/contract coverage from subprocess-heavy integration validation in Makefile, Taskfile, and CI.
- Made the packaged configuration schema the runtime source of truth.
- Updated repository ownership, documentation, catalog wording, and stable-support policy.
- Sanitized checked-in examples and aligned their report metadata with version 1.0.0.

### Fixed

- Added strict validation for Phase 6 tool configuration keys.
- Removed generated `egg-info` metadata from release source archives.
- Corrected stale phase-specific architecture and project-status documentation.
- Repaired the malformed historical changelog structure.
- Made the deterministic source-archive builder independent of an installed package.
- Made the packaged report schema directly usable for offline validation without remote reference resolution.
- Aligned Bash and PowerShell collector report versions with the v1.0.0 package.
- Made Workstation Doctor tolerate inaccessible PATH entries and null-padded WSL output as partial evidence.
- Corrected Windows fake-CLI integration behavior and explicit Linux-only test skipping.
- Resolved ShellCheck export warnings and excluded generated diagnostic reports from source archives.
- Made external command decoding resilient to non-UTF-8 bytes on Windows.
- Applied configured directory exclusions consistently to Git-history secret scans.
- Made source ZIP file permissions derive from canonical Git modes on every host platform.

## [0.6.0] - 2026-07-21

### Added

- Azure and AWS IAM exposure auditing.
- Multi-cloud waste inventory.
- Azure and AWS budget governance.
- Refresh-only Terraform/OpenTofu drift analysis.
- Kubernetes upgrade-readiness analysis.

## [0.5.0] - 2026-07-21

### Added

- Container Image Gate.
- CI Evidence Collector.
- Prometheus Auditor.
- SLO and Error-Budget Calculator.
- Kubernetes Rightsizing Auditor.

## [0.4.0] - 2026-07-21

### Added

- Terraform Plan Risk Analyzer.
- Expanded Linux Incident Snapshot.
- GitHub Repository Baseline.
- Kubeconfig Hygiene.
- TLS Auditor.

## [0.3.0] - 2026-07-21

### Added

- Secret Sentinel.
- Workstation Doctor.
- IaC Repository Gate.
- GitHub Actions Guard.
- Kubernetes Triage.

## [0.2.0] - 2026-07-21

### Added

- Repository foundation and installable Python package.
- Shared finding, reporting, redaction, subprocess, safety, configuration, and policy libraries.
- JSON schemas and console, JSON, Markdown, and SARIF reporters.
- Unit, contract, CI, security, integration, release, and documentation foundations.
