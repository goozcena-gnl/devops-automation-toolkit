# Changelog

All notable changes are documented here. The format follows Keep a Changelog and the project follows semantic versioning.

## [Unreleased]

### Added

- Curated five-tool inspection path and architecture interview walkthrough.

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
