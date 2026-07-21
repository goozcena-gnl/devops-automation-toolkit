# Phase 7 validation report

## Release candidate

- Project: `devops-automation-toolkit`
- Version: `1.0.0`
- Date: 2026-07-21
- Scope: cross-tool consistency, portability, dependency, security, failure-mode, documentation, packaging, and GitHub release-readiness review

## Outcome

Version 1.0.0 establishes the stable CLI, schema, report, finding, and exit-code contracts for the complete 20-tool portfolio.

The repository is suitable as a **release candidate**. Publication should occur only after the network-enabled dependency audit and GitHub-hosted Windows job pass for the release commit. Those checks are configured but could not be completed in the local Linux environment.

## Release corrections

### Configuration consistency

The Phase 7 audit found that the repository JSON schema contained strict Phase 6 tool settings, while the runtime Python schema did not. Phase 6 configuration objects were therefore accepted but their individual keys were not validated as strictly as earlier tools.

Resolution:

- JSON schemas are now packaged inside the wheel;
- the packaged toolkit schema is the runtime source of truth;
- repository and packaged schemas are contract-tested for parity;
- an invalid Phase 6 configuration-key regression test was added.

### Offline package and release construction

Clean-install validation identified two packaging defects before final artifact creation:

- the complete-source archive builder imported the package and therefore failed from an uninstalled checkout;
- the packaged report schema used a relative finding-schema reference anchored to a placeholder URI, which caused an attempted network lookup during direct offline validation.

Resolution:

- the archive builder now reads `project.version` directly from `pyproject.toml` using the Python standard library;
- the report schema embeds the finding contract under `$defs` and validates without a custom registry or network access;
- standalone packaged-schema validation is covered by a release contract test.

### Test execution consistency

The release Makefile previously ran all tests under the default coverage instrumentation even though subprocess-heavy integration tests were intentionally validated separately in earlier phases.

Resolution:

- unit and contract tests run with coverage;
- integration tests run separately with `--no-cov`;
- Makefile, Taskfile, integration workflow, release workflow, and testing documentation use the same split.

### Repository and documentation consistency

The audit also corrected:

- placeholder CODEOWNERS entries;
- stale “planned” and phase-specific catalog wording;
- outdated architecture and project-status text;
- malformed historical changelog sections;
- stable-version support policy;
- missing compatibility and release-process documentation;
- generated `egg-info` material in the source workspace;
- package metadata and schema inclusion.

## Validation matrix

| Check | Result |
|---|---|
| Ruff formatting | Passed |
| Ruff linting | Passed |
| Strict mypy | Passed across 63 source files |
| Unit and contract tests | 109 passed |
| Unit/contract coverage | 66% |
| Isolated integration tests | 4 passed |
| Total tests exercised | 113 passed |
| Bandit | Passed |
| Python compilation | Passed |
| Installed dependency consistency | `pip check` passed |
| Runtime configuration examples | Passed |
| Report contracts | 19 JSON reports and 2 SARIF reports passed |
| Packaged/repository schema parity | Passed |
| Catalog completeness | 20 unique tools with documentation |
| Malformed-input regression tests | Controlled exit code 2, no traceback |
| Missing-dependency regression tests | Controlled exit code 3, no traceback |
| Bash syntax | Passed |
| Native Linux collector | Executed and produced schema-valid JSON and a sanitized ZIP |
| Source Secret Sentinel audit | 0 findings |
| Native-script Secret Sentinel audit | 0 findings |
| GitHub Actions Guard self-audit | 0 findings |
| Documentation links | Passed |
| Wheel and source distribution | Passed |
| Package metadata (`twine check`) | Passed |
| Clean wheel installation | Passed |
| Packaged schema presence | Passed |
| Deterministic complete-source ZIP | Passed |
| SHA-256 checksums | Generated |

## Dependency review

Runtime dependencies remain constrained to compatible major versions:

- `jsonschema>=4.23,<5`;
- `pydantic>=2.11,<3`;
- `PyYAML>=6.0,<7`;
- `rich>=13.9,<15`;
- `typer>=0.16,<1`.

The clean development environment resolved compatible versions and `pip check` reported no broken requirements.

`pip-audit` was installed and invoked twice, but the local container could not resolve `pypi.org`; therefore no local vulnerability result is claimed. The scheduled and pull-request security workflow retains `pip-audit --progress-spinner off` and must pass in a network-enabled GitHub runner before publication.

The project intentionally avoids a runtime lock file because it is distributed as a Python library with compatible dependency ranges. Release artifacts and CI environments remain reproducible through bounded project constraints, immutable action pins, package checks, and checksums rather than by forcing application-style transitive pins on consumers.

## GitHub Actions review

All referenced repository actions remain pinned to 40-character commit SHAs. The comments correspond to official releases checked on 2026-07-21:

- `actions/checkout` v7.0.1;
- `actions/setup-python` v7.0.0;
- `actions/upload-artifact` v7.0.1.

Workflow permissions default to `contents: read`. The tag workflow builds and uploads validated release assets but does not grant automatic release-publication write access. Publishing the GitHub Release remains a separately approved step.

## Failure-mode review

Representative malformed Terraform, GitHub, kubeconfig, Trivy, Prometheus, Kubernetes, cloud, budget, drift, and upgrade snapshots were exercised. They:

- returned exit code 2;
- emitted a bounded actionable error;
- did not print Python tracebacks.

Representative missing `trivy`, `gh`, and `kubectl` paths were exercised. They:

- returned exit code 3;
- identified the unavailable executable;
- did not fall through to an internal-error exit.

Production-blocking and policy-threshold exit codes remain covered by the existing safety and CLI suites.

## Portability review

### Locally exercised

- CPython 3.13 on Linux;
- Python CLI unit and contract behavior;
- isolated subprocess-heavy integration tests;
- Bash syntax and Linux collector execution;
- clean wheel installation;
- local file, Git, fake `kubectl`, and TLS integration paths.

### Configured but not locally exercised

- CPython 3.11 and 3.12 GitHub-hosted matrix jobs;
- Windows Python matrix;
- PowerShell parser, PSScriptAnalyzer, native collector execution, and report-schema validation;
- ShellCheck on a GitHub-hosted Ubuntu runner.

### Target-environment validation still required

- authenticated private GitHub repositories and organizations;
- live Azure subscriptions and AWS accounts;
- production Terraform/OpenTofu backends and state;
- production Kubernetes clusters and distribution-specific add-ons;
- enterprise Prometheus authentication and PKI;
- private registries and signature infrastructure;
- enterprise mutual-TLS endpoints.

## Packaging review

The wheel contains:

- all Python command, core, policy, reporter, and adapter modules;
- the `devops-toolkit` console entry point;
- the four versioned JSON schemas;
- package metadata and MIT license.

The complete source ZIP additionally contains native Bash and PowerShell collectors, documentation, examples, fixtures, tests, workflows, and release evidence.

Generated virtual environments, build outputs, caches, coverage data, and `egg-info` directories are excluded from the complete source ZIP.

## Publication gates

Before creating the public `v1.0.0` GitHub Release:

1. push the exact release candidate commit;
2. confirm the Linux/Windows Python matrix passes;
3. confirm the Windows PowerShell job passes;
4. confirm ShellCheck passes;
5. confirm the network-enabled `pip-audit` job passes;
6. download the validated tag-workflow artifacts;
7. compare their SHA-256 checksums;
8. create the GitHub Release through an approved manual or release-management step.

## Final assessment

Phase 7 is complete as a local release-readiness review. No unresolved deterministic code, schema, documentation, self-audit, packaging, or local integration failure remains.

The release is intentionally classified as a release candidate until the external dependency service and GitHub-hosted Windows checks run successfully. Live-provider compatibility remains environment-specific and is not inferred from fixture-backed tests.
