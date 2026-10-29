# Tool traceability and validation matrix

This matrix traces every ranked tool to an implementation, invocation, automated evidence, operator documentation, and a checked-in synthetic or fixture-backed example. “Complete” means the repository surfaces are present and contract-tested; it does not imply live-provider validation.

| Tool | Implementation | CLI | Tests | Documentation | Example | Status |
|---|---|---|---|---|---|---|
| Secret Sentinel | `commands/secret_sentinel.py` | `devops-toolkit secret-sentinel` | unit, CLI, Git-history integration | `docs/tools/secret-sentinel.md` | `examples/reports/phase3/secret-sentinel.json` | Complete |
| Workstation Doctor | `scripts/workstation/devops-workstation-audit.ps1` | PowerShell script | parser, hosted Windows smoke/schema, release contract | `docs/tools/workstation-doctor.md` | `examples/reports/phase3/workstation-doctor.json` | Complete |
| IaC Repository Gate | `commands/iac_repo_gate.py` | `devops-toolkit iac-repo-gate` | unit, CLI, report contract | `docs/tools/iac-repo-gate.md` | `examples/reports/phase3/iac-repo-gate.json` | Complete |
| GitHub Actions Guard | `commands/gha_guard.py` | `devops-toolkit gha-guard` | unit, CLI, self-audit | `docs/tools/gha-guard.md` | `examples/reports/phase3/gha-guard.sarif` | Complete |
| Kubernetes Triage | `commands/kube_triage.py` | `devops-toolkit kube-triage` | unit, CLI, fake-kubectl integration | `docs/tools/kube-triage.md` | `examples/reports/phase3/kube-triage.json` | Complete |
| Terraform Plan Risk Analyzer | `commands/plan_risk.py` | `devops-toolkit plan-risk` | unit, CLI, report contract | `docs/tools/plan-risk.md` | `examples/reports/phase4/plan-risk.json` | Complete |
| Linux Incident Snapshot | `scripts/linux/linux-triage.sh` | Bash script | syntax, ShellCheck, Linux integration/schema | `docs/tools/linux-triage.md` | `examples/reports/phase4/linux-triage.json` | Complete |
| GitHub Repository Baseline | `commands/repo_baseline.py` | `devops-toolkit repo-baseline` | unit, CLI, report contract | `docs/tools/repo-baseline.md` | `examples/reports/phase4/repo-baseline.json` | Complete |
| Kubeconfig Hygiene | `commands/kubeconfig_hygiene.py` | `devops-toolkit kubeconfig-hygiene` | unit, CLI, report contract | `docs/tools/kubeconfig-hygiene.md` | `examples/reports/phase4/kubeconfig-hygiene.json` | Complete |
| TLS Auditor | `commands/tls_audit.py` | `devops-toolkit tls-audit` | unit, CLI, local TLS behavior | `docs/tools/tls-audit.md` | `examples/reports/phase4/tls-audit.json` | Complete |
| Container Image Gate | `commands/image_gate.py` | `devops-toolkit image-gate` | unit, CLI, report contract | `docs/tools/image-gate.md` | `examples/reports/phase5/image-gate.json` | Complete |
| CI Evidence Collector | `commands/ci_evidence.py` | `devops-toolkit ci-evidence` | unit, structured-secret and provider-punctuation CLI/archive regression, stable collision references, report contract | `docs/tools/ci-evidence.md` | `examples/reports/phase5/ci-evidence.json` | Complete |
| Prometheus Auditor | `commands/prom_audit.py` | `devops-toolkit prom-audit` | unit, CLI, report contract | `docs/tools/prom-audit.md` | `examples/reports/phase5/prom-audit.json` | Complete |
| SLO and Error-Budget Calculator | `commands/slo_budget.py` | `devops-toolkit slo-budget` | unit, CLI, report contract | `docs/tools/slo-budget.md` | `examples/reports/phase5/slo-budget.json` | Complete |
| Kubernetes Rightsizing Auditor | `commands/kube_rightsize.py` | `devops-toolkit kube-rightsize` | unit, CLI, report contract | `docs/tools/kube-rightsize.md` | `examples/reports/phase5/kube-rightsize.json` | Complete |
| Cloud IAM Exposure Auditor | `commands/cloud_iam_audit.py` | `devops-toolkit cloud-iam-audit` | unit, CLI, report contract | `docs/tools/cloud-iam-audit.md` | `examples/reports/phase6/cloud-iam-audit.json` | Complete |
| Cloud Waste Inventory | `commands/cloud_waste.py` | `devops-toolkit cloud-waste` | unit, CLI, report contract | `docs/tools/cloud-waste.md` | `examples/reports/phase6/cloud-waste.json` | Complete |
| Cloud Budget Guard | `commands/budget_guard.py` | `devops-toolkit budget-guard` | unit, CLI, report contract | `docs/tools/budget-guard.md` | `examples/reports/phase6/budget-guard.json` | Complete |
| IaC Drift Guard | `commands/iac_drift_guard.py` | `devops-toolkit iac-drift-guard` | unit, CLI, report contract | `docs/tools/iac-drift-guard.md` | `examples/reports/phase6/iac-drift-guard.json` | Complete |
| Kubernetes Upgrade Readiness | `commands/kube_upgrade_readiness.py` | `devops-toolkit kube-upgrade-readiness` | unit, CLI, report contract | `docs/tools/kube-upgrade-readiness.md` | `examples/reports/phase6/kube-upgrade-readiness.json` | Complete |

## Evidence boundary

The Python analyzers, schema/report contracts, synthetic fixtures, fake CLI integrations, local Windows Python behavior, and native parser checks are deterministic release evidence. Hosted Ubuntu executes the Bash collector and ShellCheck; hosted Windows executes Workstation Doctor and PSScriptAnalyzer. Azure, AWS, private GitHub, production Kubernetes, Terraform/OpenTofu backends, enterprise Prometheus, private registries, and enterprise TLS remain target-environment validations.

## B02 security and evidence regressions

`tests/integration/test_ci_evidence_redaction.py::test_ten_review_discussions_end_to_end`
parameterizes the ten credential/collision/metadata review discussions across console,
JSON, Markdown and SARIF, stdout and file output, and actual ZIP writes. Existing
structured, shell-segment, punctuation, malformed-prefix, metadata-key-collision,
path-component and schema/fingerprint regressions remain in their unit, contract
and integration suites.

Raw direct-bundle references, case-insensitive collisions, ancestor conflicts,
insertion-order independence and repeated sanitization are exercised by
`test_raw_bundle_references_share_archive_filename_mapping`. Metadata normalization
errors are covered at build, provider and direct-bundle boundaries, with real CLI
subprocess coverage for non-finite numbers, excessive/parser-depth nesting, valid
depth 64, and mocked `gh` responses. Cycles fail closed and unsupported objects
retain the safe replacement fallback. All `splitlines()` separators are covered by
`test_every_splitlines_boundary_survives_credential_masking` and
`test_cli_preserves_all_original_evidence_line_boundaries`.
These are synthetic local/fake-provider tests, not live GitHub-provider validation.
