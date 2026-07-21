# DevOps Automation Toolkit

A deterministic, report-first toolkit for Cloud, DevOps, SRE, DevSecOps, Kubernetes, infrastructure as code, CI/CD, observability, and FinOps workflows.

Version **1.0.0** provides the complete ranked set of 20 tools: 18 Python commands exposed through one installable CLI, one native Bash incident collector, and one native PowerShell workstation auditor.

**Project status:** release candidate. Local deterministic gates pass; public release remains draft until the GitHub-hosted Linux, Windows, PowerShell, ShellCheck, actionlint, Gitleaks, and dependency-audit jobs pass for the release commit.

## Design principles

- Read-only or report-only behavior by default.
- No cloud deletion, IAM mutation, Terraform/OpenTofu apply, state unlock, Kubernetes upgrade, or workload patch is implemented.
- Credentials are obtained from existing CLI credential chains, OIDC, managed identities, or local configuration and are never persisted by the toolkit.
- Findings use a shared severity, confidence, evidence, fingerprint, and remediation model.
- Sensitive values are redacted before serialization.
- External calls have bounded timeouts and output limits.
- Fixture and snapshot modes support deterministic CI testing without live credentials.
- No command requires an LLM.

## Architecture overview

The installed CLI routes each command to a narrow collector/analyzer module. Shared core libraries enforce configuration precedence, safety policy, redaction, bounded subprocess execution, findings, fingerprints, and exit codes. Reporters serialize the same model to console, JSON, Markdown, or SARIF. JSON Schemas are stored in the repository and packaged in the wheel for offline validation. The Bash and PowerShell collectors emit the same report contract without importing the Python package.

See [`docs/architecture.md`](docs/architecture.md), [`docs/finding-model.md`](docs/finding-model.md), and the complete [`tool traceability matrix`](docs/validation-matrix.md).

## Installation

### With `uv`

```bash
uv tool install .
devops-toolkit version
```

For development, use `uv venv` and then `uv pip install -e '.[dev]'`.

### With `pipx`

```bash
pipx install .
devops-toolkit health
```

### With a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\Activate.ps1      # Windows PowerShell
python -m pip install -e '.[dev]'
devops-toolkit version
```

### From a built wheel

```bash
python -m pip install devops_automation_toolkit-1.0.0-py3-none-any.whl
devops-toolkit health
```

The wheel contains the Python CLI and versioned JSON schemas. The native Bash and PowerShell collectors are distributed in the complete repository archive.

Checked-in reports under `examples/reports/` are synthetic or fixture-backed contract examples. They are not live assessments of a cloud account, cluster, workstation, or host.

## Tool catalog

| Rank | Tool | Entry point | Language | Primary use |
|---:|---|---|---|---|
| 1 | Secret Sentinel | `devops-toolkit secret-sentinel` | Python | Files and bounded Git-history secret detection |
| 2 | Workstation Doctor | `scripts/workstation/devops-workstation-audit.ps1` | PowerShell | Windows, WSL, Git, SSH, Docker, cloud CLI, and kubeconfig readiness |
| 3 | IaC Repository Gate | `devops-toolkit iac-repo-gate` | Python | Terraform/OpenTofu, YAML, Helm, and Ansible quality gate |
| 4 | GitHub Actions Guard | `devops-toolkit gha-guard` | Python | Workflow security and reliability audit |
| 5 | Kubernetes Triage | `devops-toolkit kube-triage` | Python | Sanitized Kubernetes incident evidence |
| 6 | Plan Risk Analyzer | `devops-toolkit plan-risk` | Python | Terraform/OpenTofu plan JSON risk analysis |
| 7 | Linux Incident Snapshot | `scripts/linux/linux-triage.sh` | Bash | Bounded Linux host diagnostics and support bundle |
| 8 | Repository Baseline | `devops-toolkit repo-baseline` | Python | GitHub governance and protection baseline |
| 9 | Kubeconfig Hygiene | `devops-toolkit kubeconfig-hygiene` | Python | Local Kubernetes credential and TLS hygiene |
| 10 | TLS Auditor | `devops-toolkit tls-audit` | Python | Trust, hostname, protocol, and expiry checks |
| 11 | Container Image Gate | `devops-toolkit image-gate` | Python | Trivy normalization, SBOM, and optional signature policy |
| 12 | CI Evidence Collector | `devops-toolkit ci-evidence` | Python | Sanitized CI failure evidence and signatures |
| 13 | Prometheus Auditor | `devops-toolkit prom-audit` | Python | Targets, rules, alerts, and promtool checks |
| 14 | SLO Budget Calculator | `devops-toolkit slo-budget` | Python | SLI compliance, error budget, and burn rates |
| 15 | Kubernetes Rightsizing | `devops-toolkit kube-rightsize` | Python | Requests/limits analysis against current usage |
| 16 | Cloud IAM Auditor | `devops-toolkit cloud-iam-audit` | Python | Azure and AWS identity exposure |
| 17 | Cloud Waste Inventory | `devops-toolkit cloud-waste` | Python | Evidence-based unused-resource inventory |
| 18 | Cloud Budget Guard | `devops-toolkit budget-guard` | Python | Budgets, alerts, forecasts, and cost anomalies |
| 19 | IaC Drift Guard | `devops-toolkit iac-drift-guard` | Python | Refresh-only Terraform/OpenTofu drift detection |
| 20 | Kubernetes Upgrade Readiness | `devops-toolkit kube-upgrade-readiness` | Python | Version skew, removed APIs, drain and add-on readiness |

Detailed permissions, examples, limitations, and failure modes are in [`docs/script-catalog.md`](docs/script-catalog.md) and [`docs/tools/`](docs/tools/).

## Typical commands

```bash
# Audit a repository without modifying it
devops-toolkit secret-sentinel . --format sarif --output secrets.sarif
devops-toolkit iac-repo-gate . --format json --output iac-report.json
devops-toolkit gha-guard . --format sarif --output workflows.sarif

# Analyze exported evidence
devops-toolkit plan-risk tfplan.json --format markdown --output plan-risk.md
devops-toolkit repo-baseline --snapshot github-baseline.json
devops-toolkit cloud-waste --provider aws --snapshot aws-inventory.json

# Use explicitly scoped live read-only collection
devops-toolkit kube-triage --context staging --namespace payments
devops-toolkit prom-audit --url https://prometheus.example.com
devops-toolkit kube-upgrade-readiness --target-version 1.33.0 --context staging
```

Run `devops-toolkit COMMAND --help` for each complete interface.

## Reports and exit codes

Python analyzers support console, JSON, Markdown, and SARIF where the format is meaningful. Native host collectors emit schema-valid JSON and optional sanitized archives.

| Code | Meaning |
|---:|---|
| 0 | Successful execution with no configured threshold violation |
| 1 | Findings exceeded the configured threshold |
| 2 | Invalid arguments, input, or configuration |
| 3 | Required dependency unavailable |
| 4 | Authentication or authorization failure |
| 5 | Partial collection or incomplete evidence |
| 6 | Unexpected internal failure |
| 7 | Safety policy blocked execution |

## Development and validation

```bash
make validate
make build
python tools/check_docs.py
```

`make validate` runs formatting and lint checks, strict type checking, unit and contract tests with coverage, isolated subprocess-heavy integration tests without inherited coverage, Bandit, configuration and report contracts, native syntax checks, documentation checks, and repository self-audits.

See:

- [`PHASE7_VALIDATION.md`](PHASE7_VALIDATION.md) for the final release evidence;
- [`docs/validation-matrix.md`](docs/validation-matrix.md) for 20-tool implementation, test, documentation, and example traceability;
- [`docs/testing.md`](docs/testing.md) for the test strategy;
- [`docs/compatibility.md`](docs/compatibility.md) for supported and unproven environments;
- [`SECURITY.md`](SECURITY.md) for vulnerability reporting and security invariants;
- [`docs/release-process.md`](docs/release-process.md) for the tag and release workflow.

## Validation boundary

The deterministic analysis engines, schemas, package installation, fixtures, fake CLI integrations, local Linux collector, and local TLS behavior are tested. Live Azure, AWS, private GitHub, enterprise Prometheus, production Terraform/OpenTofu state, production Kubernetes clusters, and the native PowerShell collector require validation in the target environment before operational adoption.

A clean static audit or fixture-backed result is not proof that a production environment is safe.

Contributions follow [`CONTRIBUTING.md`](CONTRIBUTING.md). Release construction and approval gates are documented in [`docs/release-process.md`](docs/release-process.md), and security reports follow [`SECURITY.md`](SECURITY.md).
