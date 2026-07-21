# Script catalog

| Rank | ID | Entry point | Status | Primary dependencies |
|---:|---|---|---|---|
| 1 | secret-sentinel | `devops-toolkit secret-sentinel` | Implemented | Git optional, redaction, SARIF |
| 2 | workstation-doctor | `scripts/workstation/devops-workstation-audit.ps1` | Implemented | PowerShell 7, Windows APIs |
| 3 | iac-repo-gate | `devops-toolkit iac-repo-gate` | Implemented | Terraform/OpenTofu and validators optional |
| 4 | gha-guard | `devops-toolkit gha-guard` | Implemented | YAML parser, SARIF |
| 5 | kube-triage | `devops-toolkit kube-triage` | Implemented | kubectl, Kubernetes read access |
| 6 | plan-risk | `devops-toolkit plan-risk` | Implemented | Terraform/OpenTofu plan JSON |
| 7 | linux-triage | `scripts/linux/linux-triage.sh` | Implemented | Linux native commands |
| 8 | repo-baseline | `devops-toolkit repo-baseline` | Implemented | GitHub API pagination |
| 9 | kubeconfig-hygiene | `devops-toolkit kubeconfig-hygiene` | Implemented | certificate parsing |
| 10 | tls-audit | `devops-toolkit tls-audit` | Implemented | sockets and TLS APIs |
| 11 | image-gate | `devops-toolkit image-gate` | Implemented | scanner normalization |
| 12 | ci-evidence | `devops-toolkit ci-evidence` | Implemented | GitHub logs and redaction |
| 13 | prom-audit | `devops-toolkit prom-audit` | Implemented | Prometheus API |
| 14 | slo-budget | `devops-toolkit slo-budget` | Implemented | time-series calculations |
| 15 | kube-rightsize | `devops-toolkit kube-rightsize` | Implemented | Metrics API and Prometheus |
| 16 | cloud-iam-audit | `devops-toolkit cloud-iam-audit` | Implemented | Azure/AWS adapters |
| 17 | cloud-waste | `devops-toolkit cloud-waste` | Implemented | normalized cloud resources |
| 18 | budget-guard | `devops-toolkit budget-guard` | Implemented | billing time series |
| 19 | iac-drift-guard | `devops-toolkit iac-drift-guard` | Implemented | plan-risk engine |
| 20 | kube-upgrade-readiness | `devops-toolkit kube-upgrade-readiness` | Implemented | kubectl and compatibility rules |

## Security, workstation, IaC, CI/CD, and Kubernetes triage

- [Secret Sentinel](tools/secret-sentinel.md)
- [Workstation Doctor](tools/workstation-doctor.md)
- [IaC Repository Gate](tools/iac-repo-gate.md)
- [GitHub Actions Guard](tools/gha-guard.md)
- [Kubernetes Triage](tools/kube-triage.md)

## Planning, Linux, GitHub governance, kubeconfig, and TLS

- [Terraform Plan Risk Analyzer](tools/plan-risk.md)
- [Linux Incident Snapshot](tools/linux-triage.md)
- [GitHub Repository Baseline](tools/repo-baseline.md)
- [Kubeconfig Hygiene](tools/kubeconfig-hygiene.md)
- [TLS Auditor](tools/tls-audit.md)

## Supply chain, CI evidence, observability, SRE, and rightsizing

- [Container Image Gate](tools/image-gate.md)
- [CI Evidence Collector](tools/ci-evidence.md)
- [Prometheus Auditor](tools/prom-audit.md)
- [SLO Budget Calculator](tools/slo-budget.md)
- [Kubernetes Rightsizing Auditor](tools/kube-rightsize.md)

## Cloud governance, drift, and Kubernetes upgrades

- [Cloud IAM Exposure Auditor](tools/cloud-iam-audit.md)
- [Cloud Waste Inventory](tools/cloud-waste.md)
- [Cloud Budget Guard](tools/budget-guard.md)
- [IaC Drift Guard](tools/iac-drift-guard.md)
- [Kubernetes Upgrade Readiness](tools/kube-upgrade-readiness.md)
