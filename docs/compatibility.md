# Compatibility matrix

## Python package

| Component | Supported in 1.0.0 | Validation status |
|---|---|---|
| CPython 3.11 | Yes | Unit/contract CI matrix configured |
| CPython 3.12 | Yes | Unit/contract CI matrix configured |
| CPython 3.13 | Yes | Locally validated and CI matrix configured |
| Linux | Yes | Local unit, contract, integration, Bash, packaging checks |
| Windows | Yes for Python CLI | Python 3.12 unit/contract suite, cross-platform integration paths, CLI, packaging, and PowerShell parsing exercised locally; hosted matrix configured |
| macOS | Best effort | Python code is portable, but no dedicated CI job |

## Native collectors

| Collector | Intended environment | Validation boundary |
|---|---|---|
| Linux Incident Snapshot | Modern Linux with Bash and common system utilities | Locally executed in the release container; distribution-specific commands may degrade gracefully |
| Workstation Doctor | Windows 11 and PowerShell 7, with optional WSL and Docker Desktop | Parser and execution/schema smoke test exercised locally; pinned PSScriptAnalyzer 1.25.0 remains a hosted Windows gate |

## External integrations

| Integration | Access model | Release evidence |
|---|---|---|
| Git | Local read-only commands | Fixture and integration coverage |
| GitHub | Existing `gh` authentication and read permissions | Offline snapshots and API adapter tests; live private-repository validation required |
| Kubernetes | Existing kubeconfig and read-only RBAC | Fake `kubectl`, snapshot, and deterministic analysis coverage; target-cluster validation required |
| Terraform/OpenTofu | Local binary and existing backend credentials | Plan fixtures and fake/local command paths; production backend validation required |
| Azure | Azure CLI credential chain and read-only scopes | Snapshot analysis; live subscription validation required |
| AWS | AWS CLI credential chain and read-only scopes | Snapshot analysis; live account validation required |
| Prometheus | Read-only HTTP API | Fixture analysis; enterprise authentication and PKI require target validation |
| Trivy/Cosign | Local executables and registry access | Normalization fixtures; live registry validation required |
| TLS endpoints | Standard Python TLS stack | Local trusted/untrusted endpoint smoke behavior; enterprise mTLS requires target validation |

## Operational adoption

Before using a live collector in a production environment:

1. review the tool-specific permissions and limitations;
2. run against a non-production or snapshot target;
3. verify timeout and output limits;
4. set explicit account, subscription, context, namespace, repository, or region scope;
5. confirm that generated reports and bundles meet local data-handling requirements;
6. treat partial evidence as incomplete rather than clean.
