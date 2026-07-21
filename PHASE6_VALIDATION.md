# Phase 6 validation report

## Release identity

- Project: `devops-automation-toolkit`
- Version: `0.6.0`
- Validation date: 2026-07-21
- Scope: Phase 6 and regression validation of the complete 20-tool repository
- Python validation runtime: CPython 3.13.5 on Linux

## Implemented in Phase 6

1. Cloud IAM Exposure Auditor
2. Cloud Waste Inventory
3. Cloud Budget Guard
4. IaC Drift Guard
5. Kubernetes Upgrade Readiness

The five tools use the common finding, policy, configuration, reporting, redaction, safety, and exit-code contracts established in earlier phases.

## Functional characteristics

### Cloud IAM Exposure Auditor

- Supports Azure and AWS.
- Uses existing CLI credential chains in live mode.
- Supports normalized offline snapshots.
- Detects broad assignments, wildcard permissions, risky trust, missing principals, stale keys, MFA gaps, and credential-expiry metadata when supplied.
- Does not retrieve, rotate, disable, or serialize credential values.

### Cloud Waste Inventory

- Supports Azure and AWS resource inventories.
- Detects unattached storage, unassociated public IP addresses, orphaned interfaces, aged snapshots, empty load balancers, missing tags, and idle compute only when utilization evidence exists.
- Does not delete, stop, resize, detach, or tag resources.
- Does not invent cost estimates.

### Cloud Budget Guard

- Supports Azure and AWS budget snapshots and live read-only collection.
- Checks budget presence, thresholds, recipients, actual spend, forecasts, daily increases, and service concentration.
- Separates actual, forecasted, and inferred anomaly evidence.
- Does not create or change budgets or notification recipients.

### IaC Drift Guard

- Supports Terraform and OpenTofu.
- Consumes plan JSON directly or creates a bounded refresh-only plan in live mode.
- Checks the selected workspace and production-safety policy.
- Detects external updates, remote deletions, replacement, mixed configuration changes, failed checks, local state permissions, and lock evidence.
- Never runs `apply` or `force-unlock`.

### Kubernetes Upgrade Readiness

- Supports snapshot analysis and read-only `kubectl` collection.
- Checks target-version jumps, version skew, node readiness, removed APIs, PDB drain blockers, webhooks, CRD storage versions, aggregated APIs, and add-on inventory.
- Does not upgrade, cordon, drain, restart, patch, or apply manifests.

## Validation summary

| Validation | Result |
|---|---:|
| Unit and contract tests | 89 passed |
| Isolated integration tests | 4 passed |
| Total exercised tests | 93 passed |
| Python coverage for unit and contract suite | 64% |
| Ruff formatting | Passed across 105 files |
| Ruff linting | Passed |
| mypy strict mode | Passed across 61 source files |
| Bandit configured scan | Passed |
| Python bytecode compilation | Passed |
| Bash syntax | Passed |
| Configuration examples | Passed |
| Checked-in report contracts | 19 JSON and 2 SARIF reports passed |
| Phase 6 example reports | 5 reports passed |
| Source Secret Sentinel self-audit | 0 findings |
| Native-script Secret Sentinel self-audit | 0 findings |
| GitHub Actions Guard self-audit | 0 findings |
| Clean wheel installation | Passed |
| Installed command version | `0.6.0` |
| Clean-install Phase 6 reports | 5 schema-valid reports |
| Wheel build | Passed |
| Source-distribution build | Passed |

## Test segmentation

The unit and contract suite ran with coverage instrumentation:

```text
89 passed
TOTAL: 4278 statements, 64% covered
```

The subprocess-heavy integration tests were executed independently without inherited coverage state:

- module entry-point exit-code propagation;
- bounded Git-history secret scanning;
- Kubernetes collection through a deterministic fake `kubectl`;
- native Linux collection and bundle validation.

All four passed.

## Phase 6 command and contract verification

The following installed commands were exercised from a fresh virtual environment using the built wheel:

```text
devops-toolkit cloud-iam-audit
devops-toolkit cloud-waste
devops-toolkit budget-guard
devops-toolkit iac-drift-guard
devops-toolkit kube-upgrade-readiness
```

Each deliberately risky fixture:

- returned exit code `1`;
- produced a report matching the stable JSON Schema;
- reported metadata version `0.6.0`;
- preserved the expected tool identifier;
- avoided serializing credential values.

Observed clean-install report results:

| Tool | Status | Findings |
|---|---:|---:|
| Cloud IAM Exposure Auditor | fail | 5 |
| Cloud Waste Inventory | fail | 7 |
| Cloud Budget Guard | fail | 6 |
| IaC Drift Guard | fail | 3 |
| Kubernetes Upgrade Readiness | fail | 11 |

These failures are expected policy results from intentionally unsafe fixtures, not execution failures.

## Security verification

- External command execution continues to use argument arrays and bounded execution through the shared subprocess layer.
- No `shell=True`, automatic cloud remediation, Terraform apply, state unlock, or Kubernetes mutation path was introduced.
- Phase 6 reports were inspected for synthetic raw secret markers and common secret-bearing fields; none were present.
- Cloud live modes use existing Azure CLI or AWS CLI authentication rather than accepting secret values as command-line arguments.
- Terraform plan JSON is documented as potentially sensitive and is not retained automatically by the live collector.
- Production-like Terraform directories and Kubernetes contexts remain subject to the shared safety policy and explicit acknowledgement.

## Packaging verification

The wheel and source distribution were built in an isolated PEP 517 environment:

```text
devops_automation_toolkit-0.6.0-py3-none-any.whl
devops_automation_toolkit-0.6.0.tar.gz
```

The wheel was installed into a new CPython 3.13 virtual environment with only declared runtime dependencies. The CLI reported version `0.6.0`, and all five Phase 6 snapshot commands executed successfully.

## Behavior not exercised locally

The following live paths are implemented but were not validated against production services:

- authenticated Azure tenant and subscription IAM inventory;
- authenticated AWS IAM account inventory;
- Azure Resource Graph or Azure resource inventory at enterprise scale;
- AWS resource inventory across multiple accounts and regions;
- live Azure and AWS billing and forecast APIs;
- provider-backed Terraform or OpenTofu refresh-only plans;
- live Kubernetes upgrade collection against managed and self-hosted distributions;
- Microsoft Graph service-principal credential inventory;
- Windows PowerShell execution of Workstation Doctor.

No Azure, AWS, GitHub write-capable, Terraform backend, or production Kubernetes credentials were used.

## Accuracy boundaries

- IAM findings indicate exposure or governance risk; they do not prove compromise.
- Waste findings require owner and dependency review before lifecycle action.
- Cloud billing data may be delayed, incomplete, or use provider-specific forecast semantics.
- Terraform drift visibility depends on provider refresh behavior and the audit identity's permissions.
- Kubernetes discovery cannot prove that external clients have stopped calling deprecated APIs.
- Add-on compatibility must be verified against the relevant vendor or project release documentation.

## Phase completion assessment

Phase 6 meets its entry criteria:

- all final five ranked tools are implemented;
- independent CLI commands and shared configuration are available;
- snapshot-backed deterministic tests exist;
- read-only live collection paths are implemented;
- report and exit-code contracts remain stable;
- documentation and examples are included;
- clean installation and package construction pass.

Version `0.6.0` completes the original set of 20 tools. The remaining planned activity is Phase 7: full cross-tool consistency, dependency, portability, security, failure-mode, documentation, and GitHub-release readiness review.
