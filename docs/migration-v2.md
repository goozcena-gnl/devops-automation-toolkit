# Migration from v1.0.2 to v2.0.0 (candidate v2.0.0-rc.1)

> **Not published.** This guide describes the proposed major-version migration. GitHub release `v1.0.2` remains the latest published version. Python package version in this candidate is `2.0.0rc1`. A future tag `v2.0.0-rc.1` is subject to explicit human approval; no tag or release is created by this document.

## Why this is a major-version candidate

The public CLI subcommand names and the JSON report schema `1.0` remain stable, but some existing live Kubernetes invocations change behavior without modifying their arguments. Stronger default least privilege requires explicit authorization for cluster-scoped collection. The change affects evidence completeness and automation exit codes. Do **not** weaken the read policy solely to keep the old exit code.

## Before you upgrade

1. Inventory scheduled invocations of `kube-triage`, `kube-rightsize`, and `kube-upgrade-readiness`, including consumers of their reports and exit codes.
2. Review each kubeconfig context, cluster server URL, TLS configuration, namespace and Kubernetes read-only RBAC grants.
3. Trial the new version on fixtures or non-production contexts; compare JSON reports, collection exclusions and error statuses.
4. Explicitly document which jobs require Nodes, all-namespace PodDisruptionBudgets, add-on inventory, or other cluster-scoped data. Do not grant broader privileges by default.
5. Keep using the published release until the candidate has passed hosted checks, a new exact-head preflight and human review.

## Kubernetes Triage

Previous `v1.0.2` behavior requested Nodes by default. The new default is `tools.kube-triage.allow_cluster_scope: false`; Nodes are excluded and the report records `extensions.collection_exclusions.nodes = "intentionally_excluded"` with `metadata.partial = true`. This can cause exit `5` instead of `0` when no threshold finding takes precedence.

For approved Node collection, place this in a reviewed YAML file and provide it to the CLI:

```yaml
version: 1
tools:
  kube-triage:
    allow_cluster_scope: true
    allowed_contexts: [development-cluster]
    allowed_servers: [https://kubernetes.dev.example.invalid]
    allowed_namespaces: [payments]
```

The example API server is a reserved placeholder; replace it with the exact trusted server from an approved kubeconfig. Grant Nodes `list` only to the identity that needs Node data. Context selection and server allowlists do not replace RBAC or TLS verification.

If Node inspection is unnecessary, keep `allow_cluster_scope: false`, accept the explicit exclusion, and update consumers to treat incomplete evidence as incomplete rather than healthy.

## Kubernetes Upgrade Readiness

Live mode now requires `tools.kube-upgrade-readiness.allow_cluster_scope: true`. Without the opt-in, the tool stops before any remote API request with safety-blocked exit `7` (local kubeconfig resolution may still occur). It inspects cluster-scoped resources, all-namespace PDBs and `kube-system` workloads. A restrictive namespace allowlist conflicts with those required global requests.

```yaml
version: 1
tools:
  kube-upgrade-readiness:
    allow_cluster_scope: true
    allowed_contexts: [development-cluster]
    allowed_servers: [https://kubernetes.dev.example.invalid]
```

Use `--config <reviewed-policy.yaml>` and a deliberately selected `--context`. Set `allow_cluster_scope: true` **only** after verifying cluster-wide read permissions and operational scope. If that is not authorized, use `--snapshot <file>` to analyze existing, approved local evidence without live access.

## Kubernetes Rightsize

Namespaced Pods and PodMetrics are read from explicit namespaced API routes. Namespace `payments` requires `list` on Pods and `metrics.k8s.io` PodMetrics in `payments`; `--all-namespaces` requires explicit scope and authorization. Errors, empty metrics for non-empty pod inventories, and cross-namespace responses do not result in false-complete findings. Review partial exit `5` handling.

## IaC validation and Secret Sentinel

- Terraform/OpenTofu validation is marked `validated=true` only when compatible, complete `validate -json` data agrees with the process exit code. Missing or contradictory metadata is an incomplete/failed-evidence result; complete rejected validation remains a finding. Do not treat a `5` as a clean run.
- Secret Sentinel now distinguishes empty valid scans from intentionally excluded scans and failed/incomplete inventory or Git enumeration. Review `extensions.collection` and `metadata.partial` rather than assuming zero findings means all evidence was collected.

## Automation and report contracts

The schema version remains `1.0`. Existing exit-code **meanings** remain stable, but newly enforced policy/evidence checks can change which code a particular invocation produces:

| Code | Interpretation |
| --- | --- |
| `0` | Completed without a threshold finding or incomplete collection |
| `1` | A finding reaches the configured severity threshold, even if some evidence is incomplete |
| `2` | Invalid input or unresolved scope |
| `3` | Required local tool unavailable |
| `4` | Required authentication/authorization failure |
| `5` | Partial or failed requested evidence |
| `7` | Safety policy denied requested live scope |

Check all actual shell/CI exit-code consumers and avoid marking `5` or `7` green. Inspect `metadata.partial`, `extensions.collection_exclusions`, `extensions.collection_errors` and per-tool `validation_state` where provided. The existing stable fingerprint algorithm and read-only/report-only defaults are unchanged.

## Validation and safety boundaries

The B0 non-publishing Release Preflight run [43430767700](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43430767700) succeeded on base SHA `f3033bb99645480cddb17d373bfe4fea4fee2952`, **not** on this candidate. The candidate must pass fresh CI/Security/Plumber/integration, synthetic/contract and packaging evidence at the exact head before approval. These tests are not evidence of live Azure, AWS, production Kubernetes or private-provider behavior. A Draft PR is not permission to tag, merge or publish.
