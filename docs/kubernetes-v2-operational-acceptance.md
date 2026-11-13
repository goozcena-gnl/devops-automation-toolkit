# B5 — Kubernetes v2 operational acceptance and non-production smoke-test protocol

> **Plan only; NOT RUN against any live cluster.** This document prepares human-operated testing for the unpublished `2.0.0rc1` candidate (proposed tag `v2.0.0-rc.1`). It is **not** a release approval, a production runbook authorization, or permission to merge/tag/publish PR #77. The current git HEAD and workflow run IDs must be captured at execution time; earlier CI results cannot validate later commits.

## Evidence classes and decision status

- **HOSTED PASS**: existing fixture/fake-`kubectl` and packaging checks, only if verified again on the exact candidate commit. This does not imply live Kubernetes coverage.
- **NOT RUN**: no non-production cluster operation has been performed for B5, and no real kubeconfig, tenant, cluster or privileged identity is assumed.
- **BLOCKED**: a required authorization, isolation control, sanitized evidence artifact or reviewer decision is missing. Do not convert BLOCKED or NOT RUN to PASS.
- **PASS/FAIL** for each operational scenario may be assigned only after an authorized operator has recorded the actual command, exit status, redacted report and independent review.

### Human sign-off and target record (must be filled before any live run)

| Field | Required record | Current status |
| --- | --- | --- |
| Candidate provenance | PR #77 exact HEAD SHA, installed `devops-toolkit version`, checked wheel/sdist SHA256, validated CI run IDs | PENDING new-head CI |
| Test environment | Non-production cluster identifier, owner, purpose, change window, confirmation it is not production | NOT PROVIDED |
| Trust / scope | Reviewed kubeconfig source, exact context, server URL and certificate/TLS validation, namespace(s), proxy/redirect assumptions | NOT PROVIDED |
| Authentication | Dedicated identity, Kubernetes Role/ClusterRole and binding evidence for *read-only* verbs on approved resources | NOT PROVIDED |
| Release impact | Inventory of actual scheduled invocations, report consumers and handling for exit statuses 1/5/7 | NOT PROVIDED |
| Test authorization | Named operator and independent security/platform reviewer, approval timestamps and permitted case IDs | PENDING |
| Evidence handling | Private storage destination, retention and redaction policy, prohibition of raw credentials/kubeconfigs in PR comments | PENDING |
| Business acceptance | Explicit major-version/migration decision, rollout owner and rollback decision-maker | PENDING |

## Acceptance matrix (all live cases start NOT RUN)

| ID | Scenario and execution mode | Acceptance criteria / observed evidence to record | B5 live status |
| --- | --- | --- | --- |
| B5-01 | Offline candidate/manifest verification | Installed version `2.0.0rc1` from SHA-pinned, non-publishing build; wheel hashes recorded; same exact HEAD green in required workflows | NOT RUN |
| B5-02 | Local scope trust preflight | Approved context maps to the exact expected server/TLS identity; restricted context/server/namespace allowlists; production target rejected | NOT RUN |
| B5-03 | Triage without Node opt-in (live, approved namespace) | No Nodes API call; `extensions.collection_exclusions.nodes = intentionally_excluded`; `metadata.partial=true`; normally exit 5 unless threshold findings cause 1; findings are not labeled full coverage | NOT RUN |
| B5-04 | Triage with explicit Node opt-in (live) | Only if separate cluster read access approved: Nodes list captured and no unapproved API requests; no exclusion for Nodes; actual partial/findings/exit status recorded without assuming 0 | NOT RUN |
| B5-05 | Rightsize single-namespace live | Only Pods and `metrics.k8s.io` PodMetrics lists in approved namespace; no cross-namespace evidence accepted; authorized identity has `list` on both resources | NOT RUN |
| B5-06 | Rightsize all-namespaces denied by restrictive allowlist | Requested `--all-namespaces` denied with exit 7 before remote API collection; do **not** remove the allowlist merely to get exit 0 | NOT RUN |
| B5-07 | Rightsize missing/invalid metrics | Partial evidence remains visible (typically 5, or 1 when a finding meets threshold); no automatic patch or recommendation falsely marked complete | NOT RUN |
| B5-08 | Upgrade Readiness without cluster opt-in | Local policy refuses live collection with exit 7, no remote requests (local kubeconfig resolution may still run) | NOT RUN |
| B5-09 | Upgrade Readiness with separately approved opt-in | Authorized reads limited to server version/discovery, Nodes, all-namespace PDBs, CRDs, admission webhooks, APIService and `kube-system` Deployment/StatefulSet/DaemonSet; actual findings/partial state recorded | NOT RUN |
| B5-10 | Offline snapshot fallback | Approved local snapshot analyzed with `--snapshot`; no live Kubernetes request; report/schema checks and status interpretation recorded | NOT RUN |
| B5-11 | Scope failure and auth failure handling | A known restricted scope fails closed with exit 7; required resource auth failure is 4; any other missing/partial collection is visible, not converted to success | NOT RUN |
| B5-12 | Consumer and deployment compatibility | Test each real CI/scheduler/dashboard parser with 0/1/5/7 and `metadata.partial`; findings (1) require investigation, 5/7 cannot be treated as clean runs | NOT RUN |
| B5-13 | Rollout/rollback rehearsal (no production change) | Keep verified v1.0.2 artifact and pinned installation procedure; test non-production rollback/CLI and report-consumer behavior; document responsible approver and revalidation gates | NOT RUN |

**Interpretation:** a deliberately denied test can PASS the *security control* when it returns the expected 7; that does not establish live collection readiness. Any required scenario remaining NOT RUN/BLOCKED prevents a claim of full operational acceptance unless the named approver records a scoped exception and rationale. Do not treat a reported threshold finding (1) as a healthy outcome even when the collector itself behaved correctly.

## Permissions and safeguards to review (do not apply automatically)

| Collector | Namespaced read access | Cluster/global read access |
| --- | --- | --- |
| `kube-triage` | `list`: Pods, Deployments, StatefulSets, DaemonSets, Jobs, PVCs, Events, Endpoints in the selected namespace | Optional `list nodes` **only** when `allow_cluster_scope: true` is separately authorized |
| `kube-rightsize` | `list pods` and `list pods.metrics.k8s.io` in selected namespace | None for default namespaced mode; `--all-namespaces` is a separate, explicit scope decision |
| `kube-upgrade-readiness` | `list` on Deployments, StatefulSets, DaemonSets in `kube-system` | Version/API discovery, `list` Nodes, PDBs across all namespaces, CRDs, mutating/validating webhook configurations and APIService; requires explicit cluster-scope opt-in |

Use Kubernetes RBAC to grant only required verbs/resources to a dedicated test identity. Review discovery/non-resource URL permissions where applicable, authentication plugins, TLS, network routing and redirects. Config allowlists do not replace RBAC. **Do not grant write/update/patch/delete, impersonation, Secret access, admin or cluster-admin just to make the audit pass.** Production acknowledgements, if any, are outside B5.

### Reviewed policy examples (replace placeholders; never use these as live defaults)

These examples intentionally use reserved `.invalid` endpoints and cannot be run successfully as written. Save approved policies **outside the repository**; do not commit real endpoints, credentials, kubeconfigs or reports. Use separate files per collector to avoid confusing different scopes.

**Triage (default least privilege, Nodes excluded):**

```yaml
version: 1
tools:
  kube-triage:
    allow_cluster_scope: false
    allowed_contexts: [reviewed-nonprod-context]
    allowed_servers: [https://api.nonprod.example.invalid]
    allowed_namespaces: [reviewed-namespace]
```

**Rightsize (namespace only):**

```yaml
version: 1
tools:
  kube-rightsize:
    allowed_contexts: [reviewed-nonprod-context]
    allowed_servers: [https://api.nonprod.example.invalid]
    allowed_namespaces: [reviewed-namespace]
```

**Upgrade Readiness, denial case (no cluster-scope authorization):**

```yaml
version: 1
tools:
  kube-upgrade-readiness:
    allow_cluster_scope: false
    allowed_contexts: [reviewed-nonprod-context]
    allowed_servers: [https://api.nonprod.example.invalid]
```

For the *separately approved* positive Upgrade case B5-09, a reviewer may change **only its reviewed local policy** to `allow_cluster_scope: true`. Do not set `allowed_namespaces` for Upgrade Readiness: the tool needs all-namespace PDBs and `kube-system` inventory. For B5-04, prepare a separate approved Triage policy with explicit Node opt-in. **Never widen permissions just to suppress an exit 5 or 7.**

## Non-production procedure — manual only, never run in this PR

1. **Approval gate:** operator and independent reviewer select exact target, case IDs, time window, data-handling rules, trusted kubeconfig and read-only RBAC. Reject any production context. Get explicit separate approval for B5-04/B5-09 cluster-wide reads; if absent, mark BLOCKED and use offline snapshot tests only.
2. **Pin provenance:** record PR exact SHA, installed package version, wheel/sdist SHA256, GitHub Actions run IDs and sanitized dependency/CLI environment details. Use only reviewed candidate artifacts; never create a Git tag or publish a release for this test.
3. **Local kubeconfig check:** inspect local context-to-server/TLS mapping without printing user credentials; independently review cluster ownership and authenticated principal. Consider the possibility of kubeconfig authentication plugins and proxies. Do not rely on context names alone.
4. **RBAC preflight when authorized:** verify effective rights against the matrix, for example `kubectl --context <approved-context> auth can-i list pods -n <approved-namespace>` and `kubectl --context <approved-context> auth can-i list pods.metrics.k8s.io -n <approved-namespace>`. These commands **contact the API server** and must not be executed before authorization. Record yes/no, not tokens.
5. **Safety negative tests:** with locally reviewed restrictive policies, validate context/server denial, Triage Node exclusion and Upgrade default denial. Compare command exit codes, remote-request audit logs if available and JSON report existence. A blocked run may produce **no report**; do not fabricate one.
6. **Read-only positive cases when authorized:** execute a minimal namespace Triage and Rightsize. Run Nodes and Upgrade positive tests only with separately approved cluster-scoped privileges. Do not run `kubectl apply`, `patch`, `cordon`, `drain`, upgrades, workload mutations or remediation tools.
7. **Offline alternative:** for contexts lacking cluster-wide permission, execute `devops-toolkit kube-upgrade-readiness --target-version <approved-target-version> --snapshot <approved-local-snapshot.json> --format json --output <private-output.json>` using an approved sanitized snapshot. Verify this path does not invoke remote collection.
8. **Report review:** validate output schema `1.0`, `metadata.partial`, `extensions.collection_exclusions`, `extensions.collection_errors`, `extensions.scope`, version, findings and CLI exit code; scope keys vary by collector. Validate consumer parsers, sanitized bundles and no loss of findings on incomplete requests.
9. **Decision:** record each scenario's PASS/FAIL/BLOCKED/NOT RUN, reviewer, actual observed results and remediation owner. Fail closed on missing evidence, unapproved scope, unresolved auth/TLS issues or downstream jobs treating partial/blocked results as success.
10. **Rollback:** retain a verified pre-existing v1.0.2 install artifact/configuration and test a non-production rollback before upgrading consumers. Do not claim backward-compatible interpretation of newly added report extensions; restore version-specific parsers as needed.

### Example PowerShell invocation pattern (illustrative; do not execute until approved)

```powershell
# Populate these variables only after review; paths are local PRIVATE files outside the repository.
$Context = 'reviewed-nonprod-context'
$Namespace = 'reviewed-namespace'
$Policy = 'C:\private-evidence\triage-reviewed.yaml'
$Out = 'C:\private-evidence\triage-report.json'
# WARNING: the example context/policy values are placeholders, not actual access authorization.
devops-toolkit kube-triage --context $Context --namespace $Namespace --config $Policy --format json --output $Out
$TriageExit = $LASTEXITCODE
# Record $TriageExit, whether $Out exists, report.partial/exclusions and independently approved cluster identity.
```

Never add `|| true`, unconditional `exit 0`, `continue-on-error` or allowlist/RBAC bypasses to hide observed statuses. Equivalent invocations for Rightsize and Upgrade Readiness must use their own **separately reviewed** policy files. Record exit codes directly; do not infer a PASS from the presence of an output file.

## Evidence ledger template (one record per case)

```text
Case ID: B5-__
Date/time UTC: NOT RUN
Operator / independent reviewer: PENDING
PR HEAD / artifact SHA256 / package version: PENDING
Environment classification / approved context, server and namespace (redacted aliases): PENDING
Reviewed policy version / RBAC decision / approval reference: PENDING
Exact command and exit code: NOT RUN
Remote request scope (approved audit evidence) / collection exclusions: NOT RUN
JSON schema / tool_version / metadata.partial / findings / error fields: NOT RUN
Redacted evidence location and retention: NOT RUN
Result: NOT RUN
Follow-up issue / exception approver: PENDING
```

Do not attach unsanitized reports, kubeconfigs, tokens, raw cluster object lists or secrets to a public GitHub PR. Use approved private storage for target evidence; add only a redacted summary and immutable evidence references after review.

## Promotion boundary

**B5 document creation is not B5 operational acceptance.** Technical reviewer may declare the *plan* ready only after documentation checks succeed at the new exact HEAD. An authorized operator must execute approved tests, and a separate human decision must accept the SemVer major boundary, remaining exceptions, rollout and rollback. Keep PR #77 OPEN and DRAFT, without merge, tag, auto-merge, GitHub Release, PyPI publish, CI bypass or production access.

See the [v2 migration guide](migration-v2.md), [Kubernetes read-scope policy](kubernetes-read-scope.md), and [tool-level docs](tools/kube-upgrade-readiness.md).
