# Kubernetes Triage

## Purpose

Collect a bounded, read-only cluster health snapshot and turn it into actionable
findings plus an optional sanitized evidence bundle.

## Usage

```bash
devops-toolkit kube-triage \
  --context development-cluster \
  --namespace payments \
  --bundle kube-triage.zip \
  --format json \
  --output kube-triage.json
```

Use [the live Kubernetes policy](../kubernetes-read-scope.md) to restrict
contexts, servers, and namespaces. When several contexts exist, select one with
`--context`. `--all-namespaces` requires a policy without a namespace allowlist.

## Read-only collection

The namespace-scoped lists are Pods, Deployments, StatefulSets, DaemonSets,
Jobs, PVCs, Events and Endpoints. Triage uses explicit Kubernetes API routes for
these lists. It collects Nodes only when the effective `tools.kube-triage`
configuration sets `allow_cluster_scope: true`. Node inventory requires this
opt-in in both namespace modes.

## Analysis

The current rules cover node readiness and pressure, pending and non-running
pods, waiting-container reasons, restarts, controller availability, failed jobs,
unbound PVCs, grouped warning events, and endpoints without ready addresses.

## Sanitized bundle

The ZIP contains the normalized report and per-resource JSON. Managed fields,
secret-like keys, environment values, last-applied annotations, and recognized
token patterns are redacted before archive creation. The archive is created via
a temporary file with restrictive permissions and atomically moved into place.

## Permissions

Use a read-only identity with list access to the requested resources in the
requested namespace. Node list permission is needed only when Node collection is
enabled. Reports record policy exclusions in `collection_exclusions` and
collection failures in `collection_errors`. An excluded Nodes list leaves Node
health unverified and the report partial. The bundle contains only validated
resource lists.

## Limitations

The command does not collect logs, execute into containers, perform DNS probes,
or change workloads. These capabilities require separate explicit collectors and
additional safety controls.
