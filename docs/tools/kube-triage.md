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

Use `--all-namespaces` only when the configured namespace policy permits it. A
production-like context requires `--acknowledge-production` unless allowlisted.
When more than one context exists, `--context` is mandatory.

## Read-only collection

The command invokes `kubectl --context ... get ... -o json` for:

- nodes;
- pods;
- deployments;
- StatefulSets;
- DaemonSets;
- jobs;
- persistent-volume claims;
- warning events;
- endpoints.

It does not request Kubernetes Secret objects.

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

Use a dedicated read-only role limited to the requested namespace and required
cluster-scoped node access. Collection failures are reported individually and
mark the result partial rather than being hidden.

## Limitations

The command does not collect logs, execute into containers, perform DNS probes,
or change workloads. These capabilities require separate explicit collectors and
additional safety controls.
