# Kubernetes Rightsizing Auditor

## Usage

`devops-toolkit kube-rightsize --context CONTEXT --namespace NAMESPACE [--patch-preview]`

## Behavior

Uses read-only pod specifications and the `metrics.k8s.io` API. Current samples are insufficient for automatic resizing, so recommendations are confidence-labelled and never applied.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.
