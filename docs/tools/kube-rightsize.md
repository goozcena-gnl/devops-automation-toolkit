# Kubernetes Rightsizing Auditor

## Usage

`devops-toolkit kube-rightsize --context CONTEXT --namespace NAMESPACE [--patch-preview]`

## Behavior

Uses read-only pod specifications and the `metrics.k8s.io` API. Current samples are insufficient for automatic resizing, so recommendations are confidence-labelled and never applied.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.

## Read scope

The selected namespace is used in both the core Pods list and the [PodMetrics
list](https://github.com/kubernetes/metrics/blob/v0.34.1/pkg/client/clientset/versioned/typed/metrics/v1beta1/podmetrics.go).
For example, `--namespace payments` uses
`/api/v1/namespaces/payments/pods` and
`/apis/metrics.k8s.io/v1beta1/namespaces/payments/pods`. A namespaced identity
needs list access to Pods and PodMetrics in that namespace. `--all-namespaces`
uses the global routes only when the namespace policy permits the request. See
[the live Kubernetes policy](../kubernetes-read-scope.md).

A Pods authorization failure returns exit 4. When the Pods request times out or
returns invalid evidence, the result is partial and the Metrics request is
skipped. A Metrics failure or scope mismatch leaves usage unverified while
retaining valid Pod evidence. `--snapshot FILE` uses local evidence only.
