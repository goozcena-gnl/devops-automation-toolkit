# Kubernetes live read scope

The three live collectors authorize scope before the first API request. A local
`kubectl config view` projects context names, cluster names, API server URLs and
TLS server names without requesting user records. Local resolution does not
invoke authentication plugins. Every remote call pins the resolved context,
cluster, server URL and TLS server name. Use a trusted kubeconfig and kubectl
with normal TLS verification. On Windows, use the native kubectl.exe
executable. Live kubectl can invoke authentication plugins
from that trusted configuration. The configured endpoint and TLS identity
depend on the trust of kubeconfig, DNS, proxy and certificate settings.
The server allowlist checks the configured URL. kubectl controls transport
and redirect handling.

The effective per-tool configuration comes from the repository's existing
defaults and ordered `--config` files. Explicit CLI flags select the request
within that policy. Python callers can pass
`devops_toolkit.core.kubernetes.KubernetesReadPolicy` as `read_policy` to the
three builders or their live collection functions.

| Configuration key | Live behavior |
|---|---|
| `allowed_contexts` | Exact match on the selected context, including an implicit selection. |
| `allowed_servers` | Exact match on the kubeconfig server URL. Use this to bind policy to a known endpoint when a context is an alias. |
| `allowed_namespaces` | Exact match on the requested namespace. A configured list precludes all-namespace requests. |
| `allow_cluster_scope` | Defaults to `false`. Triage uses it for Nodes and Upgrade Readiness requires it for any live collection. |

An omitted allowlist leaves that dimension unrestricted. An explicit empty list
denies that dimension. Triage and Rightsize require `--all-namespaces` to widen
their namespaced lists. The namespace defaults to `default` and must be a
Kubernetes DNS label. Upgrade Readiness explicitly selects cluster-wide scope
with its policy opt-in, including the all-namespace PDB list and the
`kube-system` add-on inventory. Triage and Rightsize require `--context` when
several contexts exist. Upgrade Readiness uses the configured current context
unless `--context` selects another one.

Production policy evaluates the resolved context and cluster names, the
configured server URL and host labels, and the TLS server name. The production
acknowledgement applies only after allowlist checks. If the configured names
do not identify production, operators can designate a production endpoint using
`safety.production_allowlist` and bind the permitted endpoint using
`allowed_servers`.

## Migration

- Existing Triage jobs that require Node findings should set
  `tools.kube-triage.allow_cluster_scope: true` in the approved configuration.
  Namespace-only jobs receive an explicit Node exclusion and partial coverage.
- Existing live Upgrade Readiness jobs should set
  `tools.kube-upgrade-readiness.allow_cluster_scope: true` and use a policy that
  permits all namespaces. Jobs limited to namespace RBAC can analyze snapshots.
- Remove historically empty allowlists from configurations that intend
  unrestricted scope. Use an empty list when the intended policy denies all.
- Rightsize requires list access on the PodMetrics resource in its selected
  namespace. Scoped Triage and Rightsize issue direct list requests on stable
  resource routes, which avoids unrequested API discovery and short-name
  resolution. A response with a continuation token is incomplete.

The report records the live scope, exclusions and collection failures. Responses
with mismatched object namespaces are discarded before findings, metrics or
bundle entries can use them. Server diagnostics are summarized without including
provider output. Local policy denials return 7. A server auth failure on a
required initial Pods or version request returns 4. Resource-level failures
yield partial evidence, code 5 unless a finding reaches the configured
threshold, in which case the exit code is 1. An invalid scope or unresolved
kubeconfig target returns 2. Missing kubectl returns 3. Snapshot modes use
local evidence and bypass live policy and kubectl.
