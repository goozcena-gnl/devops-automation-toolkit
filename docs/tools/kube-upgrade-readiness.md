# Kubernetes Upgrade Readiness

## Purpose

Assess upgrade blockers and review items before changing a Kubernetes control plane or node fleet.

## Usage

```bash
devops-toolkit kube-upgrade-readiness \
  --target-version 1.33.0 \
  --config kubernetes.yaml \
  --context staging-cluster
```

For live collection, set `tools.kube-upgrade-readiness.allow_cluster_scope: true`
in the effective configuration. The tool uses the named context or the
kubeconfig's configured current context. A namespace allowlist is incompatible
with the required all-namespace PDB list. See
[the live Kubernetes policy](../kubernetes-read-scope.md).

Use `--snapshot FILE` for deterministic analysis without cluster access.

## Checks

The initial checks cover unsupported minor-version jumps, control-plane and kubelet version skew, unhealthy nodes, API versions removed by the target release, PodDisruptionBudget drain blockers, webhook review items, CRD storage-version inconsistencies, unavailable aggregated APIs, and add-on inventory.

## Safety and limitations

All live collection uses read-only `kubectl` operations and performs no upgrade, cordon, drain, rollout, or manifest change. Discovery proves only what is currently stored or exposed by the cluster; it cannot prove that external clients have stopped sending deprecated API requests. Compatibility of third-party add-ons must be verified against their own release documentation.

Live reads cover server version and discovery, Nodes, all-namespace PDBs, CRDs,
admission webhooks, APIService, and Deployments, StatefulSets and DaemonSets
in `kube-system`. Grant the live identity read permissions only for these
surfaces. A version authorization failure returns exit 4. Missing version
evidence yields a partial report without a readiness verdict. Other read
failures appear in `collection_notes`, and findings at the configured threshold
take precedence over the partial exit code. Live discovery alone leaves
external deprecated API usage unverified.
