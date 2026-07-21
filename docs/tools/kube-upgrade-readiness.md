# Kubernetes Upgrade Readiness

## Purpose

Assess upgrade blockers and review items before changing a Kubernetes control plane or node fleet.

## Usage

```bash
devops-toolkit kube-upgrade-readiness \
  --target-version 1.33.0 \
  --context staging-cluster
```

Use `--snapshot FILE` for deterministic analysis without cluster access.

## Checks

The initial checks cover unsupported minor-version jumps, control-plane and kubelet version skew, unhealthy nodes, API versions removed by the target release, PodDisruptionBudget drain blockers, webhook review items, CRD storage-version inconsistencies, unavailable aggregated APIs, and add-on inventory.

## Safety and limitations

All live collection uses read-only `kubectl` operations and performs no upgrade, cordon, drain, rollout, or manifest change. Discovery proves only what is currently stored or exposed by the cluster; it cannot prove that external clients have stopped sending deprecated API requests. Compatibility of third-party add-ons must be verified against their own release documentation.
