# Architecture

## Context

The toolkit exposes 18 independently invokable Python analyzers through one package and shared CLI. Native Bash and PowerShell collectors remain first-class components and emit the same normalized report contract where applicable.

Version 1.0.0 completes the original 20-tool portfolio while preserving narrow, script-friendly command boundaries.

## Layers

1. **CLI and native entry points** validate user intent and explicit scope.
2. **Safety controls** classify production-like environments and enforce configured allowlists.
3. **Collectors and adapters** interact with files, Git, external CLIs, APIs, or sockets.
4. **Analysis and policy** transform bounded evidence into deterministic findings.
5. **Reporters** generate console, JSON, Markdown, and SARIF output.
6. **Archive writers** sanitize evidence before atomic persistence.

## Dependency direction

```text
CLI -> command modules -> collectors/adapters -> safe subprocess or bounded HTTP/socket calls
command modules -> deterministic analysis -> policy engine -> core models
command modules -> reporters/archive writers -> core models
all evidence paths -> redaction before serialization
```

Adapters must not import command modules. Reporters must not perform collection. Policy evaluation remains deterministic, and no command requires an LLM.

## Stable boundaries

- `secret-sentinel` owns file and bounded Git-history scanning. It never returns raw secret matches.
- `iac-repo-gate` owns repository inventory and validator orchestration. It never plans or applies infrastructure.
- `gha-guard` owns local workflow parsing and static rules. It performs no GitHub mutation.
- `kube-triage` owns explicit-context, read-only Kubernetes evidence and sanitized bundles. It never requests Secret objects.
- Workstation Doctor remains native PowerShell because Windows executable resolution, ACLs, WSL, and Docker Desktop integration are platform-specific.
- `plan-risk` owns Terraform/OpenTofu plan JSON analysis and never runs apply.
- `repo-baseline` owns read-only GitHub governance collection and offline snapshots.
- `kubeconfig-hygiene` owns local client-configuration analysis without credential serialization.
- `tls-audit` owns verified TLS socket inspection; untrusted inspection requires explicit opt-in.
- Linux Incident Snapshot remains native Bash for degraded-host portability.
- `image-gate`, `ci-evidence`, `prom-audit`, `slo-budget`, and `kube-rightsize` normalize security, CI, observability, and metrics evidence without remediation.
- `cloud-iam-audit`, `cloud-waste`, and `budget-guard` use provider-specific read-only collectors behind normalized evidence models.
- `iac-drift-guard` may run refresh-only plans but never apply or unlock state.
- `kube-upgrade-readiness` collects read-only cluster metadata and never upgrades, drains, or patches the cluster.

## Configuration and schemas

Configuration is merged once at the CLI boundary. Common defaults control output format, severity threshold, timeout, and color. Tool-specific sections control bounded collection and policy behavior.

The JSON schemas shipped under `src/devops_toolkit/resources/schemas/` are included in the wheel and are the runtime source of truth. Repository copies under `configs/schemas/` are contract-tested for byte-equivalent JSON content.

## Report model

Every Python analyzer emits a report containing:

- tool identity and version;
- execution status and timing metadata;
- findings with stable identifiers;
- severity and confidence as separate dimensions;
- bounded sanitized evidence;
- concrete recommendations;
- stable fingerprints for deduplication and expiring exceptions.

## CLI evolution

The flat entry points are the stable 1.x interface:

```text
devops-toolkit secret-sentinel
devops-toolkit iac-repo-gate
devops-toolkit gha-guard
devops-toolkit kube-triage
...
```

A future hierarchical interface may be introduced as aliases, but the existing flat commands should remain available throughout the 1.x series.
