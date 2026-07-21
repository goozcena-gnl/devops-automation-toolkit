# IaC Repository Gate

## Purpose

Provide one deterministic quality and security gate for repositories containing
Terraform, OpenTofu, YAML, Helm, and Ansible content.

## Usage

```bash
devops-toolkit iac-repo-gate PATH \
  --optional-tools \
  --severity-threshold high \
  --format json \
  --output iac-report.json
```

## Built-in checks

- Terraform/OpenTofu `required_version` constraint.
- Provider lock-file presence.
- IPv4 and IPv6 unrestricted source CIDRs.
- Credential-shaped literal assignments without retaining the value.
- YAML parseability.
- Repository technology inventory.

## External validators

When locally installed, the gate can execute:

- `tofu fmt` or `terraform fmt`;
- `tofu validate -json` or `terraform validate -json` when initialized;
- `helm lint` for discovered charts;
- Checkov;
- Trivy configuration scanning;
- yamllint;
- ansible-lint in offline mode.

Each command uses argument vectors, a timeout, bounded sanitized output, and the
repository as its working directory. The gate never runs `plan`, `apply`,
deployment, or remediation commands.

## Partial evidence

Missing optional tools are recorded as unavailable but do not make the report
partial. Timeouts or incomplete validators mark the report as partial and return
exit code `5` unless a higher-priority status applies.

## Limitations

Built-in Terraform analysis is intentionally conservative and is not a full HCL
semantic evaluator. Provider-specific policy depth comes from optional scanners
and later toolkit phases.
