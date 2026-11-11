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

Missing auxiliary tools (Checkov, Trivy, yamllint, ansible-lint) remain optional.
If Terraform files are present, a missing Terraform/OpenTofu executable leaves
the formatting check incomplete. Semantic validation is `not_applicable` in
an uninitialized directory. The gate does not initialize it.

In `extensions.tools`, `validated` is true only when the validator exits
successfully and emits a complete JSON result declaring the configuration
valid with no error diagnostics. `validation_state` describes evidence
coverage, whereas `validated` describes configuration validity. A complete
structured rejection has `validation_state=complete`,
`validation_reason=rejected`, `validated=false`, and the existing
validation finding(s); it is not an incomplete collection. A contradictory
exit code, validity flag, or diagnostic result uses
`validation_state=failed` and `validation_reason=inconsistent_result`.
Missing, malformed, truncated, timed-out, or unavailable results also mark
coverage incomplete. Incomplete evidence returns exit code `5` unless a
finding reaches the configured threshold, which still returns `1`.
Unstructured validator output is not included in reports.

## Limitations

Built-in Terraform analysis is intentionally conservative and is not a full HCL
semantic evaluator. Provider-specific policy depth comes from optional scanners
and later toolkit phases.
