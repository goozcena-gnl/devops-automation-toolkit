# Terraform Plan Risk Analyzer

`plan-risk` analyzes the JSON representation produced by Terraform or OpenTofu. It never runs `apply` and does not parse terminal-formatted plans.

## Prepare input

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

## Run

```bash
devops-toolkit plan-risk tfplan.json \
  --severity-threshold high \
  --format sarif \
  --output plan-risk.sarif
```

## Detectors

- deletion and replacement, with higher severity for stateful resources;
- large replacement sets;
- public network exposure;
- wildcard IAM actions or resources;
- encryption being disabled;
- backup or retention reductions;
- sensitive output changes.

The analyzer reports evidence paths, not sensitive output values. Provider-independent rules are intentionally conservative; provider-specific extensions can be added without changing the report contract.
