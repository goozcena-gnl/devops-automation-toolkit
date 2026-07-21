# IaC Drift Guard

## Purpose

Detect Terraform or OpenTofu drift using a refresh-only plan and protect operators from ambiguous workspaces, unsafe state handling, and unreviewed destructive differences.

## Usage

```bash
devops-toolkit iac-drift-guard . --binary terraform \
  --expected-workspace production --acknowledge-production
```

Analyze a previously generated machine-readable plan without running the CLI:

```bash
devops-toolkit iac-drift-guard . --plan-json drift.json
```

## Live workflow

Live mode checks the selected workspace, runs `plan -refresh-only -detailed-exitcode` into a restrictive temporary plan file, converts it with `show -json`, analyzes the JSON, and removes the temporary artifact. It never runs `apply` or `force-unlock`.

## Findings

Rules distinguish externally updated resources, remote deletion, replacement, configuration changes mixed into the plan, failed checks, permissive local state permissions, and state-lock evidence.

## Safety and limitations

Terraform plan JSON can contain sensitive values and must be protected as a secret-bearing artifact. Version 1.0.0 does not upload or retain live plan JSON automatically. Provider refresh behavior and permissions determine what drift can be observed.
