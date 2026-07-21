# GitHub Actions Guard

## Purpose

Statically inspect `.github/workflows/*.yml` and `.yaml` without executing the
workflows or contacting GitHub.

## Usage

```bash
devops-toolkit gha-guard PATH \
  --severity-threshold high \
  --format sarif \
  --output gha-guard.sarif
```

## Checks

- Invalid YAML and invalid `jobs` structures.
- Missing or broad workflow/job permissions.
- `pull_request_target` risk.
- Missing workflow concurrency and job timeouts.
- Self-hosted runners exposed to pull-request events.
- Third-party actions missing a reference or not pinned to a 40-character SHA.
- Checkout credentials left persisted.
- Upload-artifact retention not bounded.
- Direct shell interpolation of selected untrusted issue, comment, and
  pull-request properties.

## Evidence

Findings include the workflow path and best-effort source line. SARIF output can
be consumed by compatible code-scanning systems.

## Limitations

This is static analysis. It does not resolve reusable workflows over the network,
prove the provenance of a pinned commit, or fully model every expression-flow
path. A full SHA pin reduces mutability but still requires dependency review and
update governance.
