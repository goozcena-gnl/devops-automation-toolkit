# SLO Budget Calculator

## Usage

`devops-toolkit slo-budget SPEC.yaml`

## Behavior

The specification selects CSV/JSON samples or Prometheus range queries. Reports distinguish no-data from zero failures and calculate compliance, budget consumption, and configured burn windows.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.
