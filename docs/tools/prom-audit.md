# Prometheus Auditor

## Usage

`devops-toolkit prom-audit --url URL [--expected-job JOB] [--rule-file FILE]`

## Behavior

Uses Prometheus `/api/v1/targets` and `/api/v1/rules`. Offline snapshots and optional local promtool checks are supported.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.
