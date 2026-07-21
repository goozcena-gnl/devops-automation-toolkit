# CI Evidence Collector

## Usage

`devops-toolkit ci-evidence --logs-dir DIR [--metadata FILE] [--bundle FILE]`

## Behavior

GitHub mode uses read-only `gh api` calls with `--repository` and `--run-id`. Logs are bounded, redacted, deduplicated, and classified without an LLM.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.
