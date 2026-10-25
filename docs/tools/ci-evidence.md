# CI Evidence Collector

## Usage

`devops-toolkit ci-evidence --logs-dir DIR [--metadata FILE] [--bundle FILE]`

## Behavior

GitHub mode uses read-only `gh api` calls with `--repository` and `--run-id`. Logs are bounded, redacted, deduplicated, and classified without an LLM.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.

## Credential handling

Default credential keys such as `password`, `passwd`, `token`, `secret`, `api_key`,
`client_secret`, `access_token`, and `Authorization` are redacted in JSON logs,
including quoted values with spaces, nested objects/arrays, Unicode-escaped keys,
and JSON embedded as an escaped string in a text log. Ordinary fields, timestamps,
line numbers, and failure classifications remain available.

Local and downloaded metadata are sanitized before generating findings and report
extensions. The displayed log-directory target is sanitized before rendering;
the source path used for collection and ordinary displayed paths are unchanged.
Report serialization happens after redaction so that JSON remains
parseable. The same protection covers console, JSON, Markdown, SARIF, and the
`report.json`, `metadata.json`, and log members of an evidence ZIP. Credential-bearing
log names are sanitized; distinct files that sanitize to the same name retain
separate entries using a non-reversible digest suffix.

An unterminated sensitive value is redacted through the remaining text rather
than retaining a possible credential suffix. Keep a separate protected source
copy if the original evidence is required. Unlabelled secrets or arbitrary
encodings without a recognized credential key are not guaranteed to be detected.
