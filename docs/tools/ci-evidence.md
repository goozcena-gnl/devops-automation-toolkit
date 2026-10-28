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
separate entries using a non-reversible digest prefix placed before the sanitized
name. These identifiers stay unchanged through repeated redaction, so report
references identify the same log members in the ZIP. Names already present are
reserved before disambiguation; case-insensitive collision checks prevent
overwrites on Windows as well as POSIX hosts. Ordinary non-colliding names are
unchanged.

Plain provider logs do not establish shell syntax. Punctuation such as `&`, `|`,
`(`, `)`, `<`, `>` and `;` immediately adjacent to a credential remains part of
that value, including concatenated quoted/unquoted segments. Operators followed
by whitespace can retain separated context such as `; count=7`. Valid JSON value
boundaries and ordinary fields remain intact when an enclosing JSON container
is structurally verified. A quoted key or punctuation alone does not establish
valid JSON: sensitive malformed fragments, including adjacent commas or closing
brackets/braces and their suffixes, are consumed conservatively. This applies
again to decoded strings inside otherwise valid JSON. Malformed source text
is not repaired into JSON; rendered reports still follow schema 1.0.
This can also hide an adjacent command or diagnostic when its boundary is
ambiguous: complete credential masking takes precedence over that context.
Whitespace still separates unquoted log values; quote values containing spaces
or supply structured metadata rather than relying on inferred shell syntax.

An unterminated sensitive value is redacted through the remaining text rather
than retaining a possible credential suffix. Keep a separate protected source
copy if the original evidence is required. Unlabelled secrets or arbitrary
encodings without a recognized credential key are not guaranteed to be detected.
