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
extensions. Provider JSON is parsed before structural redaction so text masking
cannot collapse distinct keys before they can be disambiguated. Provider error
details are explicitly redacted before display. The displayed log-directory target is sanitized before rendering;
the source path used for collection and ordinary displayed paths are unchanged.
Path redaction treats both `/` and `\` as separators and masks a credential
through the rest of its component, including internal spaces. Ordinary directory
names and child paths remain available. Recognized log extensions (`.log`, `.txt`,
`.json`, `.jsonl`, `.ndjson`, `.out`, `.err`) are retained; credential-bearing
components may lose their assignment label to keep identifiers stable through
later text redaction. Log identifiers use `/` separators on all hosts; repeated
separators and `.` components are normalized to match archive member paths.
This intentionally changes identifiers for previously incompletely masked paths,
not benign paths or their fingerprints.
Displayed output-file and bundle paths use the same path masking on stdout and
stderr; the actual source and destination paths are never rewritten.
Report serialization happens after redaction so that JSON remains
parseable. The same protection covers console, JSON, Markdown, SARIF, and the
`report.json`, `metadata.json`, and log members of an evidence ZIP. Credential-bearing
log names are sanitized; distinct files that sanitize to the same name retain
separate entries using a non-reversible digest prefix placed before the sanitized
name. These identifiers stay unchanged through repeated redaction, so report
references identify the same log members in the ZIP. Names already present are
reserved before disambiguation, including their parent directories.
Case-insensitive collision checks handle both identical names and files that
would occupy another log's ancestor directory, preventing overwrites or failed
bundle writes on Windows as well as POSIX hosts. Ordinary non-colliding names
are unchanged.

Direct Python metadata inputs are normalized before recursive redaction: tuples
become JSON arrays, `pathlib` paths become component-redacted strings, and dates
and timestamps use ISO 8601 strings. JSON scalars, arrays and objects retain
their types. Unknown objects become the replacement marker without invoking
`str()`; archive serialization has no later string-conversion fallback.
Non-string dictionary keys, non-finite numbers, cycles and nesting beyond 64
levels fail explicitly rather than emitting ambiguous or unsafe metadata.
JSON object keys remain case-sensitive and Unicode-distinct. Colliding sanitized
keys retain all values using a non-reversible digest prefix with a numeric
fallback; existing safe keys are reserved first. Repeated sanitization preserves
those keys and diagnostics. JSON strings in recognized path fields also use
component-aware masking: `path`, `file`, `filename`, `directory`, `dir`, their
plurals, and underscore/hyphen-delimited suffixes such as `log_path` or
`artifact_paths`. Camel-case forms such as `logPath` and `workingDirectory`
and case variants are recognized. Path context passes through arrays, including
nested arrays; nested objects use their own field names so ordinary `message`
diagnostics retain text-log rules. Other string fields keep text-log rules;
use `pathlib` values for direct Python paths without a recognized field name.

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
Malformed quoted prefixes, including invalid JSON escapes, do not exempt a
following credential assignment from redaction. Only assignments contained
inside valid strings already inspected in decoded form can be exempted.
This can also hide an adjacent command or diagnostic when its boundary is
ambiguous: complete credential masking takes precedence over that context.
Whitespace still separates unquoted log values; quote values containing spaces
or supply structured metadata rather than relying on inferred shell syntax.

An unterminated sensitive value is redacted through the remaining text rather
than retaining a possible credential suffix. Keep a separate protected source
copy if the original evidence is required. Unlabelled secrets or arbitrary
encodings without a recognized credential key are not guaranteed to be detected.
