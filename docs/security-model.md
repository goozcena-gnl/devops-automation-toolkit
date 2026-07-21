# Security model

## Threats considered

- credentials exposed in logs, findings, reports, or archives;
- command injection through filenames or user input;
- accidental execution against production;
- excessive cloud or cluster permissions;
- unbounded file, Git, API, or subprocess collection;
- diagnostic archives containing sensitive material;
- mutable CI dependencies;
- stale policy exceptions;
- false assurance from incomplete evidence.

## Controls

- no shell interpolation in the Python command runner;
- centralized redaction before serialization;
- fingerprints instead of sensitive values;
- explicit timeouts, commit bounds, file-size limits, and output limits;
- read-only defaults and production-context classification;
- namespace and context allowlists for Kubernetes collection;
- separate partial-collection status and exit code;
- schema validation for configuration and output;
- expiring policy exceptions;
- synthetic test credentials only;
- immutable full-SHA pins for GitHub Actions;
- sanitized, atomically written Kubernetes bundles.

## Credential model

The toolkit relies on external credential chains. Configuration accepts scope and
identity metadata but not credential values. Environment variables are not dumped
into diagnostics. Workstation Doctor checks authentication state but discards CLI
output, and Kubernetes Triage never requests Secret objects.

## Secret findings

Secret Sentinel retains only:

- detector identity;
- source location and line;
- confidence and severity;
- a namespaced SHA-256 fingerprint;
- remediation guidance.

It does not validate credentials against remote services because doing so would
increase exposure, side effects, and authorization requirements.

## CI dependency policy

Repository GitHub Actions are pinned to reviewed 40-character commits with a
human-readable release comment. Dependabot can propose updates, but each new SHA
still requires review.
