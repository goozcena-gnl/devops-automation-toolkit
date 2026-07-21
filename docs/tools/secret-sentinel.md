# Secret Sentinel

## Purpose

Detect credential-shaped material in a working tree and optionally in a bounded
number of Git commits without storing or printing the matched value.

## Usage

```bash
devops-toolkit secret-sentinel PATH \
  --history \
  --max-commits 100 \
  --exclude-dir generated \
  --baseline accepted-fingerprints.json \
  --format sarif \
  --output secret-findings.sarif
```

## Inputs

- A readable directory.
- Optional Git repository metadata.
- Optional baseline containing fingerprint strings or
  `{ "fingerprints": [...] }`.
- Optional configuration from `toolkit.example.yaml`.

## Detection

The built-in deterministic detectors cover private-key blocks, GitHub token
shapes, AWS access-key identifiers, Azure Storage connection strings, JWTs, and
generic credential assignments gated by entropy and placeholder filtering.

The working-tree scanner skips binary files, oversized files, and common build,
cache, dependency, and VCS directories. Git history scanning is disabled by
default and bounded by `--max-commits`.

## Outputs and security

- Console, JSON, Markdown, or SARIF.
- Findings contain detector identity, file or commit location, line number, and a
  stable SHA-256 fingerprint.
- Matched values are never included in findings.
- Baselines suppress by fingerprint and preserve the suppression reason.

## CI example

```bash
devops-toolkit secret-sentinel src --format sarif --output secrets.sarif
```

## Limitations

This is pattern and entropy analysis, not proof that a value is active. Binary
archives and files exceeding the configured size limit are skipped. Rotation
and Git-history rewriting remain manual, explicit remediation steps.
