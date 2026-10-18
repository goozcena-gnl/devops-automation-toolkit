# Testing strategy

## Test classes

- **Unit tests:** detectors, analysis rules, sanitization, policy, serialization,
  safety, and CLI behavior.
- **Contract tests:** JSON schemas and stable report interfaces for all implemented
  Python tools.
- **Integration tests:** native Linux collection, bounded Git-history scanning,
  Kubernetes collection through a disposable fake `kubectl`, and local TLS smoke testing during release validation.
- **Security regression tests:** synthetic invalid tokens, private-key markers,
  redaction, shell argument handling, and bundle sanitization.
- **Self-audits:** Secret Sentinel scans toolkit source/native scripts and GitHub
  Actions Guard audits the repository workflows.
- **Packaging tests:** wheel/sdist build, metadata check, packaged-schema inspection, and clean virtual-environment install.
- **Release contracts:** version parity, 20-tool catalog completeness, documentation ownership, and repository/package schema parity.

## Evidence boundaries

Mocked and fixture-backed tests validate deterministic behavior but do not prove
compatibility with every real provider version. The validation report explicitly
separates:

- behavior exercised locally;
- behavior parsed or statically analyzed;
- behavior delegated to GitHub-hosted Windows CI;
- behavior requiring a real Kubernetes or workstation environment.

## Commands

```bash
pytest tests/unit tests/contract
pytest -m integration --no-cov
pytest -m contract
python tools/check_docs.py
make self-audit
make validate
```

Tests use invalid synthetic credentials only. No long-lived cloud or cluster
credentials are required.

On Windows, the fake `kubectl`, module-entrypoint, and Git-history integration paths run natively. The Bash collector test is explicitly skipped and remains mandatory on the hosted Ubuntu integration job; a platform skip is not reported as a pass.

## Locked dependency updates

Development and CI installs use `requirements/dev-constraints.txt` through
`PIP_CONSTRAINT`. Keep exact pins and platform markers when updating dependencies.
Dependabot groups mypy with its `librt` and `ast-serialize` runtime dependencies,
and Pydantic with `pydantic-core`, whose version must match Pydantic's metadata.
Grouping reduces split updates; it does not guarantee that every transitive pin
will be refreshed or that the resulting graph is installable.

After an update, install with the committed constraints and run
`python tools/check_dev_constraints.py check` using the pinned uv version. If a
new requirement conflicts with another pin, inspect the package metadata and
update only the affected dependency closure. Do not remove constraints or
regenerate unrelated pins to make installation pass. The offline integration
tests cover incompatible direct/transitive pins and preservation of compatible
pins after upstream releases.

Require the Ubuntu and Windows Python 3.11–3.13 matrix, integration and security
checks on the final PR HEAD. After combining dependency PRs, validate the combined
graph again; individually passing checks do not establish combined compatibility.

## Plumber action and binary alignment

The required `workflow-lint` job runs
`python tools/check_plumber_alignment.py .github/workflows/plumber.yml` after
actionlint. This repository guard is separate from the 20-tool product catalog.
It requires a full immutable action commit and an explicit stable binary tag
`vMAJOR.MINOR.PATCH`. Missing versions, mutable refs, dynamic expressions,
prereleases, leading-zero versions, duplicate keys, aliases, custom YAML tags,
and malformed structures fail verification. Comments are not version evidence.

The guard resolves the official `getplumber/plumber` tag, including up to four
annotated-tag levels, and checks the resolved commit against the action pin.
It rereads the tag reference to detect movement during resolution. A tag already
moved to another commit also fails the pin comparison. Repeated versions in one
workflow share a resolution; no persistent or stale-success cache is used.

Inputs and each API response are limited to 128 KiB. YAML has depth/event limits.
The client permits only official tag endpoints, refuses redirects, allows at
most 12 requests, and shares a 45-second deadline with a six-second maximum socket
timeout per request/read. Deadline checks occur between bounded reads, so an
in-flight socket read can take up to its remaining timeout before failing.
The CI step has a two-minute outer limit; the existing five-minute job limit
remains sufficient for actionlint, Python setup, constrained PyYAML installation
and verification. No dependency pins or additional permissions are required:
PyYAML is already locked and the job inherits `contents: read`. Its optional
GitHub token is supplied only to the guard and is never included in diagnostics.

Exit codes are 0 for verified alignment, 1 for invalid input or mismatch, and 2
for unavailable/incomplete GitHub evidence (HTTP/rate limit, network, JSON,
size/time/request limits, tag identity/depth/cycle or movement during resolution).
Unavailable verification is a failed required check, never a warning or success.
After an outage or rate limit clears, rerun the failed job on the same HEAD.
For a moved tag or actual mismatch, review upstream provenance and update the
action SHA and binary version together in a reviewed PR. Do not bypass the check,
remove attestation or accept cached evidence to unblock a merge.

`tests/unit/test_plumber_alignment.py` exercises these contracts offline,
including malformed inputs, tag races, bounded/sanitized networking and CLI
codes on Ubuntu/Windows Python 3.11–3.13. The live official-tag check remains in
workflow-lint. Alignment does not replace the binary checksum, attestation or
runtime version evidence produced by the Plumber job.
