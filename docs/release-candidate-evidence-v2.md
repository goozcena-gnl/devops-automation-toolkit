# B2 release-candidate preparation: v2.0.0-rc.1

**Date:** 2026-11-13. **State:** Draft preparation only; no merge, protected tag, GitHub Release or publishing.

## Immutable source and earlier validation

- Source commit on `main`: `f3033bb99645480cddb17d373bfe4fea4fee2952`.
- Candidate branch: `chore/release-v2.0.0-rc.1-prep`, created from that exact source commit.
- Historical B0 nonpublishing [Release Preflight #43430767700](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43430767700) completed successfully against that **base SHA only**; packaging wheel/sdist, clean installs, JSON schemas, locked dependency graph, and reproducible source ZIP were checked there.
- Historical `main` CI/Security/Plumber were successful. **These checks do not validate this candidate head.** Fresh B2/B3 GitHub Actions results must be recorded on the exact candidate SHA.

## Version contract

- The Python distribution and native collector metadata use PEP 440 `2.0.0rc1`.
- The future human-facing candidate tag, **if separately approved**, is `v2.0.0-rc.1`. The pinned release workflow checks that mapping.
- `schema_version: 1.0` is intentionally unchanged: the major version describes incompatible operational behavior, not a new JSON schema.
- Existing `v1.0.2` historical CHANGELOG release notes remain intact. The candidate section is explicitly unpublished.

## Scope

- Version references in Python metadata, Bash, PowerShell, CLI tests, archive contract and native collector integration test.
- All 27 version-bearing synthetic JSON/SARIF examples, retaining fixtures' evidence and schema format.
- New contract regression check for example report version coherence.
- README, changelog, compatibility matrix, the release process, and the [v2 migration guide](migration-v2.md).
- Only tag/version-string validation in `.github/workflows/release.yml`; **no** change to Kubernetes read policies, runtime collectors, security allowlists or auto-release permissions.

## Validation gates still required on the PR SHA

- CI matrix: Windows/Linux, Python 3.11–3.13; unit, contract, lint, mypy, native syntax, packaging.
- Security: Gitleaks, Bandit, dependency audit and YAML static analysis.
- Integration and documentation validations.
- Plumber CI/CD security scan.
- Read-only Release Preflight: wheel/sdist, clean installs, lock graph, deterministic ZIP, packaged schemas.
- Inspect new `CI`, `Security`, `Integration`, `Release Preflight`, and `Plumber` checks before requesting human review.
- Treat missing, skipped, or inconclusive evidence as unresolved, not PASS.

## Review and promotion boundaries

The choice of major version must be approved by a human. Any live cluster validation is out of scope for this synthetic CI phase; the reviewed [migration guide](migration-v2.md) is mandatory operator context. The PR must remain in **Draft** until evidence is complete. No commit in this branch is authorization to merge, tag or publish.
