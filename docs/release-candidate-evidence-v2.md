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

## Exact-head validation completed before P2 (historical, not the upcoming commit)

- Validated HEAD: `602dc31d2d75a8d337388da86fb00e43c0b2cca3` (PR #77, Draft). Base/main: `f3033bb99645480cddb17d373bfe4fea4fee2952`.
- The initial candidate `a32f057fd603fccfe0c48740a8d69a8dff272bbf` failed the Linux source ZIP executable-mode contract (1 failed, 1,422 passed). The second commit restored `scripts/linux/linux-triage.sh` mode `100755` without changing its contents. First-run failures remain documented and superseded.
- All **17/17 checks** and **6/6 workflows** succeeded against the validated HEAD:

| Workflow | Exact-head successful run |
| --- | --- |
| CI | [43434595878](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595878) |
| Integration | [43434595800](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595800) |
| Security | [43434595768](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595768) |
| Documentation | [43434595867](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595867) |
| Plumber | [43434595741](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595741) |
| Release Preflight | [43434595707](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595707) |

- CI: **1,423 unit/contract tests** per Windows/Linux Python 3.11–3.13 job; Integration: **169 tests**, 25 JSON reports and 2 SARIF. Security: no known vulnerabilities in the audited graph; Plumber score 100/100 (23 passing controls).
- Preflight built and Twine-checked wheel/sdist `2.0.0rc1`; clean installs, `pip check`, four packaged JSON schemas and source ZIP reproducibility were checked. [Non-publishing artifact #14043395773](https://github.com/goozcena-gnl/devops-automation-toolkit/actions/runs/43434595707/artifacts/14043395773) (629,924 bytes). [Evidence comment](https://github.com/goozcena-gnl/devops-automation-toolkit/pull/77#issuecomment-6854545067).

## P2 follow-up: changes and fresh validation requirement

- Added shared `tools/check_release_tag.py` to fail closed on a tag mismatched with a canonical Python stable/RC version. Example: Python `2.0.0rc1` must match the future tag `v2.0.0-rc.1`; a stable version maps to a stable tag.
- `tests/unit/test_release_tag.py` adds positive, negative and workflow-wiring tests; `.github/workflows/release.yml` now calls the same checker without altering event triggers or permissions.
- **Historical successful runs above do not validate this follow-up commit.** Its final HEAD and corresponding fresh CI, Integration, Security, Documentation, Plumber, Release Preflight runs must be recorded in a later PR conversation comment after completion. Avoid embedding the current commit's own SHA in a file included in that commit.
- No cluster, runtime policy, JSON schema, release tag, merge or publication is changed or authorized by this document.
## Review and promotion boundaries

The choice of major version must be approved by a human. Any live cluster validation is out of scope for this synthetic CI phase; the reviewed [migration guide](migration-v2.md) is mandatory operator context. The PR must remain in **Draft** until evidence is complete. No commit in this branch is authorization to merge, tag or publish.
