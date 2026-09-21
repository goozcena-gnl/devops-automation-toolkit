# Release process

## Preconditions

- The version in `pyproject.toml` and `src/devops_toolkit/version.py` matches.
- `CHANGELOG.md` contains a dated entry for the release.
- The generated catalog is current.
- `requirements/dev-constraints.txt` matches `pyproject.toml`.
- Configuration examples, JSON schemas, reports, and documentation links validate.
- Unit/contract and isolated integration tests pass.
- Ruff, mypy, Bandit, native syntax checks, and repository self-audits pass.
- `pip-audit` completes in CI with network access to its vulnerability service.
- The wheel and source distribution pass `twine check`.
- Gitleaks, actionlint, ShellCheck, and pinned PSScriptAnalyzer checks pass in hosted CI.
- Two independently generated complete-source ZIPs are byte-identical.

## Local release candidate

```bash
export PIP_CONSTRAINT="$PWD/requirements/dev-constraints.txt"
python -m pip install -e '.[dev]'
make lock-check
make validate
make build
python -m twine check dist/*
python tools/build_release.py
sha256sum dist/* > dist/SHA256SUMS.txt
```

Install the wheel in a fresh environment and run at least:

```bash
devops-toolkit version
devops-toolkit health --json
devops-toolkit validate-config --config configs/examples/toolkit.example.yaml
devops-toolkit render-sample --format json --output sample.json
```

## Tag and GitHub release

1. Commit the release changes.
2. Create the annotated `v1.0.1` tag at the exact reviewed release commit.
3. Push the tag.
4. The release workflow validates, builds, checks, and hashes the distributions and complete source archive.
5. Download the validated `release-assets` artifact from the tag workflow run.
6. Create the GitHub Release manually or from an approved release-management process, attach every validated asset, and generate release notes.
7. Review the published checksums and install the attached wheel in a fresh environment.

The release must remain a draft until the release-commit checks pass. Do not create or push the `v1.0.1` tag merely to populate a draft release; tag creation is the explicit promotion gate after CI approval.

The annotated `v1.0.0` tag and its unpublished GitHub draft are immutable historical release records that predate the corrected portfolio wording. Do not edit, publish, retag, recreate, or attach assets to that draft. Version 1.0.1 is the first publishable successor.

The workflow does not publish to PyPI by default. PyPI publication should be introduced separately with trusted publishing and an explicit protected environment.

## Maintaining the locked internal toolchain

The package continues to publish compatible dependency ranges for library consumers. Reproducible CI, development, and release validation instead use `requirements/dev-constraints.txt` as an internal lock applied through `PIP_CONSTRAINT`.

When dependency ranges change, regenerate the lock with `make lock`, review the diff, and commit the updated `requirements/dev-constraints.txt` alongside the manifest change. `make lock-check` and the Python workflows enforce that the committed lock remains in sync.

## Post-release

- Confirm the GitHub Release assets and checksums.
- Verify the release tag is protected.
- Open the next `Unreleased` section.
- Record provider-specific compatibility issues without overstating untested environments.
