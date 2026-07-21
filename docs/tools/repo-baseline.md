# GitHub Repository Baseline

`repo-baseline` uses authenticated, read-only GitHub CLI API requests to audit repository governance.

```bash
gh auth status
devops-toolkit repo-baseline OWNER/REPOSITORY \
  --format json \
  --output repository-baseline.json
```

For deterministic testing or review without network access:

```bash
devops-toolkit repo-baseline \
  --snapshot repository-snapshot.json \
  --format markdown
```

## Baseline areas

- default-branch protection and active rulesets;
- pull-request approvals, code-owner review, status checks, and conversation resolution;
- force-push and branch-deletion controls;
- `SECURITY.md`, `CODEOWNERS`, and Dependabot configuration;
- default GitHub Actions permissions and workflow PR approval;
- secret scanning, push protection, and Dependabot security updates when metadata is available.

Unavailable API areas are recorded as partial collection. The command never changes repository settings.
