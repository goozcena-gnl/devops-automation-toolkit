# Workstation Doctor

## Purpose

Audit a Windows 11 DevOps workstation in read-only mode and produce a normalized
JSON report compatible with the toolkit report schema.

## Usage

```powershell
./scripts/workstation/devops-workstation-audit.ps1 `
  -RequiredTools git,ssh,docker,wsl,kubectl,terraform,tofu,helm,gh,az,aws `
  -CheckAuthentication `
  -SeverityThreshold high `
  -FailOnFindings `
  -OutputPath workstation-report.json
```

## Checks

- Required executable availability, versions, and duplicate resolution paths.
- Duplicate and nonexistent PATH entries.
- Git author identity and plaintext `credential.helper=store`.
- SSH private-key ACLs without reading key contents.
- WSL distribution discovery.
- Docker engine connectivity.
- Kubernetes context inventory and production-like current-context warning.
- Optional GitHub, Azure, and AWS authentication status without serializing
  command output or tokens.

## Exit behavior

- `0`: collection completed; threshold failure is ignored unless
  `-FailOnFindings` is set.
- `1`: configured threshold exceeded with `-FailOnFindings`.
- `5`: one or more checks could not be completed.

## Security and limitations

The script does not install software, change PATH, rewrite configuration, read
private-key contents, or return account tokens. PowerShell 7+ is required.
Windows CI parses the script and runs PSScriptAnalyzer; runtime behavior must
also be tested on the target workstation because WSL, Docker Desktop, ACLs, and
installed CLIs are environment-specific.
