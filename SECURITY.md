# Security policy

## Supported versions

| Version | Support |
|---|---|
| 1.0.x | Security fixes and compatibility corrections |
| 0.x | Historical validation artifacts only |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting when enabled, or contact the repository owner through a private channel.

Include:

- affected release or commit;
- reproduction steps using synthetic data;
- expected and observed behavior;
- potential secret exposure or infrastructure impact;
- suggested mitigation when known.

Never include a live credential, production Terraform plan, kubeconfig, diagnostic archive, or unredacted CI log in a report.

## Security invariants

Contributions and releases must preserve these invariants:

1. No full credential, token, password, private key, or discovered secret is written to output.
2. Python subprocesses are executed without `shell=True` or interpolated command strings.
3. Infrastructure and service mutation is not performed by default.
4. Production-like targets require explicit acknowledgement when a command could collect broad evidence.
5. Reports contain bounded, sanitized evidence only.
6. Temporary diagnostic material uses restrictive permissions and is cleaned up.
7. Network and external-command operations use explicit timeouts.
8. Policy exceptions require justification and expiration.
9. Incomplete evidence is marked partial rather than reported as a clean bill of health.
10. Snapshot and fixture results are not represented as live-provider proof.

## Credential model

The toolkit relies on established credential chains such as GitHub CLI authentication, Azure CLI, AWS profiles, OIDC, workload identity, or managed identity. It does not provide a plaintext credential store and does not accept cloud secret values in its configuration schema.

## Release security checks

The security workflow performs:

- Bandit analysis;
- dependency auditing with `pip-audit` when the vulnerability service is reachable;
- Python compilation;
- source and native-script self-scans with Secret Sentinel;
- full-history Gitleaks scanning;
- actionlint and ShellCheck workflow/native-shell validation;
- workflow self-audit with GitHub Actions Guard;
- configuration and report-schema validation.

The repository actions are pinned to immutable commit SHAs. A new action SHA must be reviewed before merge.

## Scope and assurance

Version 1.0.0 establishes the stable CLI and report contracts for the full 20-tool set. Deterministic fixture coverage, local integration checks, package installation, and static analysis do not prove compatibility with every provider version, operating system, Kubernetes distribution, or enterprise policy.
