# Configuration

Configuration precedence is:

1. command-line arguments;
2. supported environment variables;
3. supplied configuration files in the order provided;
4. built-in defaults.

The loader merges YAML or JSON mappings and validates the result against the
versioned schema packaged at `devops_toolkit.resources.schemas/toolkit.schema.json`.
The repository copy at `configs/schemas/toolkit.schema.json` is contract-tested
for parity and is provided for editors and external validators. Unknown top-level and known-tool keys fail
validation so misspelled security settings are not silently ignored.

## Environment variables

- `DEVOPS_TOOLKIT_SEVERITY_THRESHOLD`
- `DEVOPS_TOOLKIT_TIMEOUT_SECONDS`

## Common configuration

```yaml
version: 1
defaults:
  format: json
  severity_threshold: high
  timeout_seconds: 30
  no_color: true
safety:
  production_patterns:
    - '(?i)(^|[-_/])(prod|production|live)([-_/]|$)'
  production_allowlist: []
  require_production_acknowledgement: true
```

## Tool configuration

```yaml
tools:
  secret-sentinel:
    scan_git_history: false
    max_commits: 50
    include_ignored: false
    max_file_bytes: 1000000
    excluded_dirs: [.cache]
  iac-repo-gate:
    run_optional_tools: true
  gha-guard: {}
  kube-triage:
    allowed_namespaces: [default, platform-system]
    allowed_contexts: [development-cluster]
```

Kubernetes allowlists are safety boundaries. `--all-namespaces` is rejected when
a namespace allowlist is configured, and an explicitly requested context must
belong to the configured context allowlist.

## Validation

```bash
devops-toolkit validate-config --config configs/examples/toolkit.example.yaml
python tools/validate_examples.py
```
