# Toolkit architecture interview walkthrough

Use this route to explain how the toolkit turns bounded operational evidence
into deterministic reports without presenting fixtures as live-provider proof
or turning recommendations into mutation.

## 1. Operational problem and read-only-first principle

DevOps evidence arrives through repositories, exported plans, provider CLIs,
APIs, sockets, and host-native commands. Ad hoc scripts often mix collection,
analysis, logging, and remediation, making scope and failure difficult to
reason about. This toolkit separates those concerns and defaults to read-only
or report-only behavior.

No tool implements cloud deletion, IAM mutation, Terraform/OpenTofu apply,
state unlock, Kubernetes upgrade, workload patching, or automatic remediation.
The [architecture](architecture.md) and [security invariants](../SECURITY.md)
define that boundary.

## 2. CLI, collector, analyzer, and reporter architecture

The installed `devops-toolkit` CLI and two native entry points first validate
intent and explicit scope. Command modules then coordinate narrow collectors or
adapters, deterministic analyzers and policy, and shared reporters:

```text
CLI/native entry point
  -> safety and configuration
  -> bounded collector or adapter
  -> deterministic analysis and policy
  -> normalized findings
  -> console / JSON / Markdown / SARIF reporter
```

Reporters never collect evidence, and adapters do not depend on command
modules. All Python commands share the schema `1.0` report model. The Bash and
PowerShell collectors emit the same normalized contract where applicable.

## 3. Bounded subprocesses and external calls

External commands receive argument vectors rather than interpolated shell
strings and run with `shell=False`. The shared subprocess wrapper enforces a
positive timeout, caps captured output, strips inherited test instrumentation,
and redacts stdout and stderr before returning them. A timeout or truncation is
preserved in command metadata so an analyzer can mark evidence incomplete.

HTTP and socket collectors likewise validate targets and apply explicit
timeouts. Tool-specific context, namespace, repository, account, subscription,
or region controls limit collection breadth. Missing dependencies, failed
authentication, and partial collection are distinct outcomes rather than one
generic failure.

## 4. Configuration precedence

Effective configuration follows this highest-to-lowest precedence:

1. explicit CLI arguments;
2. supported environment variables;
3. supplied YAML/JSON `--config` files, with later files overriding earlier ones;
4. built-in defaults.

The merged mapping is validated against the packaged configuration schema.
Unknown top-level and known-tool keys fail validation, so a misspelled safety
setting is not silently ignored. See [configuration](configuration.md) for the
supported environment variables and Kubernetes allowlist behavior.

## 5. Redaction before serialization

Sensitive evidence is sanitized before it reaches logs, report serializers, or
archive writers. Central rules cover private-key blocks, common token shapes,
authorization headers, credential assignments, and credential-bearing URLs;
tools add domain-specific sanitization where needed.

Secret Sentinel never stores the detected value and instead creates a
non-reversible digest for suppression and correlation. Kubernetes bundles
remove managed fields, environment values, last-applied annotations, and
secret-like keys before restrictive temporary creation and atomic movement.
Redaction reduces exposure but is not a substitute for target-specific data
handling review.

## 6. Normalized findings and remediation guidance

A finding contains a stable identifier, tool and category, severity,
confidence, resource identity, sanitized evidence, recommendation, references,
suppression state, and fingerprint. Severity describes potential impact;
confidence describes evidence strength. They remain separate so uncertain
high-impact evidence is visible without being described as confirmed fact.

Fingerprints are SHA-256 digests of stable, non-secret finding attributes. They
support deduplication and expiring exceptions. Recommendations describe an
operator-controlled next step; they are not remediation actions executed by
the toolkit. The [finding model](finding-model.md) is the concise contract.

## 7. JSON, Markdown, SARIF, and console contracts

Console, JSON, and Markdown reporters render the same normalized report. JSON
is validated against the packaged schema version `1.0`; Markdown provides a
reviewable human artifact. SARIF `2.1.0` maps finding IDs, severity, confidence,
recommendations, fingerprints, and source locations into code-scanning input
where that format is meaningful.

Checked-in reports are synthetic or fixture-backed contract examples. They
prove serialization and deterministic analysis against known inputs, not the
state of a live cloud account, cluster, repository, Prometheus service, or
workstation.

## 8. Exit codes, partial evidence, and failure behavior

The stable exit-code contract distinguishes clean execution (`0`), findings
above threshold (`1`), invalid input/configuration (`2`), unavailable required
dependencies (`3`), authentication or authorization failure (`4`), partial
collection (`5`), internal failure (`6`), and a safety-policy block (`7`).

Collectors preserve per-source failures when possible. A timed-out validator
or failed Kubernetes resource request cannot silently become a clean result;
the report marks evidence partial and returns code `5` unless a higher-priority
finding or error status applies. See [exit codes](exit-codes.md) and each tool's
limitations before scripting automation around the result.

## 9. Validation layers and evidence boundaries

- **Unit tests** exercise detectors, policy, redaction, serialization, safety,
  and CLI behavior.
- **Contract tests** validate schemas, report interfaces, version parity, the
  20-tool catalog, and repository/package schema equivalence.
- **Integration tests** cover bounded Git history, fake `kubectl`, local TLS,
  and the native Linux collector without inherited coverage instrumentation.
- **Native gates** use hosted Ubuntu for Bash/ShellCheck and hosted Windows for
  PowerShell parsing, PSScriptAnalyzer, execution, and schema checks.
- **Fixtures and snapshots** provide deterministic provider-shaped inputs with
  no live credentials.
- **Live-provider validation** remains an adoption task for the target
  environment.

The [testing strategy](testing.md), [traceability matrix](validation-matrix.md),
and [compatibility matrix](compatibility.md) record what each evidence class
does and does not prove.

## 10. Trade-offs and target-environment adoption

Read-only-first behavior lowers mutation risk but cannot prove production
safety, provider compatibility, credential availability, or complete evidence.
Bounded output protects reports but may truncate diagnostics. Conservative
static rules favor explainability over full semantic modeling. Optional local
validators expand coverage but create explicit dependency and partial-evidence
paths.

Before adoption, validate the actual provider/CLI versions, authentication and
least-privilege permissions, network and PKI behavior, context/account scope,
timeouts and output limits, report retention, redaction requirements, and local
exception policy. Live Azure, AWS, private GitHub, enterprise Prometheus,
production Terraform/OpenTofu state, production Kubernetes, private
registries, and native PowerShell behavior require target-environment evidence.
Start with a snapshot or non-production target and treat partial evidence as
incomplete rather than clean.
