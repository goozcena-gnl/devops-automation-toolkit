# GitHub Copilot Instructions

Read and follow [AGENTS.md](../AGENTS.md) as the canonical architecture and safety contract.

For Copilot-specific work:
- preserve deterministic, report-first, read-only-first behavior;
- inspect core subprocess, redaction, configuration, schema, and reporter contracts before editing tool logic;
- do not introduce provider mutation, unsafe shell execution, credential serialization, or unbounded external calls;
- preserve report schema `1.0`, JSON, Markdown and SARIF contracts, stable exit codes, finding fingerprints, and configuration precedence unless an explicitly reviewed breaking release changes the contract;
- distinguish fixture-backed validation from live-provider validation;
- do not merge, create tags or releases, publish packages, or mutate target environments without explicit human authorization for that operation.
