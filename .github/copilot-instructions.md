# GitHub Copilot Instructions

Read and follow `AGENTS.md` as the canonical architecture and safety contract.

For Copilot-specific work:
- preserve deterministic, report-first, read-only-first behavior;
- inspect core subprocess, redaction, configuration, schema, and reporter contracts before editing tool logic;
- do not introduce provider mutation, unsafe shell execution, credential serialization, or unbounded external calls;
- preserve report-schema, exit-code, fingerprint, and configuration-precedence compatibility unless explicitly changing a documented major contract;
- distinguish fixture-backed validation from live-provider validation;
- leave merge, release, publication, and any target-environment mutation to a human.
