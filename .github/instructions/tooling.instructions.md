---
applyTo: "src/**,scripts/**,tools/**,configs/**,tests/**,pyproject.toml,Makefile,Taskfile.yml"
---

# Toolkit Implementation Instructions

- Keep subprocess calls argument-vector based; never use `shell=True` or interpolate untrusted command strings.
- Bound external execution by timeout and output size and preserve redaction before serialization.
- Default to read-only/report-only collection; do not add cloud, Kubernetes, GitHub, or IaC mutation as an implicit capability.
- Preserve schema version, stable exit codes, fingerprints, configuration precedence, and packaged-schema equivalence unless a reviewed breaking change explicitly updates them.
- Add or change a tool only with implementation, catalog, schema/config, tests, docs, traceability, and synthetic-example coverage.
- Do not present synthetic, fixture, fake-CLI, or local-only evidence as live provider validation.
