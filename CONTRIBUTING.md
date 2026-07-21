# Contributing

## Workflow

1. Create an issue describing the operational problem and safety implications.
2. Add or update an architecture decision record for cross-cutting changes.
3. Implement deterministic logic and synthetic fixtures.
4. Add unit, contract, and integration tests as appropriate.
5. Run `make validate` before opening a pull request.

## Definition of done

- Inputs are validated.
- Exit codes follow `docs/exit-codes.md`.
- Output conforms to the report schema.
- Sensitive values are redacted before logging and serialization.
- External calls have timeouts.
- Partial results are explicit.
- Documentation lists permissions, limitations, and failure modes.
- Tests do not contain live credentials.

## Commit and release conventions

Use Conventional Commits. Releases follow semantic versioning. User-visible
changes must be added to `CHANGELOG.md`.
