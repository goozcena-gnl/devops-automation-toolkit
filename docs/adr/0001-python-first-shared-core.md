# ADR 0001: Python-first shared core

## Status

Accepted.

## Decision

Use an installable Python package for shared analysis, policy, configuration,
and reporting. Keep Linux and Windows host collectors in Bash and PowerShell.

## Consequences

The project gains reusable tests and consistent reports while preserving native
host access. It also introduces Python packaging maintenance and cross-language
contract testing.
