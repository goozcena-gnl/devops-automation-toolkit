"""Centralized secret redaction and non-reversible fingerprinting."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from re import Pattern

DEFAULT_REPLACEMENT = "[REDACTED]"


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: Pattern[str]
    replacement: str = DEFAULT_REPLACEMENT


DEFAULT_RULES: tuple[RedactionRule, ...] = (
    RedactionRule(
        "private-key",
        re.compile(
            r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
            r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    RedactionRule("github-token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{20,}\b")),
    RedactionRule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    RedactionRule(
        "authorization-header",
        re.compile(r"(?im)^(Authorization\s*:\s*)(?:Bearer|Basic)\s+[^\s]+"),
        r"\1[REDACTED]",
    ),
    RedactionRule(
        "credential-assignment",
        re.compile(
            r"(?i)\b(password|passwd|token|secret|api[_-]?key|client[_-]?secret)"
            r"(\s*[:=]\s*)([^\s,;]+)"
        ),
        r"\1\2[REDACTED]",
    ),
    RedactionRule(
        "credential-url",
        re.compile(r"(?P<scheme>https?://)(?P<user>[^\s:/@]+):(?P<pwd>[^\s/@]+)@"),
        r"\g<scheme>[REDACTED]@",
    ),
)


class Redactor:
    """Apply default and user-supplied regular-expression rules."""

    def __init__(
        self,
        replacement: str = DEFAULT_REPLACEMENT,
        extra_patterns: list[str] | None = None,
    ) -> None:
        self._replacement = replacement
        self._rules = list(DEFAULT_RULES)
        for index, pattern in enumerate(extra_patterns or []):
            self._rules.append(RedactionRule(f"custom-{index}", re.compile(pattern), replacement))

    def redact(self, value: str) -> str:
        redacted = value
        for rule in self._rules:
            replacement = rule.replacement
            if replacement == DEFAULT_REPLACEMENT:
                replacement = self._replacement
            redacted = rule.pattern.sub(replacement, redacted)
        return redacted


def fingerprint_sensitive(value: str, namespace: str = "secret") -> str:
    """Return a stable digest without preserving the sensitive value."""

    digest = sha256(f"{namespace}\x1f{value}".encode()).hexdigest()
    return f"sha256:{digest}"


def redact_text(value: str) -> str:
    return Redactor().redact(value)
