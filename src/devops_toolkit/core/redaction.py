"""Centralized secret redaction and non-reversible fingerprinting."""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from re import Pattern
from typing import Any

DEFAULT_REPLACEMENT = "[REDACTED]"

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "apikey",
        "clientsecret",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "authtoken",
        "bearertoken",
        "secretkey",
        "awssecretaccesskey",
        "awssessiontoken",
        "authorization",
        "proxyauthorization",
    }
)
_ASSIGNMENT = re.compile(
    r"""(?:(?<!\\)(?P<quoted>\\*["'])(?P<name>(?:[\w-]|\\+u[0-9a-f]{4})+)(?P=quoted)"""
    r"""|(?P<bare>\b(?:password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret)))"""
    r"""(?P<separator>(?:\s|\\+[nrt])*[:=](?:\s|\\+[nrt])*)""",
    re.IGNORECASE,
)
_QUOTE = re.compile(r"""\\*["']""")
_JSON_STRING = re.compile(r'(?<!\\)"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')


def _redact_json_strings(text: str, sanitize: Callable[[str], str]) -> str:
    """Decode JSON string tokens before inspecting their embedded log text."""

    def replace(match: re.Match[str]) -> str:
        decoded = json.loads(match[0])
        safe = sanitize(decoded)
        return match[0] if safe == decoded else json.dumps(safe)

    return _JSON_STRING.sub(replace, text)


def _sensitive_key(key: str) -> bool:
    return key.casefold().replace("_", "").replace("-", "") in SENSITIVE_KEYS


def _quoted_end(text: str, start: int, delimiter: str) -> tuple[int, bool]:
    """Find an unescaped closing quote at the same JSON encoding depth."""
    slashes = len(delimiter) - 1
    position = start + len(delimiter)
    while (quote := text.find(delimiter[-1], position)) != -1:
        backslash = quote
        while backslash > start and text[backslash - 1] == "\\":
            backslash -= 1
        if (quote - backslash) % (2 * (slashes + 1)) == slashes:
            return quote + 1, True
        position = quote + 1
    # Truncated or malformed evidence must not retain a sensitive value's tail.
    return len(text), False


def _shell_value_end(text: str, start: int) -> tuple[int, str, bool]:
    """Consume adjacent shell-word segments without swallowing the next command."""
    delimiter = text[start] if text[start] in "\"'" else ""
    stack: list[str] = []
    position = start
    while position < len(text):
        char = text[position]
        frame = stack[-1] if stack else ""
        if char == "\\" and frame != "'":
            position += 3 if text.startswith("\\\r\n", position) else 2
            continue
        if frame in {"'", "ansi"}:
            if char == "'":
                stack.pop()
            position += 1
            continue
        if frame and char == frame:
            stack.pop()
        elif text.startswith(("$(", "${"), position):
            stack.append(")" if text[position + 1] == "(" else "}")
            position += 2
            continue
        elif frame != '"' and text.startswith(("<(", ">("), position):
            stack.append(")")
            position += 2
            continue
        elif frame != '"' and text.startswith("$'", position):
            stack.append("ansi")
            position += 2
            continue
        elif char == "`" or (frame != '"' and char in "\"'"):
            stack.append(char)
        elif frame == ")" and char == "(":
            stack.append(")")
        elif frame == "}" and char == "{":
            stack.append("}")
        elif not stack and char in " \t\r\n;|&<>()":
            break
        position += 1
    return min(position, len(text)), delimiter, not stack


def _value_end(text: str, start: int, *, structured: bool) -> tuple[int, str, bool]:
    if not structured:
        return _shell_value_end(text, start)
    if quote := _QUOTE.match(text, start):
        end, closed = _quoted_end(text, start, quote[0])
        return end, quote[0], closed
    if structured and start < len(text) and text[start] in "[{":
        stack = ["]" if text[start] == "[" else "}"]
        position = start + 1
        while position < len(text):
            if quote := _QUOTE.match(text, position):
                position, closed = _quoted_end(text, position, quote[0])
                if not closed:
                    break
                continue
            if text[position] == "\\":
                # A malformed backslash run must be traversed only once.
                while position < len(text) and text[position] == "\\":
                    position += 1
                continue
            char = text[position]
            if char in "[{":
                stack.append("]" if char == "[" else "}")
            elif char in "]}":
                if char != stack.pop():
                    break
                if not stack:
                    return position + 1, "", True
            position += 1
        return len(text), "", False
    position = start
    delimiters = " \t\r\n,;" + ("\"'{}[]" if structured else "")
    while position < len(text) and text[position] not in delimiters:
        if text[position] == "\\":
            end = position
            while end < len(text) and text[end] == "\\":
                end += 1
            if structured and end < len(text) and text[end] in "\"'":
                break
            position = end
        else:
            position += 1
    return position, "", True


def _replacement_token(replacement: str, delimiter: str, *, closed: bool = True) -> str:
    if delimiter[-1] == '"':
        token = json.dumps(replacement, ensure_ascii=False)
    else:
        token = "'" + replacement.replace("\\", "\\\\").replace("'", "\\'") + "'"
    for _ in range((len(delimiter)).bit_length() - 1):
        token = json.dumps(token, ensure_ascii=False)[1:-1]
    return token if closed else token[: -len(delimiter)]


def _redact_assignments(text: str, replacement: str) -> str:
    parts: list[str] = []
    previous = 0
    strings = iter(_JSON_STRING.finditer(text))
    token = next(strings, None)
    for match in _ASSIGNMENT.finditer(text):
        if match.start() < previous:
            continue
        while token is not None and token.end() <= match.start():
            token = next(strings, None)
        if match["bare"] and token is not None and token.start() <= match.start():
            # Complete string tokens were sanitized at their decoded boundary.
            continue
        delimiter = match["quoted"]
        if delimiter:
            name = match["name"]
            try:
                for _ in range(len(delimiter).bit_length()):
                    name = json.loads('"' + name + '"')
            except (ValueError, RecursionError):
                continue
            if not _sensitive_key(name):
                continue
        start = match.end()
        if start == len(text):
            continue
        end, value_quote, closed = _value_end(text, start, structured=bool(delimiter))
        if end == start:
            continue
        if not delimiter and any(char in replacement for char in " \t\r\n\"'\\$`;|&<>()"):
            # Emit a single stable shell word even for a custom marker with quotes.
            safe = shlex.quote(replacement)
        elif value_quote:
            safe = _replacement_token(replacement, value_quote, closed=closed)
        elif delimiter:
            safe = _replacement_token(replacement, delimiter)
        else:
            safe = replacement
        safe += "\n" * text.count("\n", start, end)
        parts.extend((text[previous:start], safe))
        previous = end
    parts.append(text[previous:])
    return "".join(parts)


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
            if rule is DEFAULT_RULES[-1]:
                # Finish the default boundary before the existing custom rules.
                redacted = _redact_json_strings(redacted, self._redact_default_literal)
                redacted = _redact_assignments(redacted, self._replacement)
        return redacted

    def _redact_default_literal(self, value: str) -> str:
        """Inspect a decoded JSON string using only built-in credential rules."""
        redacted = value
        for rule in DEFAULT_RULES:
            replacement = rule.replacement
            if replacement == DEFAULT_REPLACEMENT:
                replacement = self._replacement
            redacted = rule.pattern.sub(replacement, redacted)
        redacted = _redact_json_strings(redacted, self._redact_default_literal)
        return _redact_assignments(redacted, self._replacement)

    def redact_data(self, value: Any) -> Any:
        """Sanitize JSON-compatible data before it is rendered or serialized."""
        if isinstance(value, dict):
            return {
                self.redact(key) if isinstance(key, str) else key: (
                    self._replacement
                    if isinstance(key, str) and _sensitive_key(key)
                    else self.redact_data(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact_data(item) for item in value]
        if isinstance(value, str):
            return self.redact(value)
        return value


def fingerprint_sensitive(value: str, namespace: str = "secret") -> str:
    """Return a stable digest without preserving the sensitive value."""

    digest = sha256(f"{namespace}\x1f{value}".encode()).hexdigest()
    return f"sha256:{digest}"


def redact_text(value: str) -> str:
    return Redactor().redact(value)
