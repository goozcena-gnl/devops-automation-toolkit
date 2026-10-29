"""Centralized secret redaction and non-reversible fingerprinting."""

from __future__ import annotations

import json
import math
import re
import shlex
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
from pathlib import PurePath
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
# Consume invalid escapes too, so a malformed string's closing quote is not
# mistaken for the opening quote of the next string. Validate before trusting it.
_JSON_STRING = re.compile(r'(?<!\\)"(?:[^"\\\x00-\x1f]|\\[^\x00-\x1f])*"')
_JSON_TOKEN = re.compile(_JSON_STRING.pattern + r"|[{}\[\]]")
_VALUE_WHITESPACE = " \t\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_SEPARATED_OPERATOR = re.compile(r"[;|&<>()]+(?=[" + _VALUE_WHITESPACE + "])")
_LINE_BREAK = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


def _preserve_line_breaks(original: str, replacement: str) -> str:
    missing = len(_LINE_BREAK.findall(original)) - len(_LINE_BREAK.findall(replacement))
    return replacement + "\n" * max(0, missing)


def _sub_preserving_line_breaks(pattern: Pattern[str], replacement: str, text: str) -> str:
    if pattern is _PRIVATE_KEY:
        return _redact_private_keys(text, replacement)

    def replace(match: re.Match[str]) -> str:
        return _preserve_line_breaks(match[0], match.expand(replacement))

    return pattern.sub(replace, text)


def _redact_private_keys(text: str, replacement: str) -> str:
    if not _PRIVATE_KEY.search(text):
        return text
    strings = [match for match, _ in _valid_json_strings(text)]
    starts = [match.start() for match in strings]
    containers = _verified_json_spans(text)
    token_edits: dict[int, list[tuple[int, int, str]]] = {}
    edits: list[tuple[int, int, str]] = []
    for pem in _PRIVATE_KEY.finditer(text):
        first = bisect_right(starts, pem.start()) - 1
        last = bisect_right(starts, pem.end() - 1) - 1
        in_strings = (
            first >= 0
            and strings[first].start() < pem.start() < strings[first].end() - 1
            and strings[last].start() < pem.end() <= strings[last].end() - 1
        )
        if not in_strings or (
            first != last
            and not any(start <= pem.start() and pem.end() <= end for start, end in containers)
        ):
            edits.append((pem.start(), pem.end(), _preserve_line_breaks(pem[0], replacement)))
            continue
        for index in range(first, last + 1):
            token = strings[index]
            start = max(pem.start(), token.start() + 1)
            end = min(pem.end(), token.end() - 1)
            decoded = json.loads('"' + text[start:end] + '"')
            safe = json.dumps(_preserve_line_breaks(decoded, replacement))[1:-1]
            token_edits.setdefault(index, []).append((start, end, safe))
            if index < last:
                gap_start, gap_end = token.end(), strings[index + 1].start()
                # Preserve JSON punctuation, but not scalar key material in a PEM array.
                gap = re.sub(
                    r"[^\s,\[\]{}:]+", lambda _: json.dumps(replacement), text[gap_start:gap_end]
                )
                edits.append((gap_start, gap_end, gap))
    for index, replacements in token_edits.items():
        token = strings[index]
        parts: list[str] = []
        previous = token.start()
        for start, end, safe in replacements:
            parts.extend((text[previous:start], safe))
            previous = end
        parts.append(text[previous : token.end()])
        edits.append((token.start(), token.end(), _preserve_line_breaks(token[0], "".join(parts))))
    parts = []
    previous = 0
    for start, end, safe in sorted(edits):
        parts.extend((text[previous:start], safe))
        previous = end
    parts.append(text[previous:])
    return "".join(parts)


def _verified_json_spans(text: str) -> list[tuple[int, int]]:
    """Verify disjoint enclosing containers, without retrying nested failed prefixes."""
    spans: list[tuple[int, int]] = []
    stack: list[str] = []
    start = 0
    for token in _JSON_TOKEN.finditer(text):
        char = token[0]
        if char in {"{", "["}:
            if not stack:
                start = token.start()
            stack.append("}" if char == "{" else "]")
        elif char in {"}", "]"} and stack:
            stack.pop()
            if not stack:
                end = token.end()
                if (
                    end < len(text)
                    and not text[end].isspace()
                    and not _SEPARATED_OPERATOR.match(text, end)
                ):
                    continue
                try:
                    json.loads(text[start:end])
                except (ValueError, RecursionError):
                    continue
                spans.append((start, end))
    return spans


def _valid_json_strings(text: str) -> Iterator[tuple[re.Match[str], str]]:
    for match in _JSON_STRING.finditer(text):
        try:
            decoded = json.loads(match[0])
        except ValueError:
            continue
        yield match, decoded


def _redact_json_strings(text: str, sanitize: Callable[[str], str]) -> str:
    """Decode JSON string tokens before inspecting their embedded log text."""

    parts: list[str] = []
    previous = 0
    spans = iter(_verified_json_spans(text))
    span = next(spans, None)
    for match, decoded in _valid_json_strings(text):
        if match.start() < previous:
            continue
        end = match.end()
        while span is not None and span[1] <= match.start():
            span = next(spans, None)
        verified = span is not None and span[0] <= match.start() and end <= span[1]
        safe = sanitize(decoded)
        if (
            (
                safe != decoded
                or any(_assignment_is_sensitive(item) for item in _ASSIGNMENT.finditer(decoded))
            )
            and not verified
            and end < len(text)
            and text[end] not in _VALUE_WHITESPACE
        ):
            # A sensitive JSON-looking token does not establish a separate tail.
            end, _, _ = _shell_value_end(text, match.start())
        replacement = match[0] if safe == decoded else json.dumps(safe)
        parts.extend(
            (
                text[previous : match.start()],
                _preserve_line_breaks(text[match.start() : end], replacement),
            )
        )
        previous = end
    parts.append(text[previous:])
    return "".join(parts)


def _sensitive_key(key: str) -> bool:
    return key.casefold().replace("_", "").replace("-", "") in SENSITIVE_KEYS


def _assignment_is_sensitive(match: re.Match[str]) -> bool:
    if match["bare"]:
        return True
    name = match["name"]
    try:
        for _ in range(len(match["quoted"]).bit_length()):
            name = json.loads('"' + name + '"')
    except (ValueError, RecursionError):
        return False
    return _sensitive_key(name)


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
    """Consume ambiguous log values, including shell quoting and adjacent punctuation.

    Callers do not establish shell syntax. Only whitespace-separated operators
    retain diagnostic context; an adjacent suffix may still be a credential.
    """
    delimiter = text[start] if text[start] in "\"'" else ""
    stack: list[str] = []
    position = start
    operator_end = start
    while position < len(text):
        if text.startswith("-----BEGIN", position) and (key := _PRIVATE_KEY.match(text, position)):
            position = key.end()
            continue
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
        elif not stack and char in _VALUE_WHITESPACE:
            break
        elif not stack and char in ";|&<>()":
            if position >= operator_end:
                operator_end = position + 1
                while operator_end < len(text) and text[operator_end] in ";|&<>()":
                    operator_end += 1
            if operator_end < len(text) and text[operator_end] in _VALUE_WHITESPACE:
                break
        position += 1
    return min(position, len(text)), delimiter, not stack


def _value_end(
    text: str, start: int, *, structured: bool, verified: bool = False
) -> tuple[int, str, bool]:
    if not structured:
        return _shell_value_end(text, start)
    if quote := _QUOTE.match(text, start):
        end, closed = _quoted_end(text, start, quote[0])
        if closed and not verified and end < len(text) and text[end] not in _VALUE_WHITESPACE:
            end, _, closed = _shell_value_end(text, end)
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
                    end = position + 1
                    if not verified and end < len(text) and text[end] not in _VALUE_WHITESPACE:
                        end, _, closed = _shell_value_end(text, end)
                        return end, "", closed
                    return end, "", True
            position += 1
        return len(text), "", False
    try:
        _, end = json.JSONDecoder().raw_decode(text, start)
    except (ValueError, RecursionError):
        return _shell_value_end(text, start)
    if verified or end == len(text) or text[end] in _VALUE_WHITESPACE:
        return end, "", True
    # A quoted key alone does not make its unquoted value valid JSON.
    return _shell_value_end(text, start)


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
    strings = (match for match, _ in _valid_json_strings(text))
    token = next(strings, None)
    spans = iter(_verified_json_spans(text))
    span = next(spans, None)
    for match in _ASSIGNMENT.finditer(text):
        if match.start() < previous:
            continue
        while token is not None and token.end() <= match.start():
            token = next(strings, None)
        if token is not None and token.start() < match.start() and match.end() <= token.end() - 1:
            # A complete key/separator inside a valid decoded string was
            # inspected with its value (or empty tail); crossing its boundary was not.
            continue
        delimiter = match["quoted"]
        if not _assignment_is_sensitive(match):
            continue
        start = match.end()
        if start == len(text):
            continue
        while span is not None and span[1] <= match.start():
            span = next(spans, None)
        verified = span is not None and span[0] <= match.start() and start < span[1]
        end, value_quote, closed = _value_end(
            text,
            start,
            structured=bool(delimiter) and ":" in match["separator"],
            verified=verified,
        )
        if end == start:
            continue
        if not delimiter and any(
            char in replacement for char in _VALUE_WHITESPACE + "\"'\\$`;|&<>()"
        ):
            # Emit a single stable shell word even for a custom marker with quotes.
            safe = shlex.quote(replacement)
        elif value_quote:
            safe = _replacement_token(replacement, value_quote, closed=closed)
        elif delimiter:
            safe = _replacement_token(replacement, delimiter)
        else:
            safe = replacement
        safe = _preserve_line_breaks(text[start:end], safe)
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
    RedactionRule("private-key", _PRIVATE_KEY),
    RedactionRule("github-token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{20,}\b")),
    RedactionRule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    RedactionRule(
        "authorization-header",
        re.compile(r"(?im)^(Authorization\s*:\s*)(?:Bearer|Basic)\s+[^\s]+"),
        r"\1[REDACTED]",
    ),
    RedactionRule(
        "credential-url",
        re.compile(r"""(?P<scheme>https?://)[^\s/"']+@""", re.IGNORECASE),
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
        if _PRIVATE_KEY.search(redacted):
            # Mask the whole assignment before block placeholders can split its tail.
            redacted = _redact_json_strings(redacted, self._redact_default_literal)
            redacted = _redact_assignments(redacted, self._replacement)
        for rule in self._rules:
            replacement = rule.replacement
            if replacement == DEFAULT_REPLACEMENT:
                replacement = self._replacement
            redacted = _sub_preserving_line_breaks(rule.pattern, replacement, redacted)
            if rule is DEFAULT_RULES[-1]:
                # Finish the default boundary before the existing custom rules.
                redacted = _redact_json_strings(redacted, self._redact_default_literal)
                redacted = _redact_assignments(redacted, self._replacement)
        return redacted

    def _redact_default_literal(self, value: str) -> str:
        """Inspect a decoded JSON string using only built-in credential rules."""
        redacted = value
        if _PRIVATE_KEY.search(redacted):
            redacted = _redact_json_strings(redacted, self._redact_default_literal)
            redacted = _redact_assignments(redacted, self._replacement)
        for rule in DEFAULT_RULES:
            replacement = rule.replacement
            if replacement == DEFAULT_REPLACEMENT:
                replacement = self._replacement
            redacted = _sub_preserving_line_breaks(rule.pattern, replacement, redacted)
        redacted = _redact_json_strings(redacted, self._redact_default_literal)
        return _redact_assignments(redacted, self._replacement)

    def redact_data(self, value: Any) -> Any:
        """Normalize then sanitize data; unknown objects become the replacement."""
        return self._redact_data(self._normalize_data(value))

    def _normalize_data(self, value: Any, depth: int = 0) -> Any:
        if depth > 64:
            raise ValueError("Redaction data exceeds the maximum nesting depth of 64")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("Redaction data requires string dictionary keys")
            return {key: self._normalize_data(item, depth + 1) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._normalize_data(item, depth + 1) for item in value]
        if isinstance(value, PurePath):
            return self.redact_path(str(value))
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Redaction data requires finite JSON numbers")
        if value is None or isinstance(value, (str, bool, int, float)):
            return value
        # Never invoke an unknown object's potentially unsafe/non-deterministic __str__.
        return self._replacement

    def _redact_data(self, value: Any, *, path_field: bool = False) -> Any:
        if isinstance(value, dict):
            names = {key: self.redact_path(key) for key in value}
            reserved = set(names.values())
            safe: dict[str, Any] = {}
            for key in sorted(value, key=lambda item: (item != names[item], item)):
                name = names[key]
                if name in safe:
                    digest = fingerprint_sensitive(
                        json.dumps(key, ensure_ascii=True), namespace="redaction-key"
                    ).removeprefix("sha256:")
                    candidate = f"{digest}.{name}"
                    suffix = 1
                    while candidate in safe or candidate in reserved:
                        candidate = f"{digest}.{suffix}.{name}"
                        suffix += 1
                    name = candidate
                safe[name] = (
                    self._replacement
                    if _sensitive_key(key)
                    else self._redact_data(
                        value[key],
                        path_field=bool(
                            re.search(
                                r"(?:^|[_-])"
                                r"(?:paths?|files?|file[_-]?names?|directories|directory|dirs?)$",
                                re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower(),
                            )
                        ),
                    )
                )
            return safe
        if isinstance(value, list):
            return [self._redact_data(item, path_field=path_field) for item in value]
        if isinstance(value, str):
            return self.redact_path(value) if path_field else self.redact(value)
        return value

    def redact_path(self, value: str) -> str:
        """Mask credentials through each component, not just its first whitespace."""
        url_rule = DEFAULT_RULES[-1]
        value = url_rule.pattern.sub(url_rule.replacement, value)
        parts = re.split(r"([/\\])", value)
        for index in range(0, len(parts), 2):
            component = parts[index]
            assignment = next(
                (
                    match
                    for match in _ASSIGNMENT.finditer(component)
                    if _assignment_is_sensitive(match)
                ),
                None,
            )
            extension = re.search(r"\.(?:log|txt|json|jsonl|ndjson|out|err)$", component, re.I)
            safe = self.redact(component)
            if assignment and not (
                index == len(parts) - 1
                and safe == component
                and not any(char.isspace() for char in component[assignment.end() :])
            ):
                # Drop the label so extensions and child paths survive text redaction too.
                parts[index] = (
                    self.redact(component[: assignment.start()])
                    + self._replacement
                    + (extension[0] if extension else "")
                )
            else:
                parts[index] = safe
        return self.redact("".join(parts))


def fingerprint_sensitive(value: str, namespace: str = "secret") -> str:
    """Return a stable digest without preserving the sensitive value."""

    digest = sha256(f"{namespace}\x1f{value}".encode()).hexdigest()
    return f"sha256:{digest}"


def redact_text(value: str) -> str:
    return Redactor().redact(value)
