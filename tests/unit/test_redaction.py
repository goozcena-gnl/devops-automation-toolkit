import json
import logging

import pytest

from devops_toolkit.core.logging import RedactingFilter
from devops_toolkit.core.redaction import Redactor, fingerprint_sensitive


def test_redacts_common_credentials() -> None:
    value = "\n".join(
        [
            "Authorization: Bearer token-value-123",
            "password=hunter2",
            "github=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "aws=AKIAABCDEFGHIJKLMNOP",
        ]
    )
    result = Redactor().redact(value)
    assert "token-value-123" not in result
    assert "hunter2" not in result
    assert "ghp_" not in result
    assert "AKIAABCDEFGHIJKLMNOP" not in result
    assert "[REDACTED]" in result


def test_redacts_private_key_block() -> None:
    value = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
    result = Redactor().redact(value)
    assert "abc123" not in result
    assert result == "[REDACTED]"


def test_custom_redaction_pattern() -> None:
    result = Redactor(extra_patterns=[r"customer-[0-9]+"]).redact("customer-123")
    assert result == "[REDACTED]"


def test_fingerprint_is_stable_and_non_reversible_representation() -> None:
    first = fingerprint_sensitive("synthetic-secret")
    second = fingerprint_sensitive("synthetic-secret")
    assert first == second
    assert first.startswith("sha256:")
    assert "synthetic-secret" not in first


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "api-key",
        "client_secret",
        "clientSecret",
        "access_token",
        "refresh_token",
        "Authorization",
    ],
)
@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_quoted_credentials_are_redacted_without_changing_other_fields(
    key: str, depth: int
) -> None:
    secret = 'synthetic credential, with spaces; quotes " and slash \\ and newline\nEND'
    original = {"message": "tests failed", key: secret, "count": 7, "enabled": True}
    value = json.dumps(original)
    for _ in range(depth):
        value = json.dumps(value)
    redactor = Redactor()
    result = redactor.redact(value)
    assert redactor.redact(result) == result
    decoded = json.loads(result)
    for _ in range(depth):
        decoded = json.loads(decoded)
    assert decoded == {**original, key: "[REDACTED]"}


@pytest.mark.parametrize(
    "value",
    [
        '"synthetic secret tail"',
        "12345",
        "true",
        "null",
        '["synthetic array", {"value": "synthetic nested"}]',
        '{"nested": ["synthetic object", "]}"]}',
    ],
)
def test_sensitive_json_values_are_removed_completely(value: str) -> None:
    result = Redactor().redact('{"password": ' + value + ', "ordinary": "keep"}')
    assert json.loads(result) == {"password": "[REDACTED]", "ordinary": "keep"}


def test_embedded_escaped_json_and_unicode_keys() -> None:
    raw = '{"\\u0070assword": "synthetic unicode value", "ordinary": "keep"}'
    nested = json.dumps({"message": raw, "status": "failed"})
    text = "runner prefix " + nested + " runner suffix"
    result = Redactor().redact(text)
    decoded = json.loads(result.removeprefix("runner prefix ").removesuffix(" runner suffix"))
    assert json.loads(decoded["message"]) == {"password": "[REDACTED]", "ordinary": "keep"}
    assert decoded["status"] == "failed"


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_assignments_keep_delimiters_and_remove_whole_value(quote: str) -> None:
    text = f"password={quote}synthetic start, SYNTHETIC_END{quote}; count=7"
    assert Redactor().redact(text) == f"password={quote}[REDACTED]{quote}; count=7"
    text = f"{{{quote}password{quote}: {quote}synthetic start, SYNTHETIC_END{quote}}}"
    assert "synthetic" not in Redactor().redact(text)
    assert "SYNTHETIC_END" not in Redactor().redact(text)


def test_embedded_bare_assignment_does_not_corrupt_json() -> None:
    result = Redactor().redact('{"message": "password=synthetic-value", "count": 7}')
    assert json.loads(result) == {"message": "password=[REDACTED]", "count": 7}


def test_truncated_quoted_value_is_redacted_to_the_end() -> None:
    result = Redactor().redact('tests failed {"password": "synthetic start, SYNTHETIC_END')
    assert "synthetic" not in result
    assert "SYNTHETIC_END" not in result
    assert result.startswith('tests failed {"password": "[REDACTED]')


def test_non_sensitive_json_is_preserved_byte_for_byte() -> None:
    text = '{ "token_count": 42, "secret_name": "ordinary", "note": "password policy" }'
    assert Redactor().redact(text) == text


def test_structured_log_record_is_redacted() -> None:
    record = logging.LogRecord(
        "synthetic", logging.INFO, __file__, 1, "%s", ('{"token":"synthetic log value"}',), None
    )
    assert RedactingFilter().filter(record)
    assert "synthetic log value" not in record.getMessage()


def test_recursive_data_redaction_preserves_types_and_does_not_mutate_input() -> None:
    value = {
        "safe": [7, True, None, {"enabled": False}],
        "password": {"secret": "synthetic"},
        "nested": [{"client_secret": ["synthetic"]}],
    }
    original = json.dumps(value)
    result = Redactor().redact_data(value)
    assert result == {
        "safe": value["safe"],
        "password": "[REDACTED]",
        "nested": [{"client_secret": "[REDACTED]"}],
    }
    assert json.dumps(value) == original


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_escaped_whitespace_and_container_values(depth: int) -> None:
    value = '{"pass\\u0077ord"\n:\t{"nested": ["synthetic secret", "}"]}, "safe": 7}'
    for _ in range(depth):
        value = json.dumps(value)
    result = Redactor().redact(value)
    for _ in range(depth):
        result = json.loads(result)
    assert json.loads(result) == {"password": "[REDACTED]", "safe": 7}


def test_custom_replacement_is_json_encoded_at_each_depth() -> None:
    replacement = 'masked "quote" \\ slash'
    value = json.dumps(json.dumps({"token": "synthetic", "safe": True}))
    result = Redactor(replacement=replacement).redact(value)
    assert json.loads(json.loads(result)) == {"token": replacement, "safe": True}


@pytest.mark.parametrize(
    "encoded",
    [
        r"\u0022password\u0022: \u0022SYNTHETIC_REVIEW credential tail\u0022",
        r"\"password\"\u003a \"SYNTHETIC_REVIEW credential tail\"",
        r"\"password\":\u0020\"SYNTHETIC_REVIEW credential tail\"",
    ],
)
def test_equivalent_json_quote_separator_and_whitespace_escapes(encoded: str) -> None:
    text = '{"message": "{' + encoded + '}", "ordinary": 7}'
    result = Redactor().redact(text)
    decoded = json.loads(result)
    assert decoded["ordinary"] == 7
    assert json.loads(decoded["message"]) == {"password": "[REDACTED]"}


def test_private_key_detection_precedes_assignment_redaction() -> None:
    text = (
        "password=-----BEGIN PRIVATE KEY-----\n"
        "SYNTHETIC_PRIVATE_MATERIAL\n-----END PRIVATE KEY-----"
    )
    assert Redactor().redact(text) == "password=[REDACTED]"


def test_encoded_unquoted_password_with_a_quote_has_no_remaining_suffix() -> None:
    text = json.dumps({"message": 'password=SYNTHETIC_REVIEW_A"SYNTHETIC_REVIEW_B', "ordinary": 7})
    assert json.loads(Redactor().redact(text)) == {"message": "password=[REDACTED]", "ordinary": 7}


def test_multiline_sensitive_values_preserve_following_log_line_numbers() -> None:
    text = '{"password": {\n "nested": "synthetic"\n}}\ntests failed'
    result = Redactor().redact(text)
    assert result.count("\n") == text.count("\n")
    assert result.splitlines()[3] == "tests failed"


def test_long_malformed_container_is_sanitized() -> None:
    text = '{"password": [' + "\\" * 100_000 + "]}"
    assert json.loads(Redactor().redact(text)) == {"password": "[REDACTED]"}


def test_escaped_surrogate_in_ordinary_log_text_remains_serializable() -> None:
    text = json.dumps({"message": 'ordinary \ud800 {"password":"synthetic"}'})
    result = Redactor().redact(text)
    result.encode("utf-8")
    assert json.loads(result) == {"message": 'ordinary \ud800 {"password":"[REDACTED]"}'}


@pytest.mark.parametrize(
    "secret",
    ["SYNTHETIC[brackets]tail", "SYNTHETIC{braces}tail", 'SYNTHETIC"quote"tail', "[SYNTHETIC]tail"],
)
def test_bare_assignment_special_characters_keep_no_secret_suffix(secret: str) -> None:
    assert Redactor().redact("password=" + secret) == "password=[REDACTED]"
    text = json.dumps({"message": "password=" + secret, "ordinary": 7})
    assert json.loads(Redactor().redact(text)) == {"message": "password=[REDACTED]", "ordinary": 7}
