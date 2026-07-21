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
