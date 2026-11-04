"""Residual B02 credential boundaries, exercised only with synthetic canaries."""

from __future__ import annotations

import json

import pytest

from devops_toolkit.core.redaction import Redactor, redact_text, redact_truncated_tail

CANARY = "SYNTHETIC_B02R_CANARY"
BEGIN = "-----BEGIN PRIVATE KEY-----"
END = "-----END PRIVATE KEY-----"
COMPLETE_KEY = f"{BEGIN}\nSYNTHETIC_B02R_PEM_ZERO\n{END}\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"Authorization: token {CANARY}", "Authorization: [REDACTED]"),
        (f"    Authorization: Bearer {CANARY}", "    Authorization: [REDACTED]"),
        (
            f"2030-01-01T00:00:00.0000000Z Authorization: Basic {CANARY}",
            "2030-01-01T00:00:00.0000000Z Authorization: [REDACTED]",
        ),
        (f"> Authorization: token {CANARY}", "> Authorization: [REDACTED]"),
        (
            f'curl -H "Authorization: token {CANARY}" https://example.invalid/api',
            'curl -H "Authorization: [REDACTED]" https://example.invalid/api',
        ),
        (
            f"curl -H 'Authorization: Bearer {CANARY}' https://example.invalid/api",
            "curl -H 'Authorization: [REDACTED]' https://example.invalid/api",
        ),
        (f"Proxy-Authorization: Basic {CANARY}", "Proxy-Authorization: [REDACTED]"),
        (f'Authorization: "Bearer {CANARY}"', 'Authorization: "[REDACTED]"'),
        (f"authorization: {CANARY}", "authorization: [REDACTED]"),
        (f"X-Authorization: {CANARY}", "X-Authorization: [REDACTED]"),
        (
            f"headers\nAuthorization: Digest username=synthetic, response={CANARY}\nexit code 1",
            "headers\nAuthorization: [REDACTED]\nexit code 1",
        ),
    ],
)
def test_authorization_values_are_redacted_for_any_scheme_and_position(
    text: str, expected: str
) -> None:
    for redactor in (Redactor(), Redactor(replacement="<hidden>")):
        safe = redactor.redact(text)
        assert CANARY not in safe
        assert safe == expected
        assert safe.count("\n") == text.count("\n")
        assert redactor.redact(safe) == safe


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"Authorization: Bearer {CANARY}", "Authorization: [REDACTED]"),
        (
            f"Authorization: Bearer {CANARY} trailing context",
            "Authorization: [REDACTED]",
        ),
        (
            f"Authorization:\n  Basic {CANARY}\nexit code 1",
            "Authorization:\n  [REDACTED]\nexit code 1",
        ),
    ],
)
def test_line_start_authorization_output_is_safely_masked(text: str, expected: str) -> None:
    assert redact_text(text) == expected
    assert Redactor(replacement="<hidden>").redact(text) == expected


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_authorization_values_inside_json_strings_keep_json_valid(depth: int) -> None:
    original = {
        "command": f'curl -H "Authorization: token {CANARY}" https://example.invalid/api',
        "headers": [f"Authorization: token {CANARY}", f"Proxy-Authorization: Basic {CANARY}"],
        "trace": f"Authorization: token {CANARY}\nexit code 1",
        "count": 7,
    }
    text = json.dumps(original)
    for _ in range(depth):
        text = json.dumps(text)
    redactor = Redactor()
    safe = redactor.redact(text)
    assert CANARY not in safe
    assert safe.count("\n") == text.count("\n")
    assert redactor.redact(safe) == safe
    decoded = json.loads(safe)
    for _ in range(depth):
        decoded = json.loads(decoded)
    assert decoded == {
        "command": 'curl -H "Authorization: [REDACTED]" https://example.invalid/api',
        "headers": ["Authorization: [REDACTED]", "Proxy-Authorization: [REDACTED]"],
        "trace": "Authorization: [REDACTED]\nexit code 1",
        "count": 7,
    }


@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_TOKEN",
        "NODE_AUTH_TOKEN",
        "DB_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "access_token",
        "refresh_token",
        "id_token",
        "dbPassword",
        "accessToken",
        "SSH_PASSPHRASE",
        "private_key",
        "WEBHOOK_SECRET",
    ],
)
def test_prefixed_credential_names_are_redacted(name: str) -> None:
    redactor = Redactor()
    for text, expected in (
        (f"{name}={CANARY} exit code 1", f"{name}=[REDACTED] exit code 1"),
        (f"  {name}: {CANARY}\nexit code 1", f"  {name}: [REDACTED]\nexit code 1"),
    ):
        safe = redactor.redact(text)
        assert CANARY not in safe
        assert safe == expected
        assert redactor.redact(safe) == safe


def test_credential_query_parameters_are_redacted() -> None:
    text = f"GET https://example.invalid/callback?access_token={CANARY} 302\nexit code 1"
    expected = "GET https://example.invalid/callback?access_token=[REDACTED] 302\nexit code 1"
    assert redact_text(text) == expected


@pytest.mark.parametrize(
    "key",
    [
        "private_key",
        "x-api-key",
        "db_password",
        "github_token",
        "SecretAccessKey",
        "SessionToken",
        "passphrase",
        "webhookSecret",
        "X-Authorization",
    ],
)
def test_suffixed_sensitive_json_keys_are_redacted(key: str) -> None:
    ordinary = {"token_count": 3, "Expiration": "2030-01-01T00:00:00Z"}
    original = {"credentials": {key: CANARY, **ordinary}, "count": 7}
    expected = {"credentials": {key: "[REDACTED]", **ordinary}, "count": 7}
    redactor = Redactor()
    assert redactor.redact_data(original) == expected
    for depth in range(4):
        text = json.dumps(original)
        for _ in range(depth):
            text = json.dumps(text)
        safe = redactor.redact(text)
        assert CANARY not in safe
        assert redactor.redact(safe) == safe
        decoded = json.loads(safe)
        for _ in range(depth):
            decoded = json.loads(decoded)
        assert decoded == expected


@pytest.mark.parametrize(
    "scheme",
    [
        "postgres",
        "postgresql",
        "mysql",
        "redis",
        "rediss",
        "mongodb+srv",
        "amqp",
        "ftp",
        "ssh",
        "wss",
        "jdbc:postgresql",
    ],
)
def test_non_http_credential_urls_are_redacted(scheme: str) -> None:
    text = f"connect {scheme}://synthetic_user:{CANARY}@db.example.invalid:5432/app failed"
    safe = redact_text(text)
    assert safe == f"connect {scheme}://[REDACTED]@db.example.invalid:5432/app failed"
    assert redact_text(safe) == safe


def test_password_only_and_json_embedded_credential_urls_are_redacted() -> None:
    text = f"redis://:{CANARY}@cache.example.invalid:6379/0"
    assert redact_text(text) == "redis://[REDACTED]@cache.example.invalid:6379/0"
    document = json.dumps({"dsn": f"postgres://synthetic_user:{CANARY}@db.example.invalid/app"})
    safe = redact_text(document)
    assert json.loads(safe) == {"dsn": "postgres://[REDACTED]@db.example.invalid/app"}


@pytest.mark.parametrize(
    "text",
    [
        "token_count=3 max_tokens=4096 tokenizer: fast",
        "GITHUB_TOKEN_PRESENT=true passwordless=true secret_name=ordinary",
        '{ "token_count": 42, "secret_name": "ordinary", "secrets_used": 2 }',
        "ssh://git@github.com/org/repo.git git@github.com:org/repo.git",
        "postgres://app@db.example.invalid:5432/app redis://cache.example.invalid:6379/0",
        "https://example.invalid:8443/path?page=2 s3://bucket/key@v1",
        "WWW-Authenticate: Bearer realm=example",
    ],
)
def test_ordinary_diagnostics_are_preserved(text: str) -> None:
    assert redact_text(text) == text
    assert Redactor().redact_data({"message": text, "count": 7}) == {"message": text, "count": 7}


def test_residual_patterns_remain_bounded_on_adversarial_input() -> None:
    texts = [
        "Authorization: x" + "\\" * 100_000 + "y",
        'Authorization: "' + "\\" * 100_000,
        "Authorization: " + "\\" * 100_000 + '"',
        "x-" * 50_000 + "authorization",
        "a" * 100_000 + "_token " + "b" * 100_000,
        "postgres+" * 10_000 + "://" + "u" * 100_000,
        "ssh://" + ":" * 100_000,
    ]
    redactor = Redactor()
    for text in texts:
        safe = redactor.redact(text)
        assert redactor.redact(safe) == safe


def _complete_lines(text: str) -> int:
    return sum(1 for line in text.splitlines(keepends=True) if line.splitlines()[0] != line)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "exit code 137\npartial https://synthetic_user:SYNTHETIC_B02R_U",
            "exit code 137\n",
        ),
        ("exit code 137\n", "exit code 137\n"),
        ("no line break SYNTHETIC_B02R_TAIL", ""),
        (
            f"exit code 137\r\n{BEGIN}\r\nSYNTHETIC_B02R_PEM_ONE\r\nSYNTHETIC_B02R_PEM_T",
            "exit code 137\r\n[REDACTED]\n\n",
        ),
        (
            f"{COMPLETE_KEY}exit code 1\n{BEGIN}\nSYNTHETIC_B02R_PEM_ONE\n",
            f"{COMPLETE_KEY}exit code 1\n[REDACTED]\n\n",
        ),
        (
            f"{BEGIN}\nSYNTHETIC_B02R_PEM_ONE\n{BEGIN}\nSYNTHETIC_B02R_PEM_TWO\n",
            "[REDACTED]\n\n\n\n",
        ),
        (f"key: {BEGIN}\nSYNTHETIC_B02R_PEM_ONE\n{END[:-3]}", "key: [REDACTED]\n\n"),
    ],
)
def test_truncated_tail_drops_cut_line_and_open_private_key(text: str, expected: str) -> None:
    safe = redact_truncated_tail(text)
    assert safe == expected
    assert redact_truncated_tail(safe) == safe
    assert len(safe.splitlines()) == _complete_lines(text)
    assert "SYNTHETIC_B02R" not in Redactor().redact(safe)


def test_truncated_tail_stays_linear_for_many_open_private_keys() -> None:
    text = f"exit code 137\n{BEGIN}\n" * 50_000 + "SYNTHETIC_B02R_CUT"
    assert redact_truncated_tail(text) == "exit code 137\n[REDACTED]" + "\n" * 99_999


@pytest.mark.parametrize(
    "message",
    [
        'Authorization: Digest username=u, response="SYNTHETIC_B02R_CANARY" trailing=context',
        'Proxy-Authorization: Digest username=u, response="SYNTHETIC_B02R_CANARY"',
        'curl -H "Authorization: Digest response=\\"SYNTHETIC_B02R_CANARY\\"" https://example.invalid',
    ],
)
def test_digest_quoted_params_are_not_exposed(message: str) -> None:
    redactor = Redactor()
    safe = redactor.redact(message)
    assert CANARY not in safe
    assert "SYNTHETIC_B02R_CANARY" not in safe
    assert redactor.redact(safe) == safe


def test_json_report_numeric_and_boolean_fields_survive_sensitive_suffixes() -> None:
    original = {
        "max_token": 2048,
        "has_secret": False,
        "buildSecret": False,
        "github_token": CANARY,
        "db_password": CANARY,
        "authorization": "SYNTHETIC_B02R_CANARY",
    }
    safe = Redactor().redact_data(original)
    assert safe["max_token"] == 2048
    assert safe["has_secret"] is False
    assert safe["buildSecret"] is False
    assert safe["github_token"] == "[REDACTED]"
    assert safe["db_password"] == "[REDACTED]"
    assert safe["authorization"] == "[REDACTED]"


# B02 v2.2: standard credential names missing from the explicit v2.1 key registry.
@pytest.mark.parametrize(
    "name",
    ["GITLAB_TOKEN", "NPM_TOKEN", "CI_JOB_TOKEN", "AZURE_CLIENT_SECRET", "DOCKER_PASSWORD"],
)
def test_standard_ci_credentials_are_redacted_in_text_and_structures(name: str) -> None:
    redactor = Redactor()
    text = f"{name}={CANARY}\nexit code 137"
    expected_text = f"{name}=[REDACTED]\nexit code 137"
    assert redactor.redact(text) == expected_text
    assert redactor.redact(expected_text) == expected_text
    source = {"credentials": {name: CANARY}, "count": 7, "enabled": False}
    expected_data = {"credentials": {name: "[REDACTED]"}, "count": 7, "enabled": False}
    assert redactor.redact_data(source) == expected_data
    assert redactor.redact_data(expected_data) == expected_data
    assert json.loads(redactor.redact(json.dumps(source))) == expected_data


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"Authorization: Bearer {CANARY}_ONE {CANARY}_TWO",
            "Authorization: [REDACTED]",
        ),
        (
            f"Authorization: Basic {CANARY}_ONE {CANARY}_TWO\nexit code 1",
            "Authorization: [REDACTED]\nexit code 1",
        ),
        (
            f"Proxy-Authorization: token {CANARY}_ONE {CANARY}_TWO",
            "Proxy-Authorization: [REDACTED]",
        ),
        (
            f'curl -H "Authorization: Bearer {CANARY}_ONE {CANARY}_TWO" https://example.invalid',
            'curl -H "Authorization: [REDACTED]" https://example.invalid',
        ),
        (
            "Authorization: [REDACTED] trailing value",
            "Authorization: [REDACTED]",
        ),
    ],
)
def test_entire_authorization_value_is_redacted_without_token_tail(
    text: str, expected: str
) -> None:
    redactor = Redactor()
    safe = redactor.redact(text)
    assert safe == expected
    assert CANARY not in safe
    assert redactor.redact(safe) == safe


def test_multi_token_authorization_in_json_strings_keeps_valid_json() -> None:
    original = {
        "request": f"Authorization: Bearer {CANARY}_ONE {CANARY}_TWO",
        "command": f'curl -H "Proxy-Authorization: Basic {CANARY}_A {CANARY}_B" /health',
        "count": 7,
        "enabled": False,
    }
    expected = {
        "request": "Authorization: [REDACTED]",
        "command": 'curl -H "Proxy-Authorization: [REDACTED]" /health',
        "count": 7,
        "enabled": False,
    }
    redactor = Redactor()
    for depth in range(4):
        value = json.dumps(original)
        for _ in range(depth):
            value = json.dumps(value)
        safe = redactor.redact(value)
        assert CANARY not in safe
        assert redactor.redact(safe) == safe
        decoded = json.loads(safe)
        for _ in range(depth):
            decoded = json.loads(decoded)
        assert decoded == expected


def test_noncredential_report_fields_keep_types_under_v22() -> None:
    ordinary = {
        "max_token": 4096,
        "has_secret": False,
        "buildSecret": True,
        "gitlab_token_count": 10,
        "npm_token_name": "ordinary",
        "azure_client_secret_enabled": False,
    }
    assert Redactor().redact_data(ordinary) == ordinary


# B02 v2.3: each axis fails with a fixed label, never with rendered credential text.
_V23_CASES = (
    "multiline_bearer",
    "multiline_basic",
    "quoted_value_suffix",
    "single_quoted_suffix",
    "multiline_quoted_suffix",
    "partially_masked_multiline",
    "partially_masked_quoted",
    "shell_multiline",
    "shell_quoted_suffix",
    "shell_adjacent_suffix",
    "shell_split_bearer",
    "shell_split_basic",
)


def _v23_header_case(case: str, header: str) -> tuple[str, str]:
    first, second = "SYNTHETIC_B02V23_FIRST", "SYNTHETIC_B02V23_SECOND"
    masked = "[REDACTED]"
    cases = {
        "multiline_bearer": (
            f"{header}:\n  Bearer {first} {second}\nexit code 137",
            f"{header}:\n  {masked}\nexit code 137",
        ),
        "multiline_basic": (
            f"{header}:\r\n\tBasic {first} {second}\r\nexit code 1",
            f"{header}:\r\n\t{masked}\r\nexit code 1",
        ),
        "quoted_value_suffix": (
            f'{header}: "Bearer {first}" {second}\nexit code 1',
            f'{header}: "{masked}"\nexit code 1',
        ),
        "single_quoted_suffix": (
            f"{header}: 'Basic {first}' {second}\r\nexit code 1",
            f"{header}: '{masked}'\r\nexit code 1",
        ),
        "multiline_quoted_suffix": (
            f'{header}:\r\n  "Basic {first}" {second}\r\nexit code 1',
            f'{header}:\r\n  "{masked}"\r\nexit code 1',
        ),
        "partially_masked_multiline": (
            f"{header}:\n  {masked} {second}\nexit code 1",
            f"{header}:\n  {masked}\nexit code 1",
        ),
        "partially_masked_quoted": (
            f'{header}: "{masked}" {second}\nexit code 1',
            f'{header}: "{masked}"\nexit code 1',
        ),
        "shell_multiline": (
            f'curl -H "{header}:\r\n  Bearer {first} {second}" https://example.invalid',
            f'curl -H "{header}:\r\n  {masked}" https://example.invalid',
        ),
        "shell_quoted_suffix": (
            f"curl -H '{header}: \"Bearer {first}\" {second}' https://example.invalid",
            f"curl -H '{header}: {masked}' https://example.invalid",
        ),
        "shell_split_bearer": (
            f"curl -H \"{header}: \"'Bearer {first} {second}' https://example.invalid",
            f'curl -H "{header}: " https://example.invalid',
        ),
        "shell_split_basic": (
            f"curl -H \"{header}: \"'Basic {first} {second}' https://example.invalid",
            f'curl -H "{header}: " https://example.invalid',
        ),
        "shell_adjacent_suffix": (
            f'curl -H "{header}: Bearer {first}"{second} https://example.invalid',
            f'curl -H "{header}: {masked}" https://example.invalid',
        ),
    }
    return cases[case]


def _v23_require(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)


@pytest.mark.parametrize("case", _V23_CASES)
@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization"])
@pytest.mark.parametrize("replacement", ["[REDACTED]", "<hidden>"])
@pytest.mark.parametrize("axis", ["canary_leak", "idempotence", "format"])
def test_v23_authorization_boundaries(case: str, header: str, replacement: str, axis: str) -> None:
    source, expected = _v23_header_case(case, header)
    redactor = Redactor(replacement=replacement)
    safe = redactor.redact(source)
    if axis == "canary_leak":
        _v23_require("SYNTHETIC_B02V23" not in safe, "credential canary leaked")
    elif axis == "idempotence":
        _v23_require(redactor.redact(safe) == safe, "redaction is not idempotent")
    else:
        _v23_require(safe == expected, "header or diagnostic format changed")
        _v23_require(safe.count("\r\n") == source.count("\r\n"), "CRLF changed")
        _v23_require(safe.count("\n") == source.count("\n"), "line count changed")


@pytest.mark.parametrize("case", _V23_CASES)
@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization"])
@pytest.mark.parametrize("depth", range(4))
def test_v23_headers_in_nested_json(case: str, header: str, depth: int) -> None:
    source, expected = _v23_header_case(case, header)
    ordinary = {"count": 7, "enabled": False, "max_token": 4096, "message": "tests failed"}
    text = json.dumps({"trace": source, **ordinary})
    for _ in range(depth):
        text = json.dumps(text)
    redactor = Redactor()
    safe = redactor.redact(text)
    _v23_require("SYNTHETIC_B02V23" not in safe, "nested credential canary leaked")
    _v23_require(redactor.redact(safe) == safe, "nested redaction is not idempotent")
    decoded = json.loads(safe)
    for _ in range(depth):
        decoded = json.loads(decoded)
    _v23_require(decoded == {"trace": expected, **ordinary}, "nested JSON structure changed")


def test_v23_ordinary_diagnostics_keep_values_and_types() -> None:
    ordinary = {
        "count": 7,
        "enabled": False,
        "ready": True,
        "ratio": 1.5,
        "nothing": None,
        "max_token": 4096,
        "has_secret": False,
        "buildSecret": True,
        "message": "exit code 137\r\ntests failed\nretry 2",
        "command": 'curl -H "Accept: application/json" https://example.invalid',
        "challenge": "WWW-Authenticate: Bearer realm=example",
    }
    redactor = Redactor()
    _v23_require(redactor.redact_data(ordinary) == ordinary, "ordinary typed fields changed")
    text = json.dumps(ordinary)
    _v23_require(redactor.redact(text) == text, "ordinary JSON bytes changed")
    for value in ordinary.values():
        if isinstance(value, str):
            _v23_require(redactor.redact(value) == value, "ordinary diagnostic changed")


def test_v23_large_headers_keep_no_tail_and_remain_idempotent() -> None:
    # The validation runner enforces a process timeout; do not depend on CPU-speed assertions.
    source, expected = _v23_header_case("multiline_basic", "Proxy-Authorization")
    text = (source + "\r\n") * 5000
    redactor = Redactor()
    safe = redactor.redact(text)
    _v23_require("SYNTHETIC_B02V23" not in safe, "large input credential leaked")
    _v23_require(safe == (expected + "\r\n") * 5000, "large input format changed")
    _v23_require(redactor.redact(safe) == safe, "large input redaction is not idempotent")
    malformed = 'Proxy-Authorization:\r\n  "' + "\\" * 100_000
    masked = redactor.redact(malformed)
    _v23_require(redactor.redact(masked) == masked, "large malformed header is not stable")
