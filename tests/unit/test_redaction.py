import json
import logging
import shlex
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from devops_toolkit.core.logging import RedactingFilter
from devops_toolkit.core.redaction import Redactor, fingerprint_sensitive


@pytest.mark.parametrize("prefix", ["", "CANARY_PREFIX"])
@pytest.mark.parametrize("quote", ["", "'", '"'])
@pytest.mark.parametrize("encoded", [False, True])
def test_private_key_line_placeholders_do_not_expose_adjacent_credential_segments(
    prefix: str, quote: str, encoded: bool
) -> None:
    value = prefix + "-----BEGIN PRIVATE KEY-----\nCANARY_KEY\n-----END PRIVATE KEY-----CANARY_TAIL"
    text = "password=" + quote + value + quote + "\nexit code 137"
    if encoded:
        text = json.dumps({"message": text, "ordinary": 7})
    safe = Redactor().redact(text)
    assert "CANARY" not in safe
    assert Redactor().redact(safe) == safe
    if encoded:
        payload = json.loads(safe)
        assert payload["ordinary"] == 7
        assert payload["message"].splitlines()[-1] == "exit code 137"
    else:
        assert len(text.splitlines()) == len(safe.splitlines())
        assert safe.splitlines()[-1] == "exit code 137"


@pytest.mark.parametrize(
    "boundary", ["\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
@pytest.mark.parametrize(
    "template",
    [
        'password="CANARY_HEAD{boundary}CANARY_TAIL"{boundary}exit code 137',
        '{{"password": [{boundary}"CANARY_HEAD"{boundary}]}}{boundary}exit code 137',
        '"password":"CANARY_HEAD{boundary}CANARY_TAIL"{boundary}exit code 137',
        "-----BEGIN PRIVATE KEY-----{boundary}CANARY_HEAD{boundary}-----END PRIVATE KEY-----{boundary}exit code 137",
    ],
)
def test_every_splitlines_boundary_survives_credential_masking(
    boundary: str, template: str
) -> None:
    from devops_toolkit.commands.ci_evidence import analyze_logs

    text = template.format(boundary=boundary)
    redactor = Redactor()
    safe = redactor.redact(text)
    assert "CANARY" not in safe
    assert len(safe.splitlines()) == len(text.splitlines())
    assert redactor.redact(safe) == safe
    findings, _, timeline = analyze_logs({"job.log": text})
    assert findings[0].evidence.line == len(text.splitlines())
    assert timeline[0]["line"] == len(text.splitlines())


@pytest.mark.parametrize(
    "field",
    [
        "path",
        "log_path",
        "LOG_PATH",
        "logPath",
        "log-path",
        "filename",
        "file_name",
        "file-name",
        "working_directory",
        "workingDirectory",
        "artifact_paths",
        "directories",
        "log_files",
    ],
)
@pytest.mark.parametrize(
    "path",
    [
        "ordinary/token=CANARY_HEAD CANARY_TAIL/job.log",
        r"C:\ordinary directory\token=CANARY_HEAD CANARY_TAIL\job.log",
        "ordinary/token=CANARY_HEAD\tCANARY_TAIL/job.log",
        "ordinary/token='CANARY_HEAD CANARY_TAIL'/job.log",
        'ordinary/"password":"CANARY_HEAD CANARY_TAIL".log',
    ],
)
def test_json_metadata_path_fields_mask_complete_components(field: str, path: str) -> None:
    redactor = Redactor()
    value = {"nested": [{"diagnostics": {field: [path, {"path": path}, [[path]]]}}]}
    safe = redactor.redact_data(value)
    assert "CANARY_HEAD" not in str(safe)
    assert "CANARY_TAIL" not in str(safe)
    assert safe["nested"][0]["diagnostics"][field][0] == redactor.redact_path(path)
    assert safe["nested"][0]["diagnostics"][field][1]["path"] == redactor.redact_path(path)
    assert safe["nested"][0]["diagnostics"][field][2][0][0] == redactor.redact_path(path)
    assert redactor.redact_data(safe) == safe
    assert redactor.redact_data(redactor.redact_data(safe)) == safe


def test_json_path_context_preserves_ordinary_diagnostics() -> None:
    value = {
        "message": "tests failed token=CANARY_HEAD count=7",
        "path": {"message": "tests failed token=CANARY_HEAD count=7"},
        "log_path": "ordinary directory/job.log",
        "profile": "tests failed token=CANARY_HEAD count=7",
        "path_count": 7,
    }
    safe = Redactor().redact_data(value)
    assert safe["message"] == safe["path"]["message"] == safe["profile"]
    assert safe["message"].endswith("count=7")
    assert safe["log_path"] == value["log_path"]
    assert safe["path_count"] == 7


class UnsupportedDiagnostic:
    def __str__(self) -> str:
        return "password=CANARY_OBJECT"


@pytest.mark.parametrize(
    "value",
    [
        ("token=CANARY_TUPLE", 7, True, None),
        Path("ordinary") / "password=CANARY_PATH",
        [{"nested": (Path("token=CANARY_NESTED"), ["secret=CANARY_LIST"])}],
        UnsupportedDiagnostic(),
    ],
)
def test_normalized_metadata_cannot_introduce_credentials(value: object) -> None:
    redactor = Redactor()
    safe = redactor.redact_data({"diagnostics": value})
    encoded = json.dumps(safe)
    assert "CANARY" not in encoded
    assert json.loads(encoded) == safe
    assert redactor.redact_data(safe) == safe
    assert "CANARY" in json.dumps({"diagnostics": value}, default=str)


@pytest.mark.parametrize("reverse", [False, True])
def test_metadata_key_collisions_preserve_all_diagnostics(reverse: bool) -> None:
    values = {
        "token=CANARY_FIRST": {"code": 137},
        "token=CANARY_SECOND": {"code": 1},
        "token=[REDACTED]": {"code": 7},
        "ordinary": {"code": 0},
        "TOKEN=CANARY_UPPER": {"code": 2},
        "caf\u00e9": {"code": 3},
        "cafe\u0301": {"code": 4},
    }
    original = {"run": values}
    if reverse:
        original = {"run": dict(reversed(list(values.items())))}
    redactor = Redactor()
    safe = redactor.redact_data(original)
    assert len(safe["run"]) == len(values)
    assert sorted(item["code"] for item in safe["run"].values()) == [0, 1, 2, 3, 4, 7, 137]
    assert safe["run"]["token=[REDACTED]"] == {"code": 7}
    assert safe["run"]["ordinary"] == {"code": 0}
    assert "CANARY" not in json.dumps(safe)
    assert safe == redactor.redact_data({"run": dict(reversed(list(values.items())))})
    for _ in range(3):
        assert redactor.redact_data(safe) == safe


@pytest.mark.parametrize("path_type", [PurePosixPath, PureWindowsPath])
def test_path_objects_with_space_containing_credentials_are_normalized_safely(path_type) -> None:
    value = path_type("ordinary directory") / "token=CANARY_HEAD CANARY_TAIL" / "child.log"
    safe = Redactor().redact_data({"path": value})
    assert "CANARY" not in json.dumps(safe)
    assert "ordinary directory" in safe["path"]
    assert safe["path"].endswith("child.log")


@pytest.mark.parametrize(
    "path",
    [
        "token=CANARY_HEAD CANARY_TAIL",
        "password=CANARY_HEAD CANARY_TAIL/child.log",
        "ordinary/token=CANARY_HEAD CANARY_TAIL/job.log",
        r"C:\ordinary directory\token=CANARY_HEAD CANARY_TAIL\job.log",
        r"\\server\share\password=CANARY_HEAD CANARY_TAIL\child.log",
        'ordinary/"password":"CANARY_HEAD",CANARY_TAIL.log',
        "ordinary/token='CANARY_HEAD'CANARY_TAIL.txt",
        "ordinary/token=CANARY_HEAD\tCANARY_TAIL.jsonl",
        "ordinary/token=CANARY_HEAD\nCANARY_TAIL",
        "ordinary/token=[REDACTED] CANARY_TAIL/child.log",
    ],
)
def test_path_redaction_preserves_structure_and_stable_extensions(path: str) -> None:
    redactor = Redactor()
    safe = redactor.redact_path(path)
    assert "CANARY" not in safe
    assert path.count("/") == safe.count("/")
    assert path.count("\\") == safe.count("\\")
    for extension in [".log", ".txt", ".jsonl"]:
        if path.endswith(extension):
            assert safe.endswith(extension)
    assert redactor.redact_path(safe) == safe
    assert redactor.redact(safe) == safe
    assert redactor.redact_data({"path": safe})["path"] == safe


@pytest.mark.parametrize(
    "path",
    ["ordinary directory/child.log", r"C:\ordinary directory\child.log", "../ordinary.log"],
)
def test_ordinary_paths_are_byte_for_byte_unchanged(path: str) -> None:
    assert Redactor().redact_path(path) == path


def test_unknown_normalization_never_invokes_string_conversion() -> None:
    class UnsafeConversion:
        def __str__(self) -> str:
            raise AssertionError("Unknown metadata conversion must not execute")

    assert Redactor().redact_data(UnsafeConversion()) == "[REDACTED]"
    assert Redactor(replacement="MASK").redact_data(UnsafeConversion()) == "MASK"


@pytest.mark.parametrize("value", [{1: "CANARY_KEY"}, float("nan"), float("inf")])
def test_invalid_metadata_fails_closed_without_credential_in_error(value: object) -> None:
    with pytest.raises(ValueError) as error:
        Redactor().redact_data(value)
    assert "CANARY" not in str(error.value)


def test_cyclic_and_excessively_nested_metadata_fail_closed() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="maximum nesting depth"):
        Redactor().redact_data(cyclic)
    nested: object = "password=CANARY_DEEP"
    for _ in range(70):
        nested = [nested]
    with pytest.raises(ValueError, match="maximum nesting depth"):
        Redactor().redact_data(nested)


def test_metadata_key_digest_collisions_and_reserved_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "devops_toolkit.core.redaction.fingerprint_sensitive", lambda *args, **kwargs: "sha256:abc"
    )
    raw = {f"token=CANARY_{index} CANARY_TAIL": index for index in range(6)}
    raw.update({"[REDACTED]": 6, "abc.[REDACTED]": 7, "abc.1.[REDACTED]": 8})
    redactor = Redactor()
    safe = redactor.redact_data({"nested": [raw]})["nested"][0]
    assert len(safe) == len(raw)
    assert sorted(safe.values()) == list(range(9))
    for key in ["[REDACTED]", "abc.[REDACTED]", "abc.1.[REDACTED]"]:
        assert safe[key] == raw[key]
    assert "CANARY" not in json.dumps(safe)
    assert redactor.redact_data(safe) == safe
    assert redactor.redact_data(dict(reversed(list(raw.items())))) == safe


@pytest.mark.parametrize(
    "path",
    [
        r'ordinary/{"\u0070assword":"CANARY_HEAD CANARY_TAIL"}/job.log',
        r'ordinary/path="bad\q" {"password":"CANARY_HEAD CANARY_TAIL"}/job.log',
        "https://ordinary:CANARY_HEAD@example.invalid/logs",
    ],
)
def test_encoded_path_fragments_and_urls_remain_redacted(path: str) -> None:
    redactor = Redactor()
    safe = redactor.redact_path(path)
    assert "CANARY" not in safe
    assert redactor.redact_path(safe) == safe
    assert redactor.redact(safe) == safe


def test_colliding_keys_with_escaped_surrogates_remain_serializable() -> None:
    raw = {f"token=CANARY{chr(0xD800 + index)}": code for index, code in enumerate([137, 1])}
    safe = Redactor().redact_data(raw)
    assert len(safe) == 2
    assert sorted(safe.values()) == [1, 137]
    assert "CANARY" not in json.dumps(safe)
    assert Redactor().redact_data(safe) == safe


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


@pytest.mark.parametrize(
    "prefix",
    [
        r'path="C:\work" ',
        'path="unmatched ',
        r'path="bad\qescape" ',
        'path="truncated\\',
        r'path="bad\u12" ',
    ],
)
@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_malformed_prefix_cannot_hide_credential_assignments(prefix: str, depth: int) -> None:
    text = (
        "tests failed " + prefix + '{"password":"CANARY_PREFIX_BYPASS tail","count":7}'
        "\nordinary context\nexit code 137"
    )
    for _ in range(depth):
        text = json.dumps({"message": text, "ordinary": [7, True, None]})
    redactor = Redactor()
    safe = redactor.redact(text)
    for _ in range(3):
        assert "CANARY" not in safe
        assert "BYPASS" not in safe
        assert "tail" not in safe
        assert safe.count("\n") == text.count("\n")
        assert redactor.redact(safe) == safe
        safe = redactor.redact(safe)
    for _ in range(depth):
        decoded = json.loads(safe)
        assert decoded["ordinary"] == [7, True, None]
        safe = decoded["message"]
    assert safe.splitlines()[1:] == ["ordinary context", "exit code 137"]


def test_valid_enclosing_json_after_windows_path_preserves_fields() -> None:
    text = r'tests failed path="C:\work" {"password":"CANARY_PREFIX_BYPASS","count":7}'
    safe = Redactor().redact(text)
    assert json.loads(safe[safe.index("{") :]) == {"password": "[REDACTED]", "count": 7}


def test_long_malformed_prefix_remains_bounded() -> None:
    text = r'path="bad\q' + "ordinary" * 10_000 + '" {"password":"CANARY_PREFIX_BYPASS"}'
    assert "CANARY" not in Redactor().redact(text)


@pytest.mark.parametrize("message", ["token=", "password=", '"password":', "token= "])
@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_empty_assignments_inside_valid_strings_remain_unchanged(message: str, depth: int) -> None:
    text = json.dumps({"message": message, "ordinary": [7, True, None]})
    for _ in range(depth):
        text = json.dumps(text)
    assert Redactor().redact(text) == text


def test_redacts_private_key_block() -> None:
    value = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
    result = Redactor().redact(value)
    assert "abc123" not in result
    assert result == "[REDACTED]\n\n"


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
    assert Redactor().redact(text) == "password=[REDACTED]\n\n"


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
    # Invalid JSON cannot prove that the final brace is separate from the secret.
    result = Redactor().redact(text)
    assert result == '{"password": "[REDACTED]"'
    assert Redactor().redact(result) == result


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


@pytest.mark.parametrize("key", ["password", "token"])
@pytest.mark.parametrize(
    ("value", "masked"),
    [
        ('"SYNTHETIC_FIRST"', '"[REDACTED]"'),
        ("SYNTHETIC_FIRST", "[REDACTED]"),
        ('"prefix"SYNTHETIC_SUFFIX', '"[REDACTED]"'),
        ("'prefix'SYNTHETIC_SUFFIX", "'[REDACTED]'"),
        ('prefix"SYNTHETIC MIDDLE"suffix', "[REDACTED]"),
        ("'SYNTHETIC_FIRST'\"SYNTHETIC_SECOND\"SYNTHETIC_THIRD", "'[REDACTED]'"),
        ("\"first\"'SYNTHETIC SECOND'SYNTHETIC_THIRD", '"[REDACTED]"'),
        (r'"SYNTHETIC_FIRST\"middle"SYNTHETIC_SUFFIX', '"[REDACTED]"'),
        (r"SYNTHETIC_FIRST\"SYNTHETIC_SUFFIX", "[REDACTED]"),
        (r'"first"\ SYNTHETIC_SUFFIX', '"[REDACTED]"'),
        (r"first\;SYNTHETIC_SUFFIX", "[REDACTED]"),
        (r"first\|SYNTHETIC_SUFFIX", "[REDACTED]"),
        (r'first\\"SYNTHETIC MIDDLE"suffix', "[REDACTED]"),
        ("'first\\'SYNTHETIC_SUFFIX", "'[REDACTED]'"),
    ],
)
def test_shell_segments_are_one_credential(key: str, value: str, masked: str) -> None:
    text = f"runner {key}={value}; count=7 --ordinary keep"
    expected = f"runner {key}={masked}; count=7 --ordinary keep"
    redactor = Redactor()
    result = redactor.redact(text)
    assert result == expected
    assert "SYNTHETIC" not in result
    assert redactor.redact(result) == result


@pytest.mark.parametrize(
    "separator", [" ", "\t", "\n", ";", "|", "||", "&", "&&", ">", ">>", "<", "(", ")"]
)
def test_shell_segments_preserve_independent_context(separator: str) -> None:
    text = 'password="prefix"SYNTHETIC_SUFFIX' + separator + "ordinary"
    redactor = Redactor()
    result = redactor.redact(text)
    # Without whitespace, an operator does not prove that the tail is not secret.
    expected = 'password="[REDACTED]"'
    if separator.isspace():
        expected += separator + "ordinary"
    assert result == expected
    assert "SYNTHETIC" not in result
    assert redactor.redact(result) == result
    separated = 'password="prefix"SYNTHETIC_SUFFIX' + separator + " ordinary"
    assert redactor.redact(separated) == 'password="[REDACTED]"' + separator + " ordinary"


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
@pytest.mark.parametrize(
    "value",
    [
        '"prefix"SYNTHETIC_SUFFIX',
        "'prefix'SYNTHETIC_SUFFIX",
        'prefix"SYNTHETIC MIDDLE"suffix',
        '"prefix"$(printf SYNTHETIC_SUFFIX)',
        '"prefix"`printf SYNTHETIC_SUFFIX`',
    ],
)
def test_shell_segments_inside_serialized_json_preserve_benign_fields(
    depth: int, value: str
) -> None:
    original = {"message": f"tests failed token={value}; count=7", "ordinary": [7, True, None]}
    text = json.dumps(original)
    for _ in range(depth):
        text = json.dumps(text)
    result = Redactor().redact(text)
    assert Redactor().redact(result) == result
    for _ in range(depth + 1):
        result = json.loads(result)
    assert result["ordinary"] == original["ordinary"]
    assert result["message"].startswith("tests failed token=")
    assert result["message"].endswith("; count=7")
    assert "SYNTHETIC" not in json.dumps(result)


@pytest.mark.parametrize(
    "value",
    [
        '"SYNTHETIC\nMIDDLE"SYNTHETIC_SUFFIX',
        "first\\\nSYNTHETIC_SUFFIX",
        "first\\\r\nSYNTHETIC_SUFFIX",
    ],
)
def test_shell_segments_preserve_following_line_locations(value: str) -> None:
    text = f"password={value}\nordinary context\ntests failed"
    result = Redactor().redact(text)
    assert "SYNTHETIC" not in result
    assert result.count("\n") == text.count("\n")
    assert result.splitlines()[-2:] == ["ordinary context", "tests failed"]
    assert Redactor().redact(result) == result


@pytest.mark.parametrize(
    "value",
    [
        '"first"SYNTHETIC_SUFFIX"truncated',
        "first'SYNTHETIC MIDDLE",
        '"SYNTHETIC MIDDLE',
        "SYNTHETIC_SUFFIX\\",
    ],
)
def test_truncated_shell_segments_leave_no_secret(value: str) -> None:
    redactor = Redactor()
    result = redactor.redact("password=" + value)
    assert "SYNTHETIC" not in result
    assert "MIDDLE" not in result
    assert "truncated" not in result
    assert redactor.redact(result) == result


def test_shell_segments_keep_custom_replacement_and_pattern_order() -> None:
    redactor = Redactor(replacement="MASK", extra_patterns=["customer-[0-9]+"])
    result = redactor.redact('password="prefix"SYNTHETIC_SUFFIX; customer-123 ordinary')
    assert result == 'password="MASK"; MASK ordinary'
    assert redactor.redact(result) == result


def test_shell_segments_are_redacted_by_logging_filter() -> None:
    record = logging.LogRecord(
        "synthetic", logging.INFO, __file__, 1, "%s", ('password="prefix"SYNTHETIC_SUFFIX',), None
    )
    assert RedactingFilter().filter(record)
    assert record.getMessage() == 'password="[REDACTED]"'


@pytest.mark.parametrize(
    "value",
    [
        '"prefix",SYNTHETIC_SUFFIX',
        '"prefix"`printf SYNTHETIC_SUFFIX`',
        '"prefix"$(printf SYNTHETIC_SUFFIX)',
        'prefix$(printf "SYNTHETIC MIDDLE")suffix',
        "\"prefix$(printf 'SYNTHETIC MIDDLE')\"suffix",
        "${name:-SYNTHETIC SUFFIX}tail",
        "prefix$((1 + SYNTHETIC_SUFFIX))tail",
        "prefix<(printf SYNTHETIC_SUFFIX)tail",
        r"$'prefix\'SYNTHETIC MIDDLE'tail",
    ],
)
def test_shell_segments_include_commas_and_nested_expansions(value: str) -> None:
    redactor = Redactor()
    result = redactor.redact("password=" + value + "; count=7")
    assert "SYNTHETIC" not in result
    assert result.endswith("; count=7")
    assert redactor.redact(result) == result


@pytest.mark.parametrize(
    "replacement", ["MASK", "masked value", "SAFE'X", 'mask "quoted" \\ slash', "$(unclosed"]
)
@pytest.mark.parametrize(
    "value",
    ['"prefix"SYNTHETIC_SUFFIX', "'prefix'SYNTHETIC_SUFFIX", 'prefix"SYNTHETIC MIDDLE"suffix'],
)
def test_shell_segments_custom_marker_is_a_stable_word(replacement: str, value: str) -> None:
    redactor = Redactor(replacement=replacement)
    result = redactor.redact("password=" + value + "; count=7")
    assert "SYNTHETIC" not in result
    assert result.endswith("; count=7")
    assert shlex.split(result.removesuffix("; count=7")) == ["password=" + replacement]
    assert redactor.redact(result) == result


@pytest.mark.parametrize("replacement", ["masked value", "SAFE'X", 'mask "quoted" \\ slash'])
def test_shell_segments_custom_marker_survives_nested_json(replacement: str) -> None:
    redactor = Redactor(replacement=replacement)
    text = json.dumps(
        json.dumps({"message": 'password=prefix"SYNTHETIC MIDDLE"suffix; count=7', "safe": 7})
    )
    result = redactor.redact(text)
    assert redactor.redact(result) == result
    value = json.loads(json.loads(result))
    assert value["safe"] == 7
    assert "SYNTHETIC" not in value["message"]
    assert shlex.split(value["message"].removesuffix("; count=7")) == ["password=" + replacement]


def test_shell_segments_many_adjacent_quotes_are_consumed() -> None:
    text = "password=" + '"segment"' * 10_000 + "SYNTHETIC_SUFFIX; ordinary"
    assert Redactor().redact(text) == 'password="[REDACTED]"; ordinary'


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=prefix&CANARY_SUFFIX", "password=[REDACTED]"),
        ("password=prefix(CANARY_SUFFIX)", "password=[REDACTED]"),
        ("token=prefix|CANARY_SUFFIX", "token=[REDACTED]"),
        ("secret=prefix<CANARY_SUFFIX", "secret=[REDACTED]"),
        ('password="prefix"CANARY_SUFFIX', 'password="[REDACTED]"'),
        ("token='prefix'CANARY_SUFFIX", "token='[REDACTED]'"),
    ],
)
def test_review_p1_requested_canaries(text: str, expected: str) -> None:
    redactor = Redactor()
    assert redactor.redact(text) == expected
    assert redactor.redact(expected) == expected


@pytest.mark.parametrize("punctuation", ["&", "&&", "|", "||", "<", ">", ">>", "(", ")", ";"])
@pytest.mark.parametrize("head", ["", "CANARY_HEAD", '"CANARY_HEAD"', "'CANARY_HEAD'"])
@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_provider_credentials_include_adjacent_punctuation(
    punctuation: str, head: str, depth: int
) -> None:
    message = f"tests failed password={head}{punctuation}CANARY_TAIL; count=7"
    text = json.dumps({"message": message, "ordinary": [7, True, None]})
    for _ in range(depth):
        text = json.dumps(text)
    redactor = Redactor()
    result = redactor.redact(text)
    assert "CANARY" not in result
    assert redactor.redact(result) == result
    for _ in range(depth + 1):
        result = json.loads(result)
    assert result["ordinary"] == [7, True, None]
    assert result["message"].startswith("tests failed password=")
    assert result["message"].endswith("; count=7")


@pytest.mark.parametrize(
    "message",
    [
        '"password"="CANARY_HEAD"CANARY_TAIL',
        '"password":"CANARY_HEAD"CANARY_TAIL',
        '"password=CANARY_HEAD"CANARY_TAIL',
        '"password=[REDACTED]"&CANARY_TAIL',
        "'token':'CANARY_HEAD'|CANARY_TAIL",
    ],
)
def test_ambiguous_quoted_tokens_include_the_credential_tail(message: str) -> None:
    redactor = Redactor()
    for text in [message, json.dumps({"message": message, "ordinary": 7})]:
        result = redactor.redact(text)
        assert "CANARY" not in result
        assert redactor.redact(result) == result
        if text.startswith("{"):
            assert json.loads(result)["ordinary"] == 7


@pytest.mark.parametrize("punctuation", ["&", "|", "<", ">", "(", ")", ";"])
def test_provider_punctuation_keeps_following_line_locations(punctuation: str) -> None:
    text = f"password=CANARY_HEAD{punctuation}CANARY_TAIL\nordinary context\nexit code 137"
    result = Redactor().redact(text)
    assert result == "password=[REDACTED]\nordinary context\nexit code 137"


def test_long_ambiguous_punctuation_and_truncated_quotes_are_bounded() -> None:
    text = "password=" + "&|<>();" * 10_000 + '"CANARY_HEAD' + "\\" * 100_000
    assert Redactor().redact(text) == "password=[REDACTED]"


@pytest.mark.parametrize(
    "text",
    [
        '"ordinary"suffix',
        json.dumps('{"ordinary":7}') + "suffix",
        json.dumps("token_count=7") + "&diagnostic",
        "ordinary/path(with)&punctuation.log",
        "tests failed; count=7 | ordinary & context",
    ],
)
def test_benign_punctuation_and_quoted_tokens_are_unchanged(text: str) -> None:
    assert Redactor().redact(text) == text


@pytest.mark.parametrize("punctuation", ["&", "|", "<", "("])
def test_provider_credentials_are_sanitized_by_logging_filter(punctuation: str) -> None:
    record = logging.LogRecord(
        "synthetic",
        logging.INFO,
        __file__,
        1,
        "%s",
        (f"password=CANARY_HEAD{punctuation}CANARY_TAIL",),
        None,
    )
    assert RedactingFilter().filter(record)
    assert record.getMessage() == "password=[REDACTED]"


@pytest.mark.parametrize("key", ['"password"', "'token'"])
@pytest.mark.parametrize(
    "value",
    [
        "CANARY_HEAD;CANARY_TAIL",
        ";CANARY_TAIL",
        "CANARY_HEAD'CANARY MIDDLE'CANARY_TAIL",
        "CANARY_HEAD[CANARY_TAIL]end",
        "${CANARY_HEAD}&CANARY_TAIL",
        "123&CANARY_TAIL",
        "true&CANARY_TAIL",
    ],
)
def test_quoted_keys_do_not_establish_a_valid_json_scalar(key: str, value: str) -> None:
    message = key + ":" + value
    redactor = Redactor()
    for text in [message, json.dumps({"message": message, "ordinary": 7})]:
        safe = redactor.redact(text)
        assert "CANARY" not in safe
        assert redactor.redact(safe) == safe
        if text.startswith("{"):
            assert json.loads(safe)["ordinary"] == 7


@pytest.mark.parametrize(
    "fragment",
    [
        '"password":"CANARY_HEAD",CANARY_TAIL',
        '"password":123,CANARY_TAIL',
        '"password":["CANARY_HEAD"],CANARY_TAIL',
        '"password":{"raw":"CANARY_HEAD"},CANARY_TAIL',
        '"password":"CANARY_HEAD"]CANARY_TAIL',
        '"password":"CANARY_HEAD"}CANARY_TAIL',
        '"password=CANARY_HEAD",CANARY_TAIL',
        '{"password":"CANARY_HEAD"}CANARY_TAIL',
    ],
)
@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_malformed_json_boundaries_mask_complete_credentials(fragment: str, depth: int) -> None:
    text = fragment + "\nordinary diagnostic\nexit code 137"
    for _ in range(depth):
        text = json.dumps({"message": text, "ordinary": [7, True, None]})
    redactor = Redactor()
    safe = redactor.redact(text)
    assert "CANARY" not in safe
    assert redactor.redact(safe) == safe
    for _ in range(depth):
        decoded = json.loads(safe)
        assert decoded["ordinary"] == [7, True, None]
        safe = decoded["message"]
    assert safe.splitlines()[1:] == ["ordinary diagnostic", "exit code 137"]


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_verified_json_boundaries_preserve_typed_diagnostics(depth: int) -> None:
    original = {
        "nested": [{"password": {"raw": ["CANARY_HEAD", 123]}, "count": 7}],
        "ordinary": [7, True, None, "diagnostic,]}suffix"],
    }
    text = "runner prefix " + json.dumps(original) + " runner suffix"
    for _ in range(depth):
        text = json.dumps({"message": text, "ordinary": False})
    redactor = Redactor()
    safe = redactor.redact(text)
    assert "CANARY" not in safe
    assert redactor.redact(safe) == safe
    for _ in range(depth):
        decoded = json.loads(safe)
        assert decoded["ordinary"] is False
        safe = decoded["message"]
    decoded = json.loads(safe.removeprefix("runner prefix ").removesuffix(" runner suffix"))
    assert decoded == {**original, "nested": [{"password": "[REDACTED]", "count": 7}]}


@pytest.mark.parametrize("suffix", ["; ordinary", "| ordinary", "&& ordinary", ") ordinary"])
@pytest.mark.parametrize("key", ["password", "message"])
@pytest.mark.parametrize("depth", [0, 1, 2])
def test_verified_json_preserves_fields_before_separated_operators(
    suffix: str, key: str, depth: int
) -> None:
    original = {key: "CANARY_HEAD" if key == "password" else "password=CANARY_HEAD", "count": 7}
    text = json.dumps(original) + suffix
    for _ in range(depth):
        text = json.dumps(text)
    redactor = Redactor()
    safe = redactor.redact(text)
    assert "CANARY" not in safe
    assert redactor.redact(safe) == safe
    for _ in range(depth):
        safe = json.loads(safe)
    assert safe.endswith(suffix)
    assert json.loads(safe.removesuffix(suffix)) == {
        key: "[REDACTED]" if key == "password" else "password=[REDACTED]",
        "count": 7,
    }
