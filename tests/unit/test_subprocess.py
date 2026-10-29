import json
import subprocess
import sys

import pytest

from devops_toolkit.core.subprocess import run_command


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\r\n"])
@pytest.mark.parametrize("array", [False, True])
def test_pem_provider_json_remains_parseable_in_both_streams(
    monkeypatch: pytest.MonkeyPatch, separator: str, array: bool
) -> None:
    lines = ["-----BEGIN PRIVATE KEY-----", "CANARY_KEY", "-----END PRIVATE KEY-----"]
    output = json.dumps(
        {"pem": lines if array else separator.join(lines), "ordinary": 7},
        ensure_ascii=False,
        indent=2,
    )

    def execute(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["synthetic"], 0, output, output)

    monkeypatch.setattr(subprocess, "run", execute)
    result = run_command([sys.executable, "-V"])
    assert result.succeeded
    for stream in [result.stdout, result.stderr]:
        assert json.loads(stream)["ordinary"] == 7
        assert "CANARY" not in stream
        assert len(stream.splitlines()) == len(output.splitlines())


def test_safe_command_execution_and_redaction() -> None:
    script = "print('password=synthetic-value')"
    result = run_command([sys.executable, "-c", script], timeout_seconds=5)
    assert result.succeeded
    assert "synthetic-value" not in result.stdout
    assert "[REDACTED]" in result.stdout


def test_output_is_bounded() -> None:
    script = "print('x' * 1000)"
    result = run_command(
        [sys.executable, "-c", script],
        timeout_seconds=5,
        max_output_chars=100,
    )
    assert result.truncated is True
    assert "OUTPUT TRUNCATED" in result.stdout


def test_non_utf8_output_is_replaced_without_crashing() -> None:
    script = "import sys; sys.stdout.buffer.write(b'valid\\xfftail')"
    result = run_command([sys.executable, "-c", script], timeout_seconds=5)
    assert result.succeeded
    assert result.stdout == "valid\ufffdtail"


def test_timeout_is_reported() -> None:
    script = "import time; time.sleep(1)"
    result = run_command([sys.executable, "-c", script], timeout_seconds=0.05)
    assert result.timed_out is True
    assert result.returncode == 124


@pytest.mark.parametrize("timeout", [False, True])
def test_structured_credentials_are_sanitized_in_both_streams(
    monkeypatch: pytest.MonkeyPatch, timeout: bool
) -> None:
    marker = "SYNTHETIC_SUBPROCESS_B02 value"
    output = json.dumps({"password": marker, "ordinary": "keep"})

    def execute(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        if timeout:
            raise subprocess.TimeoutExpired(["synthetic"], 1, output=output, stderr=output)
        return subprocess.CompletedProcess(["synthetic"], 0, output, output)

    monkeypatch.setattr(subprocess, "run", execute)
    result = run_command([sys.executable, "-V"])
    for stream in [result.stdout, result.stderr]:
        assert marker not in stream
        assert json.loads(stream) == {"password": "[REDACTED]", "ordinary": "keep"}
    assert result.returncode == (124 if timeout else 0)


@pytest.mark.parametrize("timeout", [False, True])
def test_shell_segments_are_sanitized_in_both_subprocess_streams(
    monkeypatch: pytest.MonkeyPatch, timeout: bool
) -> None:
    output = 'password="prefix"SYNTHETIC_SUFFIX; ordinary'

    def execute(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        if timeout:
            raise subprocess.TimeoutExpired(["synthetic"], 1, output=output, stderr=output)
        return subprocess.CompletedProcess(["synthetic"], 0, output, output)

    monkeypatch.setattr(subprocess, "run", execute)
    result = run_command([sys.executable, "-V"])
    assert result.stdout == result.stderr == 'password="[REDACTED]"; ordinary'
    assert result.returncode == (124 if timeout else 0)


@pytest.mark.parametrize("timeout", [False, True])
@pytest.mark.parametrize("encoded", [False, True])
def test_provider_punctuation_is_sanitized_in_both_subprocess_streams(
    monkeypatch: pytest.MonkeyPatch, timeout: bool, encoded: bool
) -> None:
    output = "password=CANARY_HEAD&CANARY_TAIL; ordinary\ntoken=CANARY_OTHER|CANARY_END"
    if encoded:
        output = json.dumps({"message": output, "ordinary": 7})

    def execute(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        if timeout:
            raise subprocess.TimeoutExpired(["synthetic"], 1, output=output, stderr=output)
        return subprocess.CompletedProcess(["synthetic"], 0, output, output)

    monkeypatch.setattr(subprocess, "run", execute)
    result = run_command([sys.executable, "-V"])
    assert result.returncode == (124 if timeout else 0)
    for stream in [result.stdout, result.stderr]:
        assert "CANARY" not in stream
        message = json.loads(stream)["message"] if encoded else stream
        assert message == "password=[REDACTED]; ordinary\ntoken=[REDACTED]"
        if encoded:
            assert json.loads(stream)["ordinary"] == 7
