import json
import subprocess
import sys

import pytest

from devops_toolkit.core.subprocess import run_command


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
