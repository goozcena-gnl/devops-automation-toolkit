import sys

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
