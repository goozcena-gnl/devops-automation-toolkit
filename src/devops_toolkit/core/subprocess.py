"""Safe external command execution without shell interpolation."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from devops_toolkit.core.exceptions import DependencyUnavailableError
from devops_toolkit.core.redaction import Redactor


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def executable_path(name: str) -> str | None:
    return shutil.which(name)


def require_executable(name: str) -> str:
    path = executable_path(name)
    if path is None:
        raise DependencyUnavailableError(f"Required executable is unavailable: {name}")
    return path


def _bounded(value: str, limit: int) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit] + "\n[OUTPUT TRUNCATED]", True


def run_command(
    args: Sequence[str],
    *,
    timeout_seconds: float = 30,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    allowed_environment: set[str] | None = None,
    max_output_chars: int = 1_000_000,
    redactor: Redactor | None = None,
    sanitize_output: bool = True,
) -> CommandResult:
    """Execute an argument vector safely and return sanitized bounded output."""

    if not args:
        raise ValueError("At least one command argument is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    if max_output_chars < 1:
        raise ValueError("max_output_chars must be positive")

    executable = require_executable(args[0])
    command = [executable, *args[1:]]
    safe_env = os.environ.copy()
    # Do not leak test/instrumentation hooks into child processes. Besides making
    # command behavior non-deterministic, coverage auto-start can deadlock when
    # many short-lived subprocesses write the same data file.
    for instrumentation_key in tuple(safe_env):
        if instrumentation_key in {
            "COVERAGE_PROCESS_START",
            "COVERAGE_FILE",
            "PYTEST_CURRENT_TEST",
            "DD_TRACE_ENABLED",
        } or instrumentation_key.startswith("COV_CORE_"):
            safe_env.pop(instrumentation_key, None)
    if allowed_environment is not None:
        safe_env = {key: value for key, value in safe_env.items() if key in allowed_environment}
    if environment:
        safe_env.update(environment)

    active_redactor = redactor or Redactor()

    def sanitize(value: str) -> str:
        return active_redactor.redact(value) if sanitize_output else value

    try:
        completed = subprocess.run(  # noqa: S603
            command,
            cwd=cwd,
            env=safe_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
        stdout, stdout_truncated = _bounded(sanitize(completed.stdout), max_output_chars)
        stderr, stderr_truncated = _bounded(sanitize(completed.stderr), max_output_chars)
        return CommandResult(
            args=tuple(str(item) for item in args),
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            truncated=stdout_truncated or stderr_truncated,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = sanitize(_coerce_output(exc.stdout))
        stderr = sanitize(_coerce_output(exc.stderr))
        stdout, stdout_truncated = _bounded(stdout, max_output_chars)
        stderr, stderr_truncated = _bounded(stderr, max_output_chars)
        return CommandResult(
            args=tuple(str(item) for item in args),
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            truncated=stdout_truncated or stderr_truncated,
        )


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
