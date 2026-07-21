"""Base executable adapter used by domain collectors."""

from __future__ import annotations

from dataclasses import dataclass

from devops_toolkit.core.subprocess import CommandResult, executable_path, run_command


@dataclass(frozen=True)
class ExecutableAdapter:
    executable: str
    version_args: tuple[str, ...] = ("--version",)

    @property
    def available(self) -> bool:
        return executable_path(self.executable) is not None

    def version(self, timeout_seconds: float = 10) -> CommandResult:
        return run_command(
            [self.executable, *self.version_args],
            timeout_seconds=timeout_seconds,
            max_output_chars=10_000,
        )
