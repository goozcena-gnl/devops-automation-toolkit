"""Environment and platform metadata."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeEnvironment:
    operating_system: str
    release: str
    architecture: str
    python_version: str
    is_ci: bool
    ci_provider: str | None


def detect_runtime_environment() -> RuntimeEnvironment:
    provider: str | None = None
    if os.getenv("GITHUB_ACTIONS") == "true":
        provider = "github-actions"
    elif os.getenv("GITLAB_CI") == "true":
        provider = "gitlab-ci"
    elif os.getenv("TF_BUILD") == "True":
        provider = "azure-devops"
    return RuntimeEnvironment(
        operating_system=platform.system(),
        release=platform.release(),
        architecture=platform.machine(),
        python_version=platform.python_version(),
        is_ci=provider is not None or os.getenv("CI", "").lower() == "true",
        ci_provider=provider,
    )
