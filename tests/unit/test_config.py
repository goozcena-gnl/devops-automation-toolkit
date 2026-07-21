from pathlib import Path

import pytest

from devops_toolkit.core.config import deep_merge, load_config
from devops_toolkit.core.exceptions import ConfigurationError


def test_deep_merge_preserves_nested_defaults() -> None:
    result = deep_merge(
        {"defaults": {"format": "console", "timeout_seconds": 30}},
        {"defaults": {"timeout_seconds": 10}},
    )
    assert result["defaults"] == {"format": "console", "timeout_seconds": 10}


def test_load_config_merges_example(repository_root: Path) -> None:
    config = load_config([repository_root / "configs/examples/toolkit.example.yaml"])
    assert config["version"] == 1
    assert config["defaults"]["severity_threshold"] == "high"
    assert config["redaction"]["replacement"] == "[REDACTED]"


def test_unknown_top_level_key_fails(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("version: 1\nmisspelled_security: true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Additional properties"):
        load_config([path])


def test_invalid_timeout_environment_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEVOPS_TOOLKIT_TIMEOUT_SECONDS", "not-a-number")
    with pytest.raises(ConfigurationError, match="must be an integer"):
        load_config()


def test_unknown_phase3_tool_setting_fails(tmp_path) -> None:
    path = tmp_path / "invalid-tool.yaml"
    path.write_text(
        """version: 1
tools:
  secret-sentinel:
    scan_git_hstory: true
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_config([path])


def test_unknown_phase6_tool_setting_fails(tmp_path: Path) -> None:
    path = tmp_path / "invalid-phase6-tool.yaml"
    path.write_text(
        """version: 1
tools:
  cloud-waste:
    snapshot_age_dayz: 30
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_config([path])
