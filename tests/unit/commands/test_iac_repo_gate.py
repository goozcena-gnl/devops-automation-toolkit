from __future__ import annotations

from devops_toolkit.commands import iac_repo_gate
from devops_toolkit.core.models import Severity


def test_iac_gate_detects_built_in_risks(repository_root, monkeypatch) -> None:
    monkeypatch.setattr(iac_repo_gate, "executable_path", lambda _name: None)
    report = iac_repo_gate.build_report(
        repository_root / "tests/fixtures/iac-repo",
        threshold=Severity.HIGH,
        run_optional_tools=False,
    )
    identifiers = {finding.id for finding in report.findings}
    assert "IAC-TF-PUBLIC-INGRESS" in identifiers
    assert "IAC-TF-HARDCODED-CREDENTIAL" in identifiers
    assert "IAC-YAML-PARSE-ERROR" in identifiers
    assert report.status.value == "fail"


def test_iac_gate_detects_direct_azure_public_prefix(tmp_path, monkeypatch) -> None:
    (tmp_path / "main.tf").write_text(
        """terraform { required_version = ">= 1.8" }
resource "azurerm_network_security_rule" "example" {
  source_address_prefix = "0.0.0.0/0"
}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(iac_repo_gate, "executable_path", lambda _name: None)
    report = iac_repo_gate.build_report(tmp_path, run_optional_tools=False)
    assert any(finding.id == "IAC-TF-PUBLIC-INGRESS" for finding in report.findings)
