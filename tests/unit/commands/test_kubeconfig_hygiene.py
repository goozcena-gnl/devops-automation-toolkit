from __future__ import annotations

import os
from pathlib import Path

from devops_toolkit.commands.kubeconfig_hygiene import build_report
from devops_toolkit.core.models import Severity


def test_kubeconfig_report_redacts_embedded_credentials(tmp_path: Path) -> None:
    path = tmp_path / "config"
    credential = "synthetic-invalid-credential-material-123456789"
    path.write_text(
        f"""apiVersion: v1
kind: Config
clusters:
  - name: production
    cluster:
      server: http://127.0.0.1:8080
      insecure-skip-tls-verify: true
users:
  - name: admin
    user:
      token: {credential}
contexts:
  - name: production
    context:
      cluster: production
      user: admin
current-context: production
""",
        encoding="utf-8",
    )
    if os.name != "nt":
        path.chmod(0o644)
    report = build_report([path], threshold=Severity.HIGH)
    rendered = str(report.as_dict())
    assert credential not in rendered
    identifiers = {finding.id for finding in report.findings}
    assert "KUBECONFIG-EMBEDDED-TOKEN" in identifiers
    assert "KUBECONFIG-INSECURE-TLS" in identifiers
    assert "KUBECONFIG-PLAINTEXT-SERVER" in identifiers
