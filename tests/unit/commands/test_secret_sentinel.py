from __future__ import annotations

from devops_toolkit.commands.secret_sentinel import build_report, scan_text
from devops_toolkit.core.models import Severity


def test_scan_text_never_preserves_secret_value() -> None:
    value = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    findings = scan_text(f'token = "{value}"', "config.txt")
    assert findings
    serialized = " ".join(str(item.model_dump()) for item in findings)
    assert value not in serialized
    assert findings[0].fingerprint.startswith("sha256:")


def test_build_report_scans_fixture(repository_root) -> None:
    report = build_report(
        repository_root / "tests/fixtures/secret-repo",
        threshold=Severity.HIGH,
    )
    assert report.status.value == "fail"
    assert any(item.id == "SECRET-GITHUB-TOKEN" for item in report.findings)
    assert report.extensions["metrics"]["files_scanned"] >= 1


def test_scanner_skips_symbolic_links_outside_root(tmp_path) -> None:
    external = tmp_path.parent / "outside-secret.txt"
    external.write_text("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n", encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(external)
    except OSError:
        return
    report = build_report(tmp_path, threshold=Severity.HIGH)
    assert not report.findings
