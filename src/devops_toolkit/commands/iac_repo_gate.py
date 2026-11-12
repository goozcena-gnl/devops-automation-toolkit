"""Infrastructure-as-code repository quality and security gate."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from devops_toolkit.core.collection import CollectionState
from devops_toolkit.core.exceptions import DependencyUnavailableError
from devops_toolkit.core.models import (
    Confidence,
    Evidence,
    Finding,
    Report,
    ReportMetadata,
    ResourceRef,
    Severity,
    utc_now,
)
from devops_toolkit.core.redaction import Redactor
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "iac-repo-gate"
EXCLUDED_PARTS = {".git", ".terraform", ".terragrunt-cache", ".venv", "node_modules", "vendor"}
YAML_SUFFIXES = {".yaml", ".yml"}


@dataclass(frozen=True)
class RepositoryInventory:
    terraform_files: tuple[Path, ...]
    yaml_files: tuple[Path, ...]
    ansible_files: tuple[Path, ...]
    helm_charts: tuple[Path, ...]

    @property
    def technologies(self) -> list[str]:
        values: list[str] = []
        if self.terraform_files:
            values.append("terraform-opentofu")
        if self.yaml_files:
            values.append("yaml")
        if self.ansible_files:
            values.append("ansible")
        if self.helm_charts:
            values.append("helm")
        return values


def _repository_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        yield path


def inventory_repository(root: Path) -> RepositoryInventory:
    files = list(_repository_files(root))
    terraform = tuple(sorted(path for path in files if path.suffix == ".tf"))
    yaml_files = tuple(sorted(path for path in files if path.suffix.lower() in YAML_SUFFIXES))
    ansible = tuple(
        sorted(
            path
            for path in yaml_files
            if "ansible" in path.parts
            or path.name in {"playbook.yml", "playbook.yaml", "site.yml", "site.yaml"}
        )
    )
    charts = tuple(sorted(path.parent for path in files if path.name == "Chart.yaml"))
    return RepositoryInventory(terraform, yaml_files, ansible, charts)


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    path: Path,
    root: Path,
    *,
    line: int | None = None,
    confidence: Confidence = Confidence.HIGH,
    summary: str | None = None,
) -> Finding:
    relative = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="infrastructure-as-code",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Repository policy or validation identified an infrastructure-as-code risk.",
        recommendation=recommendation,
        resource=ResourceRef(type="File", name=relative),
        evidence=Evidence(summary=summary or title, location=relative, line=line),
    )


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def analyze_terraform(root: Path, files: tuple[Path, ...]) -> list[Finding]:
    if not files:
        return []
    findings: list[Finding] = []
    combined = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files)
    if not re.search(r"(?m)^\s*required_version\s*=", combined):
        findings.append(
            _finding(
                "IAC-TF-REQUIRED-VERSION",
                Severity.MEDIUM,
                "Terraform or OpenTofu version is not constrained",
                "Add a required_version constraint in a terraform block and test supported versions in CI.",
                files[0],
                root,
                confidence=Confidence.HIGH,
            )
        )
    if not (root / ".terraform.lock.hcl").exists():
        findings.append(
            _finding(
                "IAC-TF-LOCKFILE-MISSING",
                Severity.LOW,
                "Provider dependency lock file is missing",
                "Generate and commit .terraform.lock.hcl for reproducible provider selection.",
                files[0],
                root,
                confidence=Confidence.HIGH,
            )
        )
    public_patterns = (
        re.compile(
            r"(?:cidr_blocks|source_address_prefix(?:es)?)\s*=\s*(?:\[[^\]]*)?[\"']0\.0\.0\.0/0[\"']",
            re.DOTALL,
        ),
        re.compile(
            r"(?:ipv6_cidr_blocks|source_address_prefix(?:es)?)\s*=\s*(?:\[[^\]]*)?[\"']::/0[\"']",
            re.DOTALL,
        ),
    )
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in public_patterns:
            for match in pattern.finditer(text):
                findings.append(
                    _finding(
                        "IAC-TF-PUBLIC-INGRESS",
                        Severity.HIGH,
                        "Unrestricted network source is declared",
                        "Restrict the source CIDR, document the exception, and place public exposure behind an approved edge control.",
                        path,
                        root,
                        line=_line_for(text, match.start()),
                        confidence=Confidence.HIGH,
                    )
                )
        for match in re.finditer(
            r"(?im)^\s*(?:password|client_secret|secret_key|access_key)\s*=\s*[\"'][^\"']{8,}[\"']",
            text,
        ):
            findings.append(
                _finding(
                    "IAC-TF-HARDCODED-CREDENTIAL",
                    Severity.CRITICAL,
                    "Potential credential is hardcoded in Terraform configuration",
                    "Remove the value, rotate the credential, and use workload identity or an approved secret store.",
                    path,
                    root,
                    line=_line_for(text, match.start()),
                    confidence=Confidence.MEDIUM,
                    summary="A credential-shaped assignment was found; the value was not captured.",
                )
            )
    return findings


def analyze_yaml(root: Path, files: tuple[Path, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        try:
            with path.open(encoding="utf-8") as handle:
                list(yaml.safe_load_all(handle))
        except (OSError, yaml.YAMLError) as exc:
            line = None
            if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark is not None:
                line = exc.problem_mark.line + 1
            findings.append(
                _finding(
                    "IAC-YAML-PARSE-ERROR",
                    Severity.HIGH,
                    "YAML document cannot be parsed",
                    "Correct the YAML syntax before merging or deploying this repository.",
                    path,
                    root,
                    line=line,
                    summary=str(exc).splitlines()[0][:300],
                )
            )
    return findings


def _validation_payload(stdout: str) -> tuple[dict[str, Any] | None, str]:
    if not stdout.strip():
        return None, "missing_json"
    try:
        payload = json.loads(stdout)
    except (ValueError, RecursionError):
        return None, "malformed_json"
    if not isinstance(payload, dict) or not isinstance(payload.get("valid"), bool):
        return None, "invalid_json_shape"
    version = payload.get("format_version")
    if not isinstance(version, str) or not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version
    ):
        return None, "invalid_format_version"
    if version.split(".", 1)[0] != "1":
        return None, "unsupported_format_version"
    diagnostics = payload.get("diagnostics")
    if not isinstance(diagnostics, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("severity"), str)
        for item in diagnostics
    ):
        return None, "invalid_json_shape"
    for field in ("error_count", "warning_count"):
        value = payload.get(field)
        if type(value) is not int or value < 0:
            return None, f"invalid_{field}"
    errors = sum(item["severity"] == "error" for item in diagnostics)
    warnings = sum(item["severity"] == "warning" for item in diagnostics)
    if payload["error_count"] != errors:
        return None, "invalid_error_count"
    if payload["warning_count"] != warnings:
        return None, "invalid_warning_count"
    if payload["valid"] != (errors == 0):
        return None, "invalid_validity"
    return payload, ""


def _terraform_diagnostic(root: Path, diagnostic: dict[str, Any], redactor: Redactor) -> Finding:
    severity = Severity.HIGH if diagnostic["severity"] == "error" else Severity.MEDIUM
    range_data = diagnostic.get("range", {})
    filename = str(range_data.get("filename", ".")) if isinstance(range_data, dict) else "."
    start = range_data.get("start", {}) if isinstance(range_data, dict) else {}
    raw_line = start.get("line") if isinstance(start, dict) else None
    line = raw_line if type(raw_line) is int and raw_line > 0 else None
    title = diagnostic.get("summary")
    detail = diagnostic.get("detail")
    return _finding(
        "IAC-TF-VALIDATE",
        severity,
        redactor.redact(title)
        if isinstance(title, str) and title
        else "Terraform validation diagnostic",
        redactor.redact(detail)
        if isinstance(detail, str)
        else "Correct the Terraform validation error.",
        root / redactor.redact_path(filename),
        root,
        line=line,
        confidence=Confidence.HIGH,
    )


def _terraform_validate_findings(
    root: Path, executable: str, timeout_seconds: int
) -> tuple[list[Finding], dict[str, Any], bool]:
    findings: list[Finding] = []
    initialized = (root / ".terraform").exists()
    metadata: dict[str, Any] = {
        "executable": executable,
        "format_checked": False,
        "validated": False,
        "validation_state": CollectionState.NOT_APPLICABLE,
        "validation_reason": "not_initialized",
    }
    try:
        fmt = run_command(
            [executable, "fmt", "-check", "-recursive", "-diff"],
            cwd=root,
            timeout_seconds=timeout_seconds,
            max_output_chars=100_000,
        )
    except (DependencyUnavailableError, OSError):
        if initialized:
            metadata.update(
                validation_state=CollectionState.FAILED, validation_reason="unavailable"
            )
        metadata["format_state"] = CollectionState.FAILED
        return findings, metadata, True

    metadata["format_checked"] = True
    metadata["format_returncode"] = fmt.returncode
    partial = fmt.timed_out or fmt.truncated
    metadata["format_state"] = CollectionState.PARTIAL if partial else CollectionState.COMPLETE
    if not fmt.timed_out and fmt.returncode != 0:
        findings.append(
            _finding(
                "IAC-TF-FORMAT",
                Severity.MEDIUM,
                "Terraform formatting check failed",
                f"Run `{executable} fmt -recursive` and review the resulting changes.",
                root,
                root,
                confidence=Confidence.HIGH,
                summary=f"Formatter exited with code {fmt.returncode}.",
            )
        )
    if not initialized:
        return findings, metadata, partial

    try:
        validation = run_command(
            [executable, "validate", "-json"],
            cwd=root,
            timeout_seconds=timeout_seconds,
            max_output_chars=500_000,
            sanitize_output=False,
        )
    except (DependencyUnavailableError, OSError):
        metadata.update(validation_state=CollectionState.FAILED, validation_reason="unavailable")
        return findings, metadata, True

    metadata["validate_returncode"] = validation.returncode
    if validation.timed_out or validation.truncated:
        metadata.update(
            validation_state=CollectionState.PARTIAL,
            validation_reason="timeout" if validation.timed_out else "truncated",
        )
        return findings, metadata, True
    payload, reason = _validation_payload(validation.stdout)
    if payload is None:
        metadata.update(validation_state=CollectionState.FAILED, validation_reason=reason)
        return findings, metadata, True

    redactor = Redactor()
    diagnostics = [
        _terraform_diagnostic(root, item, redactor)
        for item in payload["diagnostics"]
        if item["severity"] in ("error", "warning")
    ]
    findings.extend(diagnostics)
    has_errors = any(finding.severity is Severity.HIGH for finding in diagnostics)
    if validation.succeeded and payload["valid"] and not has_errors:
        metadata.update(
            validated=True, validation_state=CollectionState.COMPLETE, validation_reason="validated"
        )
        return findings, metadata, partial

    conclusive_rejection = validation.returncode != 0 and not payload["valid"] and has_errors
    if conclusive_rejection:
        metadata.update(validation_state=CollectionState.COMPLETE, validation_reason="rejected")
        return findings, metadata, partial

    metadata.update(
        validation_state=CollectionState.FAILED, validation_reason="inconsistent_result"
    )
    return findings, metadata, True


def _optional_tool_findings(
    root: Path, timeout_seconds: int
) -> tuple[list[Finding], dict[str, Any], bool]:
    findings: list[Finding] = []
    results: dict[str, Any] = {}
    partial = False
    commands: dict[str, list[str]] = {
        "checkov": ["checkov", "-d", ".", "--quiet", "--compact"],
        "trivy": ["trivy", "config", "--quiet", "--exit-code", "1", "."],
        "yamllint": ["yamllint", "-f", "parsable", "."],
        "ansible-lint": ["ansible-lint", "--offline"],
    }
    for name, command in commands.items():
        if executable_path(name) is None:
            results[name] = {"available": False}
            continue
        result = run_command(
            command, cwd=root, timeout_seconds=timeout_seconds, max_output_chars=200_000
        )
        results[name] = {
            "available": True,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
        }
        if result.timed_out:
            partial = True
            continue
        if result.returncode != 0:
            findings.append(
                _finding(
                    f"IAC-EXTERNAL-{name.upper().replace('-', '_')}",
                    Severity.HIGH if name in {"checkov", "trivy"} else Severity.MEDIUM,
                    f"{name} reported repository findings",
                    f"Run `{name}` locally, review its complete output, and remediate or document accepted exceptions.",
                    root,
                    root,
                    confidence=Confidence.HIGH,
                    summary=(result.stdout or result.stderr)[:500]
                    or f"{name} exited with {result.returncode}",
                )
            )
    return findings, results, partial


def build_report(
    root: Path,
    *,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 60,
    run_optional_tools: bool = True,
) -> Report:
    started = utc_now()
    inventory = inventory_repository(root)
    findings = analyze_terraform(root, inventory.terraform_files)
    findings.extend(analyze_yaml(root, inventory.yaml_files))
    tool_results: dict[str, Any] = {}
    partial = False
    tf_executable = (
        "tofu" if executable_path("tofu") else "terraform" if executable_path("terraform") else None
    )
    if inventory.terraform_files and tf_executable:
        external_findings, tf_metadata, external_partial = _terraform_validate_findings(
            root, tf_executable, timeout_seconds
        )
        findings.extend(external_findings)
        tool_results[tf_executable] = tf_metadata
        partial = partial or external_partial
    elif inventory.terraform_files:
        initialized = (root / ".terraform").exists()
        tool_results["terraform-opentofu"] = {
            "available": False,
            "format_checked": False,
            "format_state": CollectionState.FAILED,
            "validated": False,
            "validation_state": CollectionState.FAILED
            if initialized
            else CollectionState.NOT_APPLICABLE,
            "validation_reason": "unavailable" if initialized else "not_initialized",
        }
        partial = True
    for chart in inventory.helm_charts:
        if executable_path("helm") is None:
            tool_results.setdefault("helm", {"available": False})
            break
        helm_result = run_command(
            ["helm", "lint", str(chart)], cwd=root, timeout_seconds=timeout_seconds
        )
        tool_results.setdefault("helm", {"available": True, "charts": []})
        charts = tool_results["helm"].setdefault("charts", [])
        if isinstance(charts, list):
            charts.append(
                {"path": str(chart.relative_to(root)), "returncode": helm_result.returncode}
            )
        if helm_result.timed_out:
            partial = True
        elif helm_result.returncode != 0:
            findings.append(
                _finding(
                    "IAC-HELM-LINT",
                    Severity.HIGH,
                    "Helm chart lint failed",
                    "Run helm lint, correct template or metadata errors, and add chart tests.",
                    chart / "Chart.yaml",
                    root,
                    summary=(helm_result.stdout or helm_result.stderr)[:500],
                )
            )
    if run_optional_tools:
        optional_findings, optional_results, optional_partial = _optional_tool_findings(
            root, timeout_seconds
        )
        findings.extend(optional_findings)
        tool_results.update(optional_results)
        partial = partial or optional_partial
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=str(root.resolve()),
            partial=partial,
            capabilities=["terraform", "opentofu", "yaml", "helm", "ansible", "sarif"],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold, partial=partial),
        extensions={
            "inventory": {
                "technologies": inventory.technologies,
                "terraform_files": len(inventory.terraform_files),
                "yaml_files": len(inventory.yaml_files),
                "ansible_files": len(inventory.ansible_files),
                "helm_charts": len(inventory.helm_charts),
            },
            "tools": tool_results,
        },
    )
