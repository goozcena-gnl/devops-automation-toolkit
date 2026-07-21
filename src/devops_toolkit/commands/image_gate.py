"""Read-only container image vulnerability, secret, SBOM, and signature gate."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import yaml

from devops_toolkit.core.exceptions import (
    CommandExecutionError,
    ConfigurationError,
    DependencyUnavailableError,
)
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
from devops_toolkit.core.subprocess import executable_path, run_command
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.policies.exceptions import PolicyException, apply_exceptions
from devops_toolkit.version import __version__

TOOL_NAME = "image-gate"
SEVERITY_MAP = {
    "UNKNOWN": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _severity(value: object) -> Severity:
    return SEVERITY_MAP.get(str(value).upper(), Severity.INFO)


def _resource(image: str, target: str | None = None) -> ResourceRef:
    name = image if target is None else f"{image}:{target}"
    return ResourceRef(type="ContainerImage", name=name, identifier=image)


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    summary: str,
    recommendation: str,
    image: str,
    *,
    target: str | None = None,
    confidence: Confidence = Confidence.HIGH,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="container-image",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Container image analysis identified a release-policy concern.",
        recommendation=recommendation,
        resource=_resource(image, target),
        evidence=Evidence(summary=summary, location=target),
        references=references or [],
    )


def analyze_trivy(
    payload: dict[str, Any],
    image: str,
    *,
    require_fixed: bool = False,
) -> tuple[list[Finding], dict[str, int]]:
    """Normalize a Trivy JSON report without retaining raw secret matches."""

    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise ConfigurationError("Trivy JSON field `Results` must be a list")
    findings: list[Finding] = []
    metrics = {
        "vulnerabilities": 0,
        "fix_available": 0,
        "secrets": 0,
        "misconfigurations": 0,
        "licenses": 0,
        "unfixed_ignored": 0,
    }
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", "unknown"))
        vulnerabilities = result.get("Vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            for item in vulnerabilities:
                if not isinstance(item, dict):
                    continue
                vulnerability_id = str(item.get("VulnerabilityID", "UNKNOWN"))
                package = str(item.get("PkgName", "unknown-package"))
                installed = str(item.get("InstalledVersion", "unknown"))
                fixed = str(item.get("FixedVersion", "")).strip()
                severity = _severity(item.get("Severity"))
                metrics["vulnerabilities"] += 1
                if fixed:
                    metrics["fix_available"] += 1
                elif require_fixed:
                    metrics["unfixed_ignored"] += 1
                    continue
                references = [
                    str(value) for value in item.get("References", []) if isinstance(value, str)
                ][:5]
                findings.append(
                    _finding(
                        "IMAGE-VULNERABILITY",
                        severity,
                        f"{vulnerability_id} affects {package}",
                        f"package={package}; installed={installed}; fixed={fixed or 'unavailable'}",
                        (
                            f"Upgrade {package} to {fixed} or later and rebuild the image."
                            if fixed
                            else "Review exploitability, apply a documented exception if justified, and rebuild when a fix becomes available."
                        ),
                        image,
                        target=target,
                        references=references,
                    )
                )
        secrets = result.get("Secrets", [])
        if isinstance(secrets, list):
            for item in secrets:
                if not isinstance(item, dict):
                    continue
                rule_id = str(item.get("RuleID", item.get("Category", "secret")))
                category = str(item.get("Category", "credential"))
                severity = _severity(item.get("Severity", "HIGH"))
                metrics["secrets"] += 1
                start_line = item.get("StartLine")
                line = start_line if isinstance(start_line, int) and start_line > 0 else None
                findings.append(
                    Finding(
                        id="IMAGE-EMBEDDED-SECRET",
                        tool=TOOL_NAME,
                        category="container-secret",
                        severity=max(
                            severity, Severity.HIGH, key=lambda value: list(Severity).index(value)
                        ),
                        confidence=Confidence.HIGH,
                        title=f"Embedded secret detected: {rule_id}",
                        description="The scanner reported credential-like material in an image layer or file.",
                        recommendation="Revoke the credential, remove it from the build context and history, and rebuild from a clean layer chain.",
                        resource=_resource(image, target),
                        evidence=Evidence(
                            summary=f"rule={rule_id}; category={category}; value=redacted",
                            location=str(item.get("Title", target)),
                            line=line,
                        ),
                    )
                )
        misconfigurations = result.get("Misconfigurations", [])
        if isinstance(misconfigurations, list):
            for item in misconfigurations:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("Status", "FAIL")).upper()
                if status not in {"FAIL", "ERROR"}:
                    continue
                check_id = str(item.get("ID", item.get("AVDID", "configuration")))
                metrics["misconfigurations"] += 1
                findings.append(
                    _finding(
                        "IMAGE-MISCONFIGURATION",
                        _severity(item.get("Severity", "MEDIUM")),
                        f"Image configuration check failed: {check_id}",
                        f"status={status}; message={str(item.get('Message', item.get('Title', 'policy failure')))[:300]}",
                        str(
                            item.get(
                                "Resolution", "Correct the image configuration before release."
                            )
                        ),
                        image,
                        target=target,
                        confidence=Confidence.MEDIUM,
                        references=[str(item["PrimaryURL"])] if item.get("PrimaryURL") else [],
                    )
                )
        licenses = result.get("Licenses", [])
        if isinstance(licenses, list):
            metrics["licenses"] += len(licenses)
    return findings, metrics


def load_trivy_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read Trivy JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Trivy JSON root must be an object")
    return payload


def _load_exceptions(path: Path | None) -> list[PolicyException]:
    if path is None:
        return []
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to read image policy exceptions: {exc}") from exc
    if payload is None:
        return []
    raw_items = payload.get("exceptions", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_items, list):
        raise ConfigurationError("Image exceptions must be a list or an object with `exceptions`")
    try:
        return [PolicyException.model_validate(item) for item in raw_items]
    except ValueError as exc:
        raise ConfigurationError(f"Invalid image policy exception: {exc}") from exc


def _scan_live(image: str, timeout_seconds: int, *, require_fixed: bool) -> dict[str, Any]:
    if executable_path("trivy") is None:
        raise DependencyUnavailableError("Required executable is unavailable: trivy")
    with tempfile.TemporaryDirectory(prefix="devops-toolkit-image-") as temp_dir:
        output_path = Path(temp_dir) / "trivy.json"
        args = [
            "trivy",
            "image",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(output_path),
            "--scanners",
            "vuln,secret,misconfig",
            "--image-config-scanners",
            "misconfig,secret",
        ]
        if require_fixed:
            args.append("--ignore-unfixed")
        args.append(image)
        result = run_command(
            args,
            timeout_seconds=timeout_seconds,
            max_output_chars=100_000,
        )
        if not result.succeeded:
            detail = result.stderr or result.stdout or "unknown Trivy failure"
            raise CommandExecutionError(f"Trivy image scan failed: {detail[:1000]}")
        return load_trivy_json(output_path)


def generate_sbom(image: str, output: Path, *, timeout_seconds: int) -> None:
    if executable_path("trivy") is None:
        raise DependencyUnavailableError("Required executable is unavailable: trivy")
    result = run_command(
        [
            "trivy",
            "image",
            "--quiet",
            "--format",
            "cyclonedx",
            "--output",
            str(output),
            image,
        ],
        timeout_seconds=timeout_seconds,
        max_output_chars=100_000,
    )
    if not result.succeeded:
        raise CommandExecutionError(
            f"Trivy SBOM generation failed: {(result.stderr or result.stdout)[:1000]}"
        )


def verify_signature(
    image: str,
    *,
    public_key: Path | None,
    timeout_seconds: int,
) -> Finding | None:
    if executable_path("cosign") is None:
        raise DependencyUnavailableError("Required executable is unavailable: cosign")
    args = ["cosign", "verify"]
    if public_key is not None:
        args.extend(["--key", str(public_key)])
    args.append(image)
    result = run_command(args, timeout_seconds=timeout_seconds, max_output_chars=100_000)
    if result.succeeded:
        return None
    return _finding(
        "IMAGE-SIGNATURE-VERIFICATION-FAILED",
        Severity.HIGH,
        "Container image signature verification failed",
        f"cosign_exit_code={result.returncode}",
        "Verify the expected signer identity or public key and publish a valid signature before release.",
        image,
    )


def build_report(
    image: str,
    *,
    trivy_json: Path | None = None,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 600,
    require_fixed: bool = False,
    verify_image_signature: bool = False,
    cosign_key: Path | None = None,
    exceptions_path: Path | None = None,
    sbom_output: Path | None = None,
) -> Report:
    started = utc_now()
    payload = (
        load_trivy_json(trivy_json)
        if trivy_json
        else _scan_live(image, timeout_seconds, require_fixed=require_fixed)
    )
    findings, metrics = analyze_trivy(payload, image, require_fixed=require_fixed)
    if verify_image_signature:
        signature_finding = verify_signature(
            image,
            public_key=cosign_key,
            timeout_seconds=timeout_seconds,
        )
        if signature_finding is not None:
            findings.append(signature_finding)
    if sbom_output is not None:
        if trivy_json is not None:
            raise ConfigurationError(
                "Offline Trivy JSON cannot be used to reconstruct a complete SBOM; run a live image scan for --sbom-output"
            )
        generate_sbom(image, sbom_output, timeout_seconds=timeout_seconds)
    findings = apply_exceptions(findings, _load_exceptions(exceptions_path))
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=image,
            capabilities=[
                "vulnerability-normalization",
                "secret-redaction",
                "misconfiguration-policy",
                "cyclonedx-sbom",
                "optional-cosign-verification",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold),
        extensions={
            "metrics": metrics,
            "scanner": payload.get("SchemaVersion", "trivy-json"),
            "artifact_name": payload.get("ArtifactName", image),
            "artifact_type": payload.get("ArtifactType"),
            "sbom_output": str(sbom_output) if sbom_output else None,
        },
    )
