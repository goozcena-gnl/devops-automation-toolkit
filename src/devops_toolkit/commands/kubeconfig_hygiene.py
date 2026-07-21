"""Kubeconfig credential and trust hygiene auditor."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import ssl
import tempfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from devops_toolkit.core.exceptions import ConfigurationError
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
from devops_toolkit.policies.engine import status_for_findings
from devops_toolkit.version import __version__

TOOL_NAME = "kubeconfig-hygiene"
SAFE_EXEC_COMMANDS = {"aws", "az", "gcloud", "kubelogin", "oidc-login", "tsh", "vault"}


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    path: Path,
    resource_type: str,
    resource_name: str,
    summary: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="kubeconfig",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Kubeconfig analysis identified a credential, trust, or context hygiene concern.",
        recommendation=recommendation,
        resource=ResourceRef(type=resource_type, name=resource_name, identifier=str(path)),
        evidence=Evidence(summary=summary, location=str(path)),
    )


def _fingerprint_data(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raw = value.encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _certificate_expiry(encoded: str) -> tuple[datetime | None, str | None]:
    try:
        der = base64.b64decode(encoded, validate=True)
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", encoding="ascii", suffix=".pem") as handle:
            handle.write(pem)
            handle.flush()
            decoded = ssl._ssl._test_decode_cert(handle.name)  # type: ignore[attr-defined]
        not_after = decoded.get("notAfter")
        if not isinstance(not_after, str):
            return None, "certificate has no notAfter value"
        timestamp = ssl.cert_time_to_seconds(not_after)
        return datetime.fromtimestamp(timestamp, UTC), None
    except (ValueError, OSError, ssl.SSLError, binascii.Error) as exc:
        return None, str(exc)


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to parse kubeconfig {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(f"Kubeconfig root must be a mapping: {path}")
    return payload


def resolve_paths(paths: list[Path] | None) -> list[Path]:
    if paths:
        resolved = paths
    elif os.getenv("KUBECONFIG"):
        resolved = [Path(item).expanduser() for item in os.environ["KUBECONFIG"].split(os.pathsep)]
    else:
        resolved = [Path.home() / ".kube" / "config"]
    existing = [item.resolve() for item in resolved if item.exists()]
    if not existing:
        raise ConfigurationError("No readable kubeconfig file was found")
    return existing


def analyze_paths(
    paths: list[Path], *, expiry_days: int = 30
) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    context_locations: defaultdict[str, list[str]] = defaultdict(list)
    credential_fingerprints: defaultdict[str, list[str]] = defaultdict(list)
    counts = {"files": len(paths), "clusters": 0, "users": 0, "contexts": 0}
    now = datetime.now(UTC)
    for path in paths:
        if os.name != "nt":
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                findings.append(
                    _finding(
                        "KUBECONFIG-PERMISSIONS",
                        Severity.HIGH,
                        f"Kubeconfig `{path}` is readable by group or others",
                        "Restrict the file to the owning user, for example with chmod 600.",
                        path,
                        "KubeconfigFile",
                        path.name,
                        f"mode={mode:04o}",
                    )
                )
        payload = _load(path)
        clusters = payload.get("clusters", [])
        users = payload.get("users", [])
        contexts = payload.get("contexts", [])
        counts["clusters"] += len(clusters) if isinstance(clusters, list) else 0
        counts["users"] += len(users) if isinstance(users, list) else 0
        counts["contexts"] += len(contexts) if isinstance(contexts, list) else 0
        cluster_names: set[str] = set()
        user_names: set[str] = set()
        if isinstance(clusters, list):
            for entry in clusters:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "unknown"))
                cluster_names.add(name)
                cluster = entry.get("cluster", {})
                if not isinstance(cluster, dict):
                    continue
                server = str(cluster.get("server", ""))
                if server.startswith("http://"):
                    findings.append(
                        _finding(
                            "KUBECONFIG-PLAINTEXT-SERVER",
                            Severity.CRITICAL,
                            f"Cluster `{name}` uses a plaintext API endpoint",
                            "Use an HTTPS API endpoint with trusted certificate validation.",
                            path,
                            "KubernetesCluster",
                            name,
                            f"server_scheme=http; host={server.split('://', 1)[-1].split('/', 1)[0]}",
                        )
                    )
                if cluster.get("insecure-skip-tls-verify") is True:
                    findings.append(
                        _finding(
                            "KUBECONFIG-INSECURE-TLS",
                            Severity.CRITICAL,
                            f"Cluster `{name}` disables TLS verification",
                            "Remove insecure-skip-tls-verify and configure a trusted certificate authority.",
                            path,
                            "KubernetesCluster",
                            name,
                            "insecure-skip-tls-verify=true",
                        )
                    )
                if (
                    not cluster.get("certificate-authority")
                    and not cluster.get("certificate-authority-data")
                    and server.startswith("https://")
                ):
                    findings.append(
                        _finding(
                            "KUBECONFIG-CA-IMPLICIT",
                            Severity.LOW,
                            f"Cluster `{name}` relies on the system trust store",
                            "Confirm this is intentional and that the API certificate chains to an approved public or enterprise CA.",
                            path,
                            "KubernetesCluster",
                            name,
                            "no certificate-authority or certificate-authority-data",
                            confidence=Confidence.MEDIUM,
                        )
                    )
        if isinstance(users, list):
            for entry in users:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "unknown"))
                user_names.add(name)
                user = entry.get("user", {})
                if not isinstance(user, dict):
                    continue
                for key, severity in (
                    ("token", Severity.CRITICAL),
                    ("password", Severity.CRITICAL),
                    ("client-key-data", Severity.HIGH),
                ):
                    value = user.get(key)
                    if isinstance(value, str) and value:
                        fingerprint = _fingerprint_data(value)
                        credential_fingerprints[fingerprint].append(f"{path}:{name}:{key}")
                        findings.append(
                            _finding(
                                f"KUBECONFIG-EMBEDDED-{key.upper().replace('-', '_')}",
                                severity,
                                f"User `{name}` contains embedded credential material",
                                "Prefer an exec authentication plugin, short-lived identity, or external protected credential store.",
                                path,
                                "KubernetesUser",
                                name,
                                f"credential_type={key}; fingerprint={fingerprint}",
                            )
                        )
                certificate = user.get("client-certificate-data")
                if isinstance(certificate, str) and certificate:
                    expiry, error = _certificate_expiry(certificate)
                    if expiry is not None:
                        days = int((expiry - now).total_seconds() // 86400)
                        if days <= expiry_days:
                            severity = Severity.CRITICAL if days <= 7 else Severity.HIGH
                            findings.append(
                                _finding(
                                    "KUBECONFIG-CERTIFICATE-EXPIRY",
                                    severity,
                                    f"Client certificate for `{name}` expires soon",
                                    "Rotate the client certificate or migrate to short-lived identity before expiry.",
                                    path,
                                    "KubernetesUser",
                                    name,
                                    f"expires_at={expiry.isoformat()}; days_remaining={days}",
                                )
                            )
                    elif error:
                        findings.append(
                            _finding(
                                "KUBECONFIG-CERTIFICATE-INVALID",
                                Severity.MEDIUM,
                                f"Client certificate for `{name}` cannot be decoded",
                                "Replace malformed certificate data and validate the kubeconfig source.",
                                path,
                                "KubernetesUser",
                                name,
                                f"decode_error={error[:160]}",
                            )
                        )
                if "auth-provider" in user:
                    findings.append(
                        _finding(
                            "KUBECONFIG-AUTH-PROVIDER",
                            Severity.MEDIUM,
                            f"User `{name}` uses legacy auth-provider configuration",
                            "Migrate to a maintained exec credential plugin with short-lived credentials.",
                            path,
                            "KubernetesUser",
                            name,
                            "auth-provider present",
                        )
                    )
                exec_config = user.get("exec")
                if isinstance(exec_config, dict):
                    command = str(exec_config.get("command", ""))
                    command_name = Path(command).name.lower()
                    if command_name not in SAFE_EXEC_COMMANDS:
                        findings.append(
                            _finding(
                                "KUBECONFIG-EXEC-UNRECOGNIZED",
                                Severity.HIGH,
                                f"User `{name}` invokes an unrecognized exec plugin",
                                "Review the executable path, provenance, arguments, and environment before using this context.",
                                path,
                                "KubernetesUser",
                                name,
                                f"exec_command={command_name or '<empty>'}",
                                confidence=Confidence.MEDIUM,
                            )
                        )
                    api_version = str(exec_config.get("apiVersion", ""))
                    if api_version.endswith("/v1alpha1") or api_version.endswith("/v1beta1"):
                        findings.append(
                            _finding(
                                "KUBECONFIG-EXEC-API-OLD",
                                Severity.MEDIUM,
                                f"User `{name}` uses an old exec credential API version",
                                "Upgrade the credential plugin and kubeconfig to client.authentication.k8s.io/v1.",
                                path,
                                "KubernetesUser",
                                name,
                                f"apiVersion={api_version}",
                            )
                        )
        if isinstance(contexts, list):
            for entry in contexts:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "unknown"))
                context_locations[name].append(str(path))
                context = entry.get("context", {})
                if not isinstance(context, dict):
                    continue
                cluster = str(context.get("cluster", ""))
                user = str(context.get("user", ""))
                if cluster and cluster not in cluster_names:
                    findings.append(
                        _finding(
                            "KUBECONFIG-CONTEXT-CLUSTER-MISSING",
                            Severity.HIGH,
                            f"Context `{name}` references an unknown cluster",
                            "Correct or remove the stale context reference.",
                            path,
                            "KubernetesContext",
                            name,
                            f"cluster={cluster}",
                        )
                    )
                if user and user not in user_names:
                    findings.append(
                        _finding(
                            "KUBECONFIG-CONTEXT-USER-MISSING",
                            Severity.HIGH,
                            f"Context `{name}` references an unknown user",
                            "Correct or remove the stale context reference.",
                            path,
                            "KubernetesContext",
                            name,
                            f"user={user}",
                        )
                    )
        current = payload.get("current-context")
        if (
            current
            and isinstance(contexts, list)
            and str(current)
            not in {str(item.get("name")) for item in contexts if isinstance(item, dict)}
        ):
            findings.append(
                _finding(
                    "KUBECONFIG-CURRENT-CONTEXT-MISSING",
                    Severity.HIGH,
                    "Current context references a missing context",
                    "Select a valid current context or remove the stale reference.",
                    path,
                    "KubeconfigFile",
                    path.name,
                    f"current-context={current}",
                )
            )
    for name, locations in context_locations.items():
        if len(locations) > 1:
            findings.append(
                Finding(
                    id="KUBECONFIG-DUPLICATE-CONTEXT",
                    tool=TOOL_NAME,
                    category="kubeconfig",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Context name `{name}` is duplicated across kubeconfig files",
                    recommendation="Rename or consolidate contexts to avoid selecting an unintended cluster.",
                    resource=ResourceRef(type="KubernetesContext", name=name),
                    evidence=Evidence(summary=f"locations={locations}"),
                )
            )
    for fingerprint, locations in credential_fingerprints.items():
        if len(locations) > 1:
            findings.append(
                Finding(
                    id="KUBECONFIG-DUPLICATE-CREDENTIAL",
                    tool=TOOL_NAME,
                    category="kubeconfig",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="The same embedded credential appears in multiple entries",
                    recommendation="Revoke or rotate the credential and replace duplicated long-lived material with short-lived authentication.",
                    resource=ResourceRef(type="KubernetesCredential", name=fingerprint),
                    evidence=Evidence(
                        summary=f"fingerprint={fingerprint}; occurrences={len(locations)}"
                    ),
                )
            )
    return findings, counts


def build_report(
    paths: list[Path] | None = None,
    *,
    threshold: Severity = Severity.HIGH,
    expiry_days: int = 30,
) -> Report:
    started = utc_now()
    resolved = resolve_paths(paths)
    findings, counts = analyze_paths(resolved, expiry_days=expiry_days)
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=os.pathsep.join(str(item) for item in resolved),
            capabilities=[
                "permissions",
                "embedded-credentials",
                "certificate-expiry",
                "context-integrity",
                "exec-plugins",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold),
        extensions={"inventory": counts, "files": [str(item) for item in resolved]},
    )
