"""Concurrent TLS endpoint and certificate auditor."""

from __future__ import annotations

import hashlib
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

TOOL_NAME = "tls-audit"


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int = 443

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


def parse_endpoint(value: str) -> Endpoint:
    text = value.strip()
    if not text or text.startswith("#"):
        raise ConfigurationError("TLS target is empty")
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            raise ConfigurationError(f"Invalid IPv6 TLS target: {value}")
        host = text[1:closing]
        port = int(text[closing + 2 :]) if text[closing + 1 :].startswith(":") else 443
        return Endpoint(host=host, port=port)
    if text.count(":") == 1:
        host, raw_port = text.rsplit(":", 1)
        if raw_port.isdigit():
            port = int(raw_port)
            if not 1 <= port <= 65535:
                raise ConfigurationError(f"TLS target port is out of range: {value}")
            return Endpoint(host=host, port=port)
    return Endpoint(host=text, port=443)


def resolve_targets(values: list[str], target_file: Path | None = None) -> list[Endpoint]:
    raw = list(values)
    if target_file is not None:
        try:
            raw.extend(target_file.read_text(encoding="utf-8").splitlines())
        except OSError as exc:
            raise ConfigurationError(f"Unable to read TLS target file: {exc}") from exc
    targets: list[Endpoint] = []
    seen: set[str] = set()
    for item in raw:
        stripped = item.strip()
        if not stripped or stripped.startswith("#"):
            continue
        endpoint = parse_endpoint(stripped)
        if endpoint.label not in seen:
            targets.append(endpoint)
            seen.add(endpoint.label)
    if not targets:
        raise ConfigurationError("Provide at least one TLS target")
    return targets


def _decode_der(der: bytes) -> dict[str, Any]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", encoding="ascii", suffix=".pem") as handle:
        handle.write(pem)
        handle.flush()
        decoded = ssl._ssl._test_decode_cert(handle.name)  # type: ignore[attr-defined]
    return decoded if isinstance(decoded, dict) else {}


def inspect_endpoint(
    endpoint: Endpoint,
    *,
    timeout_seconds: int = 10,
    allow_untrusted_inspection: bool = False,
) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    verified = True
    verification_error: str | None = None
    try:
        with (
            socket.create_connection(
                (endpoint.host, endpoint.port), timeout=timeout_seconds
            ) as raw,
            context.wrap_socket(raw, server_hostname=endpoint.host) as secure,
        ):
            der = secure.getpeercert(binary_form=True)
            cipher = secure.cipher()
            return {
                "endpoint": endpoint.label,
                "verified": True,
                "protocol": secure.version(),
                "cipher": cipher[0] if cipher else None,
                "certificate": _decode_der(der) if der else {},
                "fingerprint": f"sha256:{hashlib.sha256(der).hexdigest()}" if der else None,
            }
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verification_error = str(exc)
        if not allow_untrusted_inspection:
            return {
                "endpoint": endpoint.label,
                "verified": False,
                "error_type": "verification",
                "error": verification_error,
            }
    except TimeoutError as exc:
        return {
            "endpoint": endpoint.label,
            "verified": False,
            "error_type": "timeout",
            "error": str(exc),
        }
    except socket.gaierror as exc:
        return {
            "endpoint": endpoint.label,
            "verified": False,
            "error_type": "dns",
            "error": str(exc),
        }
    except (ConnectionError, OSError, ssl.SSLError) as exc:
        return {
            "endpoint": endpoint.label,
            "verified": False,
            "error_type": "connection",
            "error": str(exc),
        }
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    unverified.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with (
            socket.create_connection(
                (endpoint.host, endpoint.port), timeout=timeout_seconds
            ) as raw,
            unverified.wrap_socket(raw, server_hostname=endpoint.host) as secure,
        ):
            der = secure.getpeercert(binary_form=True)
            cipher = secure.cipher()
            return {
                "endpoint": endpoint.label,
                "verified": verified,
                "verification_error": verification_error,
                "protocol": secure.version(),
                "cipher": cipher[0] if cipher else None,
                "certificate": _decode_der(der) if der else {},
                "fingerprint": f"sha256:{hashlib.sha256(der).hexdigest()}" if der else None,
                "untrusted_inspection": True,
            }
    except (TimeoutError, socket.gaierror, ConnectionError, OSError, ssl.SSLError) as exc:
        return {
            "endpoint": endpoint.label,
            "verified": False,
            "error_type": "connection",
            "error": str(exc),
            "verification_error": verification_error,
        }


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    endpoint: str,
    summary: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="tls",
        severity=severity,
        confidence=confidence,
        title=title,
        description="TLS endpoint inspection identified a certificate, trust, or connectivity concern.",
        recommendation=recommendation,
        resource=ResourceRef(type="TLSEndpoint", name=endpoint),
        evidence=Evidence(summary=summary, location=endpoint),
    )


def analyze_results(
    results: list[dict[str, Any]], *, warning_days: int = 30, critical_days: int = 7
) -> list[Finding]:
    findings: list[Finding] = []
    fingerprints: dict[str, list[str]] = {}
    now = datetime.now(UTC)
    for result in results:
        endpoint = str(result.get("endpoint", "unknown"))
        error_type = result.get("error_type")
        if error_type:
            severity = Severity.CRITICAL if error_type == "verification" else Severity.HIGH
            findings.append(
                _finding(
                    f"TLS-{str(error_type).upper()}-FAILURE",
                    severity,
                    f"TLS endpoint `{endpoint}` failed {error_type} validation",
                    "Verify DNS, reachability, certificate chain, hostname coverage, expiry, and service configuration.",
                    endpoint,
                    str(result.get("error", "unknown error"))[:300],
                )
            )
            continue
        if result.get("verified") is not True:
            findings.append(
                _finding(
                    "TLS-CERTIFICATE-UNTRUSTED",
                    Severity.CRITICAL,
                    f"TLS endpoint `{endpoint}` is not trusted",
                    "Install a complete trusted certificate chain and verify the requested hostname.",
                    endpoint,
                    str(result.get("verification_error", "certificate verification failed"))[:300],
                )
            )
        certificate = result.get("certificate", {})
        if isinstance(certificate, dict):
            not_after = certificate.get("notAfter")
            if isinstance(not_after, str):
                try:
                    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
                    days = int((expiry - now).total_seconds() // 86400)
                    if days <= warning_days:
                        severity = Severity.CRITICAL if days <= critical_days else Severity.HIGH
                        findings.append(
                            _finding(
                                "TLS-CERTIFICATE-EXPIRY",
                                severity,
                                f"Certificate for `{endpoint}` expires soon",
                                "Renew and deploy the certificate early enough to validate the full chain and all clients.",
                                endpoint,
                                f"expires_at={expiry.isoformat()}; days_remaining={days}",
                            )
                        )
                except (ValueError, OverflowError):
                    findings.append(
                        _finding(
                            "TLS-CERTIFICATE-DATE-INVALID",
                            Severity.MEDIUM,
                            f"Certificate for `{endpoint}` has an invalid expiry value",
                            "Replace the malformed certificate and verify issuance automation.",
                            endpoint,
                            f"notAfter={not_after[:120]}",
                        )
                    )
        protocol = str(result.get("protocol", ""))
        if protocol and protocol not in {"TLSv1.2", "TLSv1.3"}:
            findings.append(
                _finding(
                    "TLS-PROTOCOL-LEGACY",
                    Severity.HIGH,
                    f"Endpoint `{endpoint}` negotiated a legacy TLS protocol",
                    "Disable TLS 1.0 and 1.1 and require TLS 1.2 or later.",
                    endpoint,
                    f"protocol={protocol}",
                )
            )
        fingerprint = result.get("fingerprint")
        if isinstance(fingerprint, str):
            fingerprints.setdefault(fingerprint, []).append(endpoint)
    for fingerprint, endpoints in fingerprints.items():
        hosts = {item.rsplit(":", 1)[0] for item in endpoints}
        if len(hosts) > 1:
            findings.append(
                Finding(
                    id="TLS-CERTIFICATE-REUSED",
                    tool=TOOL_NAME,
                    category="tls",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="The same certificate is reused across multiple endpoint hosts",
                    recommendation="Confirm certificate reuse is intentional and that SAN coverage and key-management boundaries are appropriate.",
                    resource=ResourceRef(type="TLSCertificate", name=fingerprint),
                    evidence=Evidence(summary=f"fingerprint={fingerprint}; endpoints={endpoints}"),
                )
            )
    return findings


def build_report(
    targets: list[Endpoint],
    *,
    threshold: Severity = Severity.HIGH,
    timeout_seconds: int = 10,
    warning_days: int = 30,
    critical_days: int = 7,
    workers: int = 8,
    allow_untrusted_inspection: bool = False,
) -> Report:
    started = utc_now()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as executor:
        futures = {
            executor.submit(
                inspect_endpoint,
                endpoint,
                timeout_seconds=timeout_seconds,
                allow_untrusted_inspection=allow_untrusted_inspection,
            ): endpoint
            for endpoint in targets
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: str(item.get("endpoint", "")))
    findings = analyze_results(results, warning_days=warning_days, critical_days=critical_days)
    completed = utc_now()
    summary_results = [
        {
            "endpoint": item.get("endpoint"),
            "verified": item.get("verified"),
            "protocol": item.get("protocol"),
            "cipher": item.get("cipher"),
            "fingerprint": item.get("fingerprint"),
            "error_type": item.get("error_type"),
        }
        for item in results
    ]
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=",".join(endpoint.label for endpoint in targets),
            partial=False,
            capabilities=[
                "hostname-verification",
                "chain-verification",
                "expiry",
                "protocol",
                "certificate-fingerprint",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold),
        extensions={
            "endpoints": summary_results,
            "allow_untrusted_inspection": allow_untrusted_inspection,
        },
    )
