from __future__ import annotations

from devops_toolkit.commands.tls_audit import Endpoint, analyze_results, parse_endpoint


def test_parse_endpoint_supports_default_port_and_ipv6() -> None:
    assert parse_endpoint("example.com") == Endpoint("example.com", 443)
    assert parse_endpoint("example.com:8443") == Endpoint("example.com", 8443)
    assert parse_endpoint("[::1]:9443") == Endpoint("::1", 9443)


def test_tls_results_detect_expired_and_untrusted_certificates() -> None:
    findings = analyze_results(
        [
            {
                "endpoint": "expired.example:443",
                "verified": True,
                "protocol": "TLSv1.2",
                "certificate": {"notAfter": "Jan  1 00:00:00 2020 GMT"},
                "fingerprint": "sha256:abc",
            },
            {
                "endpoint": "bad.example:443",
                "verified": False,
                "error_type": "verification",
                "error": "self-signed certificate",
            },
        ]
    )
    identifiers = {finding.id for finding in findings}
    assert "TLS-CERTIFICATE-EXPIRY" in identifiers
    assert "TLS-VERIFICATION-FAILURE" in identifiers
