# TLS Auditor

`tls-audit` validates network connectivity, hostname and chain trust, certificate expiry, negotiated protocol, and certificate reuse.

```bash
devops-toolkit tls-audit api.example.com registry.example.com:443 \
  --warning-days 30 \
  --critical-days 7 \
  --timeout 10 \
  --format json
```

Targets may also be loaded from a file:

```bash
devops-toolkit tls-audit --targets-file endpoints.txt
```

Verification uses the platform trust store and requires TLS 1.2 or later. A failed certificate is not inspected with verification disabled unless `--allow-untrusted-inspection` is explicitly supplied. That option is intended for diagnostics, not for treating the endpoint as trusted.

Reports contain public certificate fingerprints and metadata, never private keys.
