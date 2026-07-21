# Container Image Gate

## Usage

`devops-toolkit image-gate IMAGE [--trivy-json FILE] [--sbom-output FILE] [--verify-signature]`

## Behavior

Live mode requires Trivy; signature verification additionally requires Cosign. Offline Trivy JSON is supported for deterministic analysis. Raw secret matches are never copied into findings.

All reports use the shared schema and standard exit codes. Severity thresholds are configurable. No mutation is performed.
