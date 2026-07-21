# Finding model

A finding represents a deterministic statement supported by sanitized evidence.
It contains severity, confidence, resource identity, recommendation, and a
stable fingerprint.

Severity describes potential impact. Confidence describes evidence strength.
The two must not be conflated. A critical but low-confidence finding remains
visible and should request verification rather than claim confirmed compromise.

Fingerprints are SHA-256 digests over stable, non-secret finding attributes.
They support deduplication and expiring exceptions.
