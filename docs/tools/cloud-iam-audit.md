# Cloud IAM Exposure Auditor

## Purpose

Audit high-impact Azure role assignments and AWS IAM trust or permission exposure without changing identities, policies, assignments, or credentials.

## Usage

```bash
devops-toolkit cloud-iam-audit --provider azure --subscription SUBSCRIPTION_ID
devops-toolkit cloud-iam-audit --provider aws --profile audit --format sarif
```

Deterministic offline analysis is available with `--snapshot FILE`.

## Authentication and permissions

Live mode relies on the existing Azure CLI or AWS CLI credential chain. The tool requests account, role, policy, trust, and key metadata only; it does not retrieve secret values. Use a dedicated read-only audit identity and constrain the selected subscription, account, or profile.

## Findings

The initial rule set includes broad privileged Azure assignments, wildcard custom roles, missing principals, expired application credentials, AWS administrative policies, wildcard resources, risky trust policies, missing MFA, and stale access-key metadata when the evidence is present.

## Safety and limitations

No remediation command is implemented. A finding represents exposure or governance risk, not proof that an identity has been compromised. Some credential-age checks require normalized snapshot evidence because live provider APIs expose different identity inventories and permissions.
