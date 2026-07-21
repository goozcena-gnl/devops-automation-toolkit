# Cloud Waste Inventory

## Purpose

Inventory potentially unused Azure and AWS resources and produce evidence-based recommendations without deleting, stopping, resizing, or tagging anything.

## Usage

```bash
devops-toolkit cloud-waste --provider azure --subscription SUBSCRIPTION_ID
devops-toolkit cloud-waste --provider aws --profile audit --region eu-west-1 \
  --required-tag owner --required-tag environment
```

Use `--snapshot FILE` for deterministic offline analysis.

## Findings

The initial collectors cover unattached disks or volumes, unassociated public IP addresses, orphaned network interfaces, aged snapshots, empty load balancers, missing required tags, and low-utilization compute only when utilization evidence is supplied.

## Evidence model

Every recommendation includes provider, account or subscription scope, resource identity, region, age or utilization evidence, and confidence. Cost values are reported only when the provider response or snapshot supplies them; the tool does not fabricate savings estimates.

## Safety and limitations

Version 1.0.0 has no destructive or mutation mode. A resource classified as unused still requires owner, backup, dependency, and retention review before any lifecycle action.
