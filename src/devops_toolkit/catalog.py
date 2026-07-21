"""Stable catalog of implemented toolkit commands and implementation waves."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolDefinition:
    rank: int
    identifier: str
    display_name: str
    domain: str
    phase: int
    language: str


TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition(1, "secret-sentinel", "Secret Sentinel", "Security", 3, "Python"),
    ToolDefinition(2, "workstation-doctor", "Workstation Doctor", "Workstation", 3, "PowerShell"),
    ToolDefinition(3, "iac-repo-gate", "IaC Repository Gate", "IaC", 3, "Python"),
    ToolDefinition(4, "gha-guard", "GitHub Actions Guard", "CI/CD", 3, "Python"),
    ToolDefinition(5, "kube-triage", "Kubernetes Triage", "Kubernetes", 3, "Python"),
    ToolDefinition(6, "plan-risk", "Terraform Plan Risk Analyzer", "IaC", 4, "Python"),
    ToolDefinition(7, "linux-triage", "Linux Incident Snapshot", "Linux/SRE", 4, "Bash"),
    ToolDefinition(8, "repo-baseline", "GitHub Repository Baseline", "GitHub", 4, "Python"),
    ToolDefinition(9, "kubeconfig-hygiene", "Kubeconfig Hygiene", "Security", 4, "Python"),
    ToolDefinition(10, "tls-audit", "TLS Auditor", "Security", 4, "Python"),
    ToolDefinition(11, "image-gate", "Container Image Gate", "Security", 5, "Python"),
    ToolDefinition(12, "ci-evidence", "CI Evidence Collector", "CI/CD/SRE", 5, "Python"),
    ToolDefinition(13, "prom-audit", "Prometheus Auditor", "Observability", 5, "Python"),
    ToolDefinition(14, "slo-budget", "SLO Budget Calculator", "SRE", 5, "Python"),
    ToolDefinition(
        15, "kube-rightsize", "Kubernetes Rightsizing Auditor", "Kubernetes", 5, "Python"
    ),
    ToolDefinition(16, "cloud-iam-audit", "Cloud IAM Exposure Auditor", "Cloud", 6, "Python"),
    ToolDefinition(17, "cloud-waste", "Cloud Waste Inventory", "FinOps", 6, "Python"),
    ToolDefinition(18, "budget-guard", "Cloud Budget Guard", "FinOps", 6, "Python"),
    ToolDefinition(19, "iac-drift-guard", "IaC Drift Guard", "IaC", 6, "Python"),
    ToolDefinition(
        20, "kube-upgrade-readiness", "Kubernetes Upgrade Readiness", "Kubernetes", 6, "Python"
    ),
)
