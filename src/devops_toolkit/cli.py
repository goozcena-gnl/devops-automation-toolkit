"""Foundation command-line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from devops_toolkit.adapters.tools import KNOWN_ADAPTERS
from devops_toolkit.catalog import TOOLS
from devops_toolkit.commands.budget_guard import build_report as build_budget_guard_report
from devops_toolkit.commands.ci_evidence import build_report as build_ci_evidence_report
from devops_toolkit.commands.ci_evidence import write_bundle as write_ci_evidence_bundle
from devops_toolkit.commands.cloud_iam_audit import build_report as build_cloud_iam_report
from devops_toolkit.commands.cloud_waste import build_report as build_cloud_waste_report
from devops_toolkit.commands.common import (
    emit_report,
    exit_code_for_report,
    format_from_config,
    no_color_from_config,
    severity_from_config,
    timeout_from_config,
    tool_config,
)
from devops_toolkit.commands.gha_guard import build_report as build_gha_guard_report
from devops_toolkit.commands.iac_drift_guard import build_report as build_iac_drift_report
from devops_toolkit.commands.iac_repo_gate import build_report as build_iac_gate_report
from devops_toolkit.commands.image_gate import build_report as build_image_gate_report
from devops_toolkit.commands.kube_rightsize import build_report as build_kube_rightsize_report
from devops_toolkit.commands.kube_triage import (
    build_report as build_kube_triage_report,
)
from devops_toolkit.commands.kube_triage import (
    write_sanitized_bundle,
)
from devops_toolkit.commands.kube_upgrade_readiness import (
    build_report as build_kube_upgrade_report,
)
from devops_toolkit.commands.kubeconfig_hygiene import build_report as build_kubeconfig_report
from devops_toolkit.commands.plan_risk import build_report as build_plan_risk_report
from devops_toolkit.commands.prom_audit import build_report as build_prom_audit_report
from devops_toolkit.commands.repo_baseline import build_report as build_repo_baseline_report
from devops_toolkit.commands.secret_sentinel import build_report as build_secret_report
from devops_toolkit.commands.slo_budget import build_report as build_slo_budget_report
from devops_toolkit.commands.tls_audit import build_report as build_tls_report
from devops_toolkit.commands.tls_audit import resolve_targets as resolve_tls_targets
from devops_toolkit.core.config import load_config
from devops_toolkit.core.exceptions import (
    CommandExecutionError,
    ConfigurationError,
    DependencyUnavailableError,
    SafetyBlockedError,
    ToolkitError,
)
from devops_toolkit.core.exit_codes import ExitCode
from devops_toolkit.core.filesystem import atomic_write_text
from devops_toolkit.core.models import Severity
from devops_toolkit.core.redaction import Redactor
from devops_toolkit.core.safety import SafetyPolicy
from devops_toolkit.reporters.dispatcher import ReportFormat, render_report
from devops_toolkit.sample import build_sample_report
from devops_toolkit.version import __version__

app = typer.Typer(
    name="devops-toolkit",
    help="Shared foundation for production-oriented DevOps automation utilities.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print the package version."""

    typer.echo(__version__)


@app.command()
def health(
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Check the runtime and discover optional DevOps executables."""

    rows: list[dict[str, str | bool]] = []
    for name, adapter in KNOWN_ADAPTERS.items():
        rows.append({"tool": name, "available": adapter.available})
    if output_json:
        typer.echo(json.dumps({"version": __version__, "dependencies": rows}, indent=2))
        return
    table = Table(title=f"DevOps Toolkit {__version__} health")
    table.add_column("Dependency")
    table.add_column("Available")
    for row in rows:
        table.add_row(str(row["tool"]), "yes" if row["available"] else "no")
    console.print(table)


@app.command("validate-config")
def validate_config_command(
    config: Annotated[Path, typer.Option("--config", exists=True, dir_okay=False, readable=True)],
) -> None:
    """Merge a configuration file with defaults and validate it."""

    try:
        merged = load_config([config])
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    typer.echo(json.dumps(merged, indent=2))


@app.command()
def redact(
    text: Annotated[str | None, typer.Option("--text")] = None,
    file: Annotated[Path | None, typer.Option("--file", exists=True, dir_okay=False)] = None,
) -> None:
    """Redact sensitive patterns from provided text or a local file."""

    if (text is None) == (file is None):
        typer.echo("Provide exactly one of --text or --file", err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT)
    value = text if text is not None else file.read_text(encoding="utf-8")  # type: ignore[union-attr]
    typer.echo(Redactor().redact(value))


@app.command("render-sample")
def render_sample(
    report_format: Annotated[
        ReportFormat,
        typer.Option("--format", case_sensitive=False),
    ] = ReportFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """Render a synthetic report to validate output contracts."""

    rendered = render_report(build_sample_report(), report_format, color=not no_color)
    if output:
        atomic_write_text(output, rendered)
        typer.echo(str(output))
    else:
        typer.echo(rendered, nl=False)


@app.command()
def catalog() -> None:
    """Show the implemented top-20 toolkit catalog."""

    table = Table(title="Implemented toolkit commands")
    table.add_column("Rank", justify="right")
    table.add_column("Identifier")
    table.add_column("Domain")
    table.add_column("Wave", justify="right")
    table.add_column("Language")
    for item in TOOLS:
        table.add_row(str(item.rank), item.identifier, item.domain, str(item.phase), item.language)
    console.print(table)


def _raise_for_report(report_status: int) -> None:
    if report_status != int(ExitCode.SUCCESS):
        raise typer.Exit(report_status)


@app.command("secret-sentinel")
def secret_sentinel_command(
    root: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)] = Path("."),
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    history: Annotated[bool | None, typer.Option("--history/--no-history")] = None,
    max_commits: Annotated[int | None, typer.Option("--max-commits", min=0, max=5000)] = None,
    include_ignored: Annotated[
        bool | None, typer.Option("--include-ignored/--exclude-ignored")
    ] = None,
    max_file_bytes: Annotated[int | None, typer.Option("--max-file-bytes", min=1024)] = None,
    exclude_dir: Annotated[list[str] | None, typer.Option("--exclude-dir")] = None,
    baseline: Annotated[
        Path | None, typer.Option("--baseline", exists=True, dir_okay=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Scan a working tree and optionally bounded Git history for exposed secrets."""

    merged, tool_options = tool_config(config or [], "secret-sentinel")
    history_value = (
        history if history is not None else bool(tool_options.get("scan_git_history", False))
    )
    include_ignored_value = (
        include_ignored
        if include_ignored is not None
        else bool(tool_options.get("include_ignored", False))
    )
    max_commits_value = (
        max_commits if max_commits is not None else int(tool_options.get("max_commits", 50))
    )
    max_file_bytes_value = (
        max_file_bytes
        if max_file_bytes is not None
        else int(tool_options.get("max_file_bytes", 1_000_000))
    )
    configured_exclusions = tool_options.get("excluded_dirs", [])
    excluded_dirs = {str(item) for item in configured_exclusions if isinstance(item, str)}
    excluded_dirs.update(exclude_dir or [])
    report = build_secret_report(
        root,
        threshold=severity_from_config(merged, threshold),
        include_ignored=include_ignored_value,
        history=history_value,
        max_commits=max_commits_value,
        max_file_bytes=max_file_bytes_value,
        timeout_seconds=timeout_from_config(merged, timeout_seconds),
        baseline=baseline,
        excluded_dirs=excluded_dirs,
    )
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("iac-repo-gate")
def iac_repo_gate_command(
    root: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)] = Path("."),
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    optional_tools: Annotated[
        bool | None, typer.Option("--optional-tools/--no-optional-tools")
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Audit Terraform, OpenTofu, YAML, Helm and Ansible repository quality."""

    merged, tool_options = tool_config(config or [], "iac-repo-gate")
    optional_tools_value = (
        optional_tools
        if optional_tools is not None
        else bool(tool_options.get("run_optional_tools", True))
    )
    report = build_iac_gate_report(
        root,
        threshold=severity_from_config(merged, threshold),
        timeout_seconds=timeout_from_config(merged, timeout_seconds),
        run_optional_tools=optional_tools_value,
    )
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("gha-guard")
def gha_guard_command(
    root: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)] = Path("."),
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Statically audit GitHub Actions workflows for security and reliability risks."""

    merged, _ = tool_config(config or [], "gha-guard")
    report = build_gha_guard_report(root, threshold=severity_from_config(merged, threshold))
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("kube-triage")
def kube_triage_command(
    context: Annotated[str | None, typer.Option("--context")] = None,
    namespace: Annotated[str, typer.Option("--namespace")] = "default",
    all_namespaces: Annotated[bool, typer.Option("--all-namespaces")] = False,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    bundle: Annotated[Path | None, typer.Option("--bundle", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    acknowledge_production: Annotated[bool, typer.Option("--acknowledge-production")] = False,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Collect read-only Kubernetes health evidence and optional sanitized bundle."""

    merged, tool_options = tool_config(config or [], "kube-triage")
    safety = SafetyPolicy(**merged["safety"])
    allowed_namespaces = {
        str(item) for item in tool_options.get("allowed_namespaces", []) if isinstance(item, str)
    }
    allowed_contexts = {
        str(item) for item in tool_options.get("allowed_contexts", []) if isinstance(item, str)
    }
    if all_namespaces and allowed_namespaces:
        typer.echo("--all-namespaces is blocked by the configured namespace allowlist", err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED)
    if allowed_namespaces and namespace not in allowed_namespaces:
        typer.echo(f"Namespace is not in the configured allowlist: {namespace}", err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED)
    if context is not None and allowed_contexts and context not in allowed_contexts:
        typer.echo(f"Kubernetes context is not in the configured allowlist: {context}", err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED)
    try:
        report, collections = build_kube_triage_report(
            context=context,
            namespace=namespace,
            all_namespaces=all_namespaces,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            safety_policy=safety,
            production_acknowledged=acknowledge_production,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except SafetyBlockedError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED) from exc
    if bundle is not None:
        write_sanitized_bundle(bundle, report, collections)
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    if bundle is not None:
        typer.echo(f"bundle={bundle}", err=True)
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("plan-risk")
def plan_risk_command(
    plan: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    replacement_threshold: Annotated[
        int | None, typer.Option("--replacement-threshold", min=1, max=10000)
    ] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Analyze Terraform or OpenTofu `show -json` output for deployment risk."""

    merged, tool_options = tool_config(config or [], "plan-risk")
    replacement_value = (
        replacement_threshold
        if replacement_threshold is not None
        else int(tool_options.get("replacement_threshold", 10))
    )
    try:
        report = build_plan_risk_report(
            plan,
            threshold=severity_from_config(merged, threshold),
            replacement_threshold=replacement_value,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("repo-baseline")
def repo_baseline_command(
    repository: Annotated[
        str | None, typer.Argument(help="GitHub repository in OWNER/REPO form.")
    ] = None,
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Audit a GitHub repository against a read-only governance baseline."""

    merged, _ = tool_config(config or [], "repo-baseline")
    try:
        report = build_repo_baseline_report(
            repository,
            snapshot_path=snapshot,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("kubeconfig-hygiene")
def kubeconfig_hygiene_command(
    kubeconfig: Annotated[
        list[Path] | None, typer.Option("--kubeconfig", exists=True, dir_okay=False, readable=True)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    expiry_days: Annotated[int | None, typer.Option("--expiry-days", min=1, max=3650)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Audit kubeconfig files without serializing embedded credential values."""

    merged, tool_options = tool_config(config or [], "kubeconfig-hygiene")
    expiry_value = (
        expiry_days if expiry_days is not None else int(tool_options.get("expiry_days", 30))
    )
    try:
        report = build_kubeconfig_report(
            kubeconfig,
            threshold=severity_from_config(merged, threshold),
            expiry_days=expiry_value,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("tls-audit")
def tls_audit_command(
    targets: Annotated[
        list[str] | None, typer.Argument(help="TLS targets as host or host:port.")
    ] = None,
    targets_file: Annotated[
        Path | None, typer.Option("--targets-file", exists=True, dir_okay=False, readable=True)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=300)] = None,
    warning_days: Annotated[int | None, typer.Option("--warning-days", min=1, max=3650)] = None,
    critical_days: Annotated[int | None, typer.Option("--critical-days", min=0, max=3650)] = None,
    workers: Annotated[int | None, typer.Option("--workers", min=1, max=64)] = None,
    allow_untrusted_inspection: Annotated[
        bool, typer.Option("--allow-untrusted-inspection")
    ] = False,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Validate TLS connectivity, hostname trust, expiry, and negotiated protocol."""

    merged, tool_options = tool_config(config or [], "tls-audit")
    warning_value = (
        warning_days if warning_days is not None else int(tool_options.get("warning_days", 30))
    )
    critical_value = (
        critical_days if critical_days is not None else int(tool_options.get("critical_days", 7))
    )
    worker_value = workers if workers is not None else int(tool_options.get("workers", 8))
    if critical_value > warning_value:
        typer.echo("--critical-days cannot exceed --warning-days", err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT)
    try:
        resolved = resolve_tls_targets(targets or [], targets_file)
        report = build_tls_report(
            resolved,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            warning_days=warning_value,
            critical_days=critical_value,
            workers=worker_value,
            allow_untrusted_inspection=allow_untrusted_inspection,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("image-gate")
def image_gate_command(
    image: Annotated[str, typer.Argument(help="Container image reference or fixture identity.")],
    trivy_json: Annotated[
        Path | None, typer.Option("--trivy-json", exists=True, dir_okay=False, readable=True)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    sbom_output: Annotated[Path | None, typer.Option("--sbom-output", dir_okay=False)] = None,
    verify_signature: Annotated[bool, typer.Option("--verify-signature")] = False,
    cosign_key: Annotated[
        Path | None, typer.Option("--cosign-key", exists=True, dir_okay=False)
    ] = None,
    exceptions: Annotated[
        Path | None, typer.Option("--exceptions", exists=True, dir_okay=False)
    ] = None,
    require_fixed: Annotated[bool | None, typer.Option("--require-fixed/--allow-unfixed")] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Gate a container image using normalized Trivy evidence and optional Cosign verification."""

    merged, tool_options = tool_config(config or [], "image-gate")
    require_fixed_value = (
        require_fixed
        if require_fixed is not None
        else bool(tool_options.get("require_fixed", False))
    )
    try:
        report = build_image_gate_report(
            image,
            trivy_json=trivy_json,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            require_fixed=require_fixed_value,
            verify_image_signature=verify_signature,
            cosign_key=cosign_key,
            exceptions_path=exceptions,
            sbom_output=sbom_output,
        )
    except (ConfigurationError, CommandExecutionError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("ci-evidence")
def ci_evidence_command(
    logs_dir: Annotated[
        Path | None, typer.Option("--logs-dir", exists=True, file_okay=False, readable=True)
    ] = None,
    metadata: Annotated[
        Path | None, typer.Option("--metadata", exists=True, dir_okay=False, readable=True)
    ] = None,
    repository: Annotated[str | None, typer.Option("--repository")] = None,
    run_id: Annotated[int | None, typer.Option("--run-id", min=1)] = None,
    bundle: Annotated[Path | None, typer.Option("--bundle", dir_okay=False)] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    max_file_bytes: Annotated[int | None, typer.Option("--max-file-bytes", min=1024)] = None,
    max_total_bytes: Annotated[int | None, typer.Option("--max-total-bytes", min=1024)] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Collect, sanitize, and classify failed CI run evidence."""

    merged, tool_options = tool_config(config or [], "ci-evidence")
    max_file_value = (
        max_file_bytes
        if max_file_bytes is not None
        else int(tool_options.get("max_file_bytes", 2_000_000))
    )
    max_total_value = (
        max_total_bytes
        if max_total_bytes is not None
        else int(tool_options.get("max_total_bytes", 25_000_000))
    )
    try:
        report, logs, metadata_payload = build_ci_evidence_report(
            logs_dir=logs_dir,
            metadata_path=metadata,
            repository=repository,
            run_id=run_id,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            max_file_bytes=max_file_value,
            max_total_bytes=max_total_value,
        )
    except (ConfigurationError, CommandExecutionError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    if bundle is not None:
        write_ci_evidence_bundle(bundle, report, logs, metadata_payload)
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    if bundle is not None:
        typer.echo(f"bundle={bundle}", err=True)
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("prom-audit")
def prom_audit_command(
    url: Annotated[str | None, typer.Option("--url")] = None,
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    expected_job: Annotated[list[str] | None, typer.Option("--expected-job")] = None,
    rule_file: Annotated[
        list[Path] | None, typer.Option("--rule-file", exists=True, dir_okay=False, readable=True)
    ] = None,
    bearer_token_env: Annotated[str | None, typer.Option("--bearer-token-env")] = None,
    ca_file: Annotated[
        Path | None, typer.Option("--ca-file", exists=True, dir_okay=False, readable=True)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    duration_ratio: Annotated[
        float | None, typer.Option("--duration-ratio", min=0.1, max=1.0)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=300)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Audit Prometheus targets, rules, and active alert hygiene."""

    merged, tool_options = tool_config(config or [], "prom-audit")
    ratio = (
        duration_ratio
        if duration_ratio is not None
        else float(tool_options.get("duration_ratio", 0.8))
    )
    token = os.getenv(bearer_token_env) if bearer_token_env else None
    if bearer_token_env and token is None:
        typer.echo(f"Environment variable is not set: {bearer_token_env}", err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT)
    try:
        report = build_prom_audit_report(
            base_url=url,
            snapshot_path=snapshot,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            bearer_token=token,
            ca_file=ca_file,
            expected_jobs=set(expected_job or []),
            duration_ratio_threshold=ratio,
            rule_files=rule_file or [],
        )
    except (ConfigurationError, CommandExecutionError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("slo-budget")
def slo_budget_command(
    spec: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    bearer_token_env: Annotated[str | None, typer.Option("--bearer-token-env")] = None,
    ca_file: Annotated[
        Path | None, typer.Option("--ca-file", exists=True, dir_okay=False, readable=True)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=300)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Calculate SLO compliance, remaining error budget, and multi-window burn rates."""

    merged, _ = tool_config(config or [], "slo-budget")
    token = os.getenv(bearer_token_env) if bearer_token_env else None
    if bearer_token_env and token is None:
        typer.echo(f"Environment variable is not set: {bearer_token_env}", err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT)
    try:
        report = build_slo_budget_report(
            spec,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            bearer_token=token,
            ca_file=ca_file,
        )
    except (ConfigurationError, CommandExecutionError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("kube-rightsize")
def kube_rightsize_command(
    context: Annotated[str | None, typer.Option("--context")] = None,
    namespace: Annotated[str, typer.Option("--namespace")] = "default",
    all_namespaces: Annotated[bool, typer.Option("--all-namespaces")] = False,
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    patch_preview: Annotated[bool, typer.Option("--patch-preview")] = False,
    acknowledge_production: Annotated[bool, typer.Option("--acknowledge-production")] = False,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    overrequest_ratio: Annotated[
        float | None, typer.Option("--overrequest-ratio", min=0.01, max=0.99)
    ] = None,
    high_usage_ratio: Annotated[
        float | None, typer.Option("--high-usage-ratio", min=0.1, max=1.5)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=300)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Audit Kubernetes requests and limits against current Metrics API usage."""

    merged, tool_options = tool_config(config or [], "kube-rightsize")
    safety = SafetyPolicy(**merged["safety"])
    allowed_namespaces = {
        str(item) for item in tool_options.get("allowed_namespaces", []) if isinstance(item, str)
    }
    allowed_contexts = {
        str(item) for item in tool_options.get("allowed_contexts", []) if isinstance(item, str)
    }
    if snapshot is None:
        if all_namespaces and allowed_namespaces:
            typer.echo(
                "--all-namespaces is blocked by the configured namespace allowlist", err=True
            )
            raise typer.Exit(ExitCode.SAFETY_BLOCKED)
        if allowed_namespaces and namespace not in allowed_namespaces:
            typer.echo(f"Namespace is not in the configured allowlist: {namespace}", err=True)
            raise typer.Exit(ExitCode.SAFETY_BLOCKED)
        if context is not None and allowed_contexts and context not in allowed_contexts:
            typer.echo(
                f"Kubernetes context is not in the configured allowlist: {context}", err=True
            )
            raise typer.Exit(ExitCode.SAFETY_BLOCKED)
    overrequest_value = (
        overrequest_ratio
        if overrequest_ratio is not None
        else float(tool_options.get("overrequest_ratio", 0.25))
    )
    high_usage_value = (
        high_usage_ratio
        if high_usage_ratio is not None
        else float(tool_options.get("high_usage_ratio", 0.85))
    )
    try:
        report = build_kube_rightsize_report(
            context=context,
            namespace=namespace,
            all_namespaces=all_namespaces,
            snapshot_path=snapshot,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            safety_policy=safety,
            production_acknowledged=acknowledge_production,
            include_patch_preview=patch_preview,
            overrequest_ratio=overrequest_value,
            high_usage_ratio=high_usage_value,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except (SafetyBlockedError, CommandExecutionError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(
            ExitCode.SAFETY_BLOCKED
            if isinstance(exc, SafetyBlockedError)
            else ExitCode.INVALID_INPUT
        ) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("cloud-iam-audit")
def cloud_iam_audit_command(
    provider: Annotated[str, typer.Option("--provider", help="Cloud provider: azure or aws.")],
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    subscription: Annotated[str | None, typer.Option("--subscription")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Audit Azure or AWS identity exposure using read-only CLI calls or a snapshot."""

    merged, _ = tool_config(config or [], "cloud-iam-audit")
    try:
        report = build_cloud_iam_report(
            provider=provider,
            snapshot_path=snapshot,
            subscription=subscription,
            profile=profile,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except CommandExecutionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.AUTHENTICATION_FAILURE) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("cloud-waste")
def cloud_waste_command(
    provider: Annotated[str, typer.Option("--provider", help="Cloud provider: azure or aws.")],
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    subscription: Annotated[str | None, typer.Option("--subscription")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    region: Annotated[str | None, typer.Option("--region")] = None,
    required_tag: Annotated[list[str] | None, typer.Option("--required-tag")] = None,
    snapshot_age_days: Annotated[
        int | None, typer.Option("--snapshot-age-days", min=1, max=3650)
    ] = None,
    idle_age_days: Annotated[int | None, typer.Option("--idle-age-days", min=1, max=3650)] = None,
    idle_utilization_percent: Annotated[
        float | None, typer.Option("--idle-utilization-percent", min=0.0, max=100.0)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Inventory likely unused Azure or AWS resources without deleting anything."""

    merged, tool_options = tool_config(config or [], "cloud-waste")
    snapshot_days = (
        snapshot_age_days
        if snapshot_age_days is not None
        else int(tool_options.get("snapshot_age_days", 30))
    )
    idle_days = (
        idle_age_days if idle_age_days is not None else int(tool_options.get("idle_age_days", 14))
    )
    idle_percent = (
        idle_utilization_percent
        if idle_utilization_percent is not None
        else float(tool_options.get("idle_utilization_percent", 5.0))
    )
    configured_tags = {
        str(item) for item in tool_options.get("required_tags", []) if isinstance(item, str)
    }
    configured_tags.update(required_tag or [])
    try:
        report = build_cloud_waste_report(
            provider=provider,
            snapshot_path=snapshot,
            subscription=subscription,
            profile=profile,
            region=region,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            snapshot_age_days=snapshot_days,
            idle_age_days=idle_days,
            idle_utilization_percent=idle_percent,
            required_tags=configured_tags,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except CommandExecutionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.AUTHENTICATION_FAILURE) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("budget-guard")
def budget_guard_command(
    provider: Annotated[str, typer.Option("--provider", help="Cloud provider: azure or aws.")],
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    subscription: Annotated[str | None, typer.Option("--subscription")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    required_threshold: Annotated[
        list[int] | None, typer.Option("--required-threshold", min=1, max=1000)
    ] = None,
    anomaly_ratio: Annotated[
        float | None, typer.Option("--anomaly-ratio", min=1.0, max=20.0)
    ] = None,
    concentration_ratio: Annotated[
        float | None, typer.Option("--concentration-ratio", min=0.01, max=1.0)
    ] = None,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Verify cloud budgets, alert thresholds, forecasts, and cost trends."""

    merged, tool_options = tool_config(config or [], "budget-guard")
    configured_thresholds = {
        int(item)
        for item in tool_options.get("required_thresholds", [50, 80, 100])
        if isinstance(item, int)
    }
    if required_threshold:
        configured_thresholds = set(required_threshold)
    anomaly_value = (
        anomaly_ratio
        if anomaly_ratio is not None
        else float(tool_options.get("anomaly_ratio", 1.5))
    )
    concentration_value = (
        concentration_ratio
        if concentration_ratio is not None
        else float(tool_options.get("concentration_ratio", 0.6))
    )
    try:
        report = build_budget_guard_report(
            provider=provider,
            snapshot_path=snapshot,
            subscription=subscription,
            profile=profile,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            required_thresholds=configured_thresholds,
            anomaly_ratio=anomaly_value,
            concentration_ratio=concentration_value,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except CommandExecutionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.AUTHENTICATION_FAILURE) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("iac-drift-guard")
def iac_drift_guard_command(
    root: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)] = Path("."),
    plan_json: Annotated[
        Path | None, typer.Option("--plan-json", exists=True, dir_okay=False, readable=True)
    ] = None,
    binary: Annotated[str | None, typer.Option("--binary")] = None,
    expected_workspace: Annotated[str | None, typer.Option("--expected-workspace")] = None,
    var_file: Annotated[
        list[Path] | None, typer.Option("--var-file", exists=True, dir_okay=False, readable=True)
    ] = None,
    lock_timeout_seconds: Annotated[
        int | None, typer.Option("--lock-timeout", min=1, max=600)
    ] = None,
    stale_lock_minutes: Annotated[
        int | None, typer.Option("--stale-lock-minutes", min=1, max=10080)
    ] = None,
    acknowledge_production: Annotated[bool, typer.Option("--acknowledge-production")] = False,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=3600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Run or analyze a refresh-only Terraform/OpenTofu plan without applying drift."""

    merged, tool_options = tool_config(config or [], "iac-drift-guard")
    binary_value = binary or str(tool_options.get("binary", "terraform"))
    lock_value = (
        lock_timeout_seconds
        if lock_timeout_seconds is not None
        else int(tool_options.get("lock_timeout_seconds", 15))
    )
    stale_value = (
        stale_lock_minutes
        if stale_lock_minutes is not None
        else int(tool_options.get("stale_lock_minutes", 60))
    )
    try:
        report = build_iac_drift_report(
            root,
            plan_json=plan_json,
            binary=binary_value,
            expected_workspace=expected_workspace,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            lock_timeout_seconds=lock_value,
            stale_lock_minutes=stale_value,
            var_files=var_file or [],
            safety_policy=SafetyPolicy(**merged["safety"]),
            production_acknowledged=acknowledge_production,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except SafetyBlockedError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED) from exc
    except CommandExecutionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


@app.command("kube-upgrade-readiness")
def kube_upgrade_readiness_command(
    target_version: Annotated[str, typer.Option("--target-version")],
    context: Annotated[str | None, typer.Option("--context")] = None,
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", exists=True, dir_okay=False, readable=True)
    ] = None,
    acknowledge_production: Annotated[bool, typer.Option("--acknowledge-production")] = False,
    config: Annotated[
        list[Path] | None, typer.Option("--config", exists=True, dir_okay=False)
    ] = None,
    report_format: Annotated[
        ReportFormat | None, typer.Option("--format", case_sensitive=False)
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    threshold: Annotated[
        Severity | None, typer.Option("--severity-threshold", case_sensitive=False)
    ] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1, max=600)] = None,
    no_color: Annotated[bool | None, typer.Option("--no-color/--color")] = None,
) -> None:
    """Assess Kubernetes version skew, API removals, drains, webhooks, and CRD readiness."""

    merged, tool_options = tool_config(config or [], "kube-upgrade-readiness")
    allowed_contexts = {
        str(item) for item in tool_options.get("allowed_contexts", []) if isinstance(item, str)
    }
    if (
        snapshot is None
        and context is not None
        and allowed_contexts
        and context not in allowed_contexts
    ):
        typer.echo(f"Kubernetes context is not in the configured allowlist: {context}", err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED)
    try:
        report = build_kube_upgrade_report(
            target_version=target_version,
            context=context,
            snapshot_path=snapshot,
            threshold=severity_from_config(merged, threshold),
            timeout_seconds=timeout_from_config(merged, timeout_seconds),
            safety_policy=SafetyPolicy(**merged["safety"]),
            production_acknowledged=acknowledge_production,
        )
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except DependencyUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.DEPENDENCY_UNAVAILABLE) from exc
    except SafetyBlockedError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.SAFETY_BLOCKED) from exc
    except CommandExecutionError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    emit_report(
        report,
        format_from_config(merged, report_format),
        output,
        no_color=no_color_from_config(merged, no_color),
    )
    _raise_for_report(int(exit_code_for_report(report)))


def main() -> int:
    """Testable wrapper used by embedding environments."""

    try:
        result = app(standalone_mode=False)
        return int(result or ExitCode.SUCCESS)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except ToolkitError as exc:
        print(str(exc), file=sys.stderr)
        return int(ExitCode.INTERNAL_ERROR)


if __name__ == "__main__":
    raise SystemExit(main())
