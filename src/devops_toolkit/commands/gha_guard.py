"""Static GitHub Actions security and reliability auditor."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml

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

TOOL_NAME = "gha-guard"
SHA_REF = re.compile(r"^[0-9a-fA-F]{40}$")
UNTRUSTED_RUN_INPUT = re.compile(
    r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body)\s*\}\}"
)


class WorkflowLoader(yaml.SafeLoader):
    """YAML loader that preserves GitHub's `on` key as a string."""


WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for first_character, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
    WorkflowLoader.yaml_implicit_resolvers[first_character] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
WorkflowLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def _line_containing(text: str, needle: str) -> int | None:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _finding(
    identifier: str,
    severity: Severity,
    title: str,
    recommendation: str,
    workflow: Path,
    root: Path,
    *,
    needle: str = "",
    confidence: Confidence = Confidence.HIGH,
    summary: str | None = None,
) -> Finding:
    relative = workflow.relative_to(root).as_posix()
    text = workflow.read_text(encoding="utf-8", errors="replace")
    line = _line_containing(text, needle) if needle else None
    return Finding(
        id=identifier,
        tool=TOOL_NAME,
        category="github-actions",
        severity=severity,
        confidence=confidence,
        title=title,
        description="Static workflow analysis identified a security or reliability weakness.",
        recommendation=recommendation,
        resource=ResourceRef(type="GitHubWorkflow", name=relative),
        evidence=Evidence(summary=summary or title, location=relative, line=line),
    )


def _permission_findings(
    permissions: Any,
    workflow: Path,
    root: Path,
    *,
    scope: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if permissions is None:
        findings.append(
            _finding(
                "GHA-PERMISSIONS-UNDECLARED",
                Severity.MEDIUM,
                f"Permissions are not explicitly declared at {scope} scope",
                "Declare least-privilege permissions explicitly and use `contents: read` as the baseline.",
                workflow,
                root,
                needle="permissions:",
                confidence=Confidence.MEDIUM,
            )
        )
        return findings
    if isinstance(permissions, str):
        if permissions == "write-all":
            findings.append(
                _finding(
                    "GHA-PERMISSIONS-WRITE-ALL",
                    Severity.CRITICAL,
                    f"Workflow grants write-all permissions at {scope} scope",
                    "Replace write-all with the smallest per-scope permissions required by each job.",
                    workflow,
                    root,
                    needle="write-all",
                )
            )
        return findings
    if isinstance(permissions, dict):
        for name, value in permissions.items():
            if str(value).lower() != "write":
                continue
            severity = (
                Severity.HIGH
                if name in {"contents", "actions", "id-token", "packages"}
                else Severity.MEDIUM
            )
            findings.append(
                _finding(
                    "GHA-PERMISSION-WRITE",
                    severity,
                    f"Write permission `{name}: write` is granted at {scope} scope",
                    "Move write permissions to the single job that needs them and document why they are required.",
                    workflow,
                    root,
                    needle=f"{name}:",
                    confidence=Confidence.HIGH,
                )
            )
    return findings


def _events(workflow_data: dict[str, Any]) -> set[str]:
    raw = workflow_data.get("on")
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(item) for item in raw}
    if isinstance(raw, dict):
        return {str(item) for item in raw}
    return set()


def analyze_workflow(workflow: Path, root: Path) -> tuple[list[Finding], dict[str, int]]:
    text = workflow.read_text(encoding="utf-8", errors="replace")
    loader = WorkflowLoader(text)
    try:
        loaded = loader.get_single_data()
    except yaml.YAMLError as exc:
        line = (
            exc.problem_mark.line + 1
            if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark
            else None
        )
        finding = Finding(
            id="GHA-YAML-PARSE-ERROR",
            tool=TOOL_NAME,
            category="github-actions",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Workflow YAML cannot be parsed",
            recommendation="Correct the YAML syntax before the workflow is merged or executed.",
            resource=ResourceRef(type="GitHubWorkflow", name=workflow.relative_to(root).as_posix()),
            evidence=Evidence(
                summary=str(exc).splitlines()[0][:300],
                location=workflow.relative_to(root).as_posix(),
                line=line,
            ),
        )
        return [finding], {"jobs": 0, "steps": 0}
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]
    if not isinstance(loaded, dict):
        return [
            _finding(
                "GHA-WORKFLOW-ROOT",
                Severity.HIGH,
                "Workflow root is not a mapping",
                "Use a GitHub Actions workflow mapping with `name`, `on`, and `jobs` keys.",
                workflow,
                root,
            )
        ], {"jobs": 0, "steps": 0}
    data: dict[str, Any] = loaded
    findings = _permission_findings(data.get("permissions"), workflow, root, scope="workflow")
    events = _events(data)
    if "pull_request_target" in events:
        findings.append(
            _finding(
                "GHA-PULL-REQUEST-TARGET",
                Severity.HIGH,
                "Workflow uses pull_request_target",
                "Avoid checking out or executing untrusted pull-request code in this event; split privileged and untrusted processing.",
                workflow,
                root,
                needle="pull_request_target",
            )
        )
    if "concurrency" not in data:
        findings.append(
            _finding(
                "GHA-CONCURRENCY-MISSING",
                Severity.LOW,
                "Workflow has no concurrency policy",
                "Add a concurrency group and cancel superseded runs where safe to reduce duplicate deployments and cost.",
                workflow,
                root,
                confidence=Confidence.MEDIUM,
            )
        )
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        findings.append(
            _finding(
                "GHA-JOBS-INVALID",
                Severity.HIGH,
                "Workflow jobs section is invalid",
                "Define jobs as a mapping keyed by stable job identifiers.",
                workflow,
                root,
                needle="jobs:",
            )
        )
        return findings, {"jobs": 0, "steps": 0}
    step_count = 0
    for job_name, raw_job in jobs.items():
        if not isinstance(raw_job, dict):
            continue
        job: dict[str, Any] = raw_job
        if "permissions" in job:
            findings.extend(
                _permission_findings(
                    job.get("permissions"), workflow, root, scope=f"job `{job_name}`"
                )
            )
        if "timeout-minutes" not in job:
            findings.append(
                _finding(
                    "GHA-TIMEOUT-MISSING",
                    Severity.MEDIUM,
                    f"Job `{job_name}` has no timeout",
                    "Set timeout-minutes to bound hung commands and hosted-runner consumption.",
                    workflow,
                    root,
                    needle=f"{job_name}:",
                    confidence=Confidence.HIGH,
                )
            )
        runs_on = job.get("runs-on")
        run_labels = (
            [runs_on] if isinstance(runs_on, str) else runs_on if isinstance(runs_on, list) else []
        )
        if any(str(label).lower() == "self-hosted" for label in run_labels):
            findings.append(
                _finding(
                    "GHA-SELF-HOSTED-RUNNER",
                    Severity.HIGH
                    if "pull_request" in events or "pull_request_target" in events
                    else Severity.MEDIUM,
                    f"Job `{job_name}` uses a self-hosted runner",
                    "Isolate ephemeral runners, restrict repository access, and never run untrusted fork code on persistent runners.",
                    workflow,
                    root,
                    needle="self-hosted",
                    confidence=Confidence.HIGH,
                )
            )
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for raw_step in steps:
            if not isinstance(raw_step, dict):
                continue
            step: dict[str, Any] = raw_step
            step_count += 1
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("docker://") and "@sha256:" not in uses:
                findings.append(
                    _finding(
                        "GHA-DOCKER-ACTION-NOT-DIGEST-PINNED",
                        Severity.HIGH,
                        "Docker action image is not pinned by digest",
                        "Replace the mutable image tag with a reviewed sha256 digest.",
                        workflow,
                        root,
                        needle=uses,
                    )
                )
            if (
                isinstance(uses, str)
                and not uses.startswith("./")
                and not uses.startswith("docker://")
            ):
                if "@" not in uses:
                    findings.append(
                        _finding(
                            "GHA-ACTION-REF-MISSING",
                            Severity.CRITICAL,
                            "Third-party action reference has no version",
                            "Pin the action to a reviewed full commit SHA and document the upstream release tag.",
                            workflow,
                            root,
                            needle=uses,
                        )
                    )
                else:
                    _, reference = uses.rsplit("@", 1)
                    if not SHA_REF.fullmatch(reference):
                        findings.append(
                            _finding(
                                "GHA-ACTION-NOT-SHA-PINNED",
                                Severity.HIGH,
                                f"Action `{uses.split('@', 1)[0]}` is not pinned to a full commit SHA",
                                "Replace the mutable tag or branch with a reviewed 40-character commit SHA.",
                                workflow,
                                root,
                                needle=uses,
                            )
                        )
                if uses.startswith("actions/checkout@"):
                    with_values = step.get("with", {})
                    persist = (
                        with_values.get("persist-credentials")
                        if isinstance(with_values, dict)
                        else None
                    )
                    if persist is not False and str(persist).lower() != "false":
                        findings.append(
                            _finding(
                                "GHA-CHECKOUT-PERSIST-CREDENTIALS",
                                Severity.MEDIUM,
                                "Checkout credentials remain persisted",
                                "Set `persist-credentials: false` unless later steps explicitly require the GitHub token in Git configuration.",
                                workflow,
                                root,
                                needle="actions/checkout@",
                                confidence=Confidence.HIGH,
                            )
                        )
                if uses.startswith("actions/upload-artifact@"):
                    with_values = step.get("with", {})
                    if not isinstance(with_values, dict) or "retention-days" not in with_values:
                        findings.append(
                            _finding(
                                "GHA-ARTIFACT-RETENTION",
                                Severity.LOW,
                                "Artifact retention is not explicitly bounded",
                                "Set retention-days according to data sensitivity and operational need.",
                                workflow,
                                root,
                                needle="actions/upload-artifact@",
                                confidence=Confidence.MEDIUM,
                            )
                        )
            run = step.get("run")
            if isinstance(run, str) and UNTRUSTED_RUN_INPUT.search(run):
                findings.append(
                    _finding(
                        "GHA-UNTRUSTED-INPUT-IN-SHELL",
                        Severity.CRITICAL,
                        "Untrusted event data is interpolated directly into a shell command",
                        "Pass the expression through an environment variable and quote it safely, or process it with a non-shell action.",
                        workflow,
                        root,
                        needle="run:",
                    )
                )
    return findings, {"jobs": len(jobs), "steps": step_count}


def build_report(root: Path, *, threshold: Severity = Severity.HIGH) -> Report:
    started = utc_now()
    workflow_root = root / ".github" / "workflows"
    workflows = (
        sorted(
            path
            for path in workflow_root.glob("*")
            if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
        )
        if workflow_root.exists()
        else []
    )
    findings: list[Finding] = []
    jobs = 0
    steps = 0
    for workflow in workflows:
        workflow_findings, metrics = analyze_workflow(workflow, root)
        findings.extend(workflow_findings)
        jobs += metrics["jobs"]
        steps += metrics["steps"]
    completed = utc_now()
    return Report(
        metadata=ReportMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            started_at=started,
            completed_at=completed,
            target=str(root.resolve()),
            capabilities=[
                "workflow-yaml",
                "permissions",
                "action-pinning",
                "shell-injection",
                "sarif",
            ],
        ),
        findings=findings,
        status=status_for_findings(findings, threshold),
        extensions={"metrics": {"workflows": len(workflows), "jobs": jobs, "steps": steps}},
    )
