from __future__ import annotations

import json

import pytest

from devops_toolkit.commands import kube_rightsize, kube_triage, kube_upgrade_readiness
from devops_toolkit.commands.common import exit_code_for_report
from devops_toolkit.core import kubernetes
from devops_toolkit.core.exceptions import ConfigurationError, SafetyBlockedError
from devops_toolkit.core.kubernetes import KubernetesReadPolicy
from devops_toolkit.core.models import Severity
from devops_toolkit.core.subprocess import CommandResult


@pytest.fixture
def kube_boundary(monkeypatch):
    local_config = {
        "current": "development",
        "contexts": [["development", "sandbox"]],
        "clusters": [["sandbox", "https://sandbox.example.invalid", ""]],
    }
    requests = []
    responses = {}

    def fake_command(args, **_options):
        if args[1:3] == ["config", "view"]:
            return CommandResult(tuple(args), 0, json.dumps(local_config), "")
        requests.append(args)
        resource = args[-1]
        return CommandResult(tuple(args), 0, json.dumps(responses.get(resource, {"items": []})), "")

    monkeypatch.setattr(kubernetes, "run_command", fake_command)
    return local_config, requests, responses


@pytest.mark.parametrize(
    "build,kwargs",
    [
        (kube_triage.build_report, {}),
        (kube_rightsize.build_report, {}),
        (kube_upgrade_readiness.build_report, {"target_version": "1.33.0"}),
    ],
)
@pytest.mark.parametrize("context", ["development", None])
def test_disallowed_effective_context_stops_at_local_configuration(
    kube_boundary, build, kwargs, context
):
    _, requests, _ = kube_boundary
    with pytest.raises(SafetyBlockedError, match="context"):
        build(
            context=context,
            read_policy=KubernetesReadPolicy(allowed_contexts=["staging"]),
            **kwargs,
        )
    assert not requests


def test_rightsize_queries_only_authorized_namespace(kube_boundary):
    _, requests, _ = kube_boundary
    report = kube_rightsize.build_report(
        namespace="payments", read_policy=KubernetesReadPolicy(allowed_namespaces=["payments"])
    )
    assert not report.metadata.partial
    assert requests[0][-3:] == ["get", "--raw", "/api/v1/namespaces/payments/pods"]
    assert requests[1][-1] == "/apis/metrics.k8s.io/v1beta1/namespaces/payments/pods"


def test_triage_excludes_nodes_without_cluster_opt_in(kube_boundary):
    _, requests, _ = kube_boundary
    report, collections = kube_triage.build_report(namespace="payments")
    assert "nodes" not in collections
    assert all(not request[-1].endswith("/nodes") for request in requests)
    assert report.extensions["scope"]["cluster_scoped"] is False


def test_upgrade_requires_cluster_opt_in_before_api_requests(kube_boundary):
    _, requests, _ = kube_boundary
    with pytest.raises(SafetyBlockedError, match="allow_cluster_scope"):
        kube_upgrade_readiness.build_report(target_version="1.33.0")
    assert not requests


@pytest.mark.parametrize("namespace", ["", "bad/name", "--all-namespaces", "bad%2Fname"])
def test_invalid_namespace_never_reaches_api(kube_boundary, namespace):
    _, requests, _ = kube_boundary
    with pytest.raises(ConfigurationError, match="namespace"):
        kube_rightsize.build_report(namespace=namespace)
    assert not requests


def test_ambiguous_implicit_scope_stops_before_api(kube_boundary):
    config, requests, _ = kube_boundary
    config["contexts"].append(["staging", "sandbox"])
    with pytest.raises(ConfigurationError, match="context explicitly"):
        kube_triage.collect_cluster(None)
    assert not requests


@pytest.mark.parametrize(
    "policy",
    [
        KubernetesReadPolicy(allowed_namespaces=[]),
        KubernetesReadPolicy(allowed_contexts=[]),
        KubernetesReadPolicy(allowed_servers=[]),
    ],
)
def test_explicit_empty_allowlists_deny_all(kube_boundary, policy):
    _, requests, _ = kube_boundary
    with pytest.raises(SafetyBlockedError, match="allowlist"):
        kube_rightsize.collect_snapshot(
            None,
            namespace="payments",
            all_namespaces=False,
            timeout_seconds=5,
            read_policy=policy,
        )
    assert not requests


def test_all_namespaces_uses_only_global_pods_and_metrics_when_allowed(kube_boundary):
    _, requests, _ = kube_boundary
    kube_rightsize.build_report(all_namespaces=True)
    assert [request[-1] for request in requests] == [
        "/api/v1/pods",
        "/apis/metrics.k8s.io/v1beta1/pods",
    ]


@pytest.mark.parametrize(
    "build,kwargs",
    [
        (kube_rightsize.build_report, {"all_namespaces": True}),
        (kube_upgrade_readiness.build_report, {"target_version": "1.33.0"}),
    ],
)
def test_restrictive_namespace_policy_prevents_any_global_request(kube_boundary, build, kwargs):
    _, requests, _ = kube_boundary
    with pytest.raises(SafetyBlockedError, match="namespace"):
        build(
            read_policy=KubernetesReadPolicy(
                allowed_namespaces=["payments"],
                allow_cluster_scope=True,
            ),
            **kwargs,
        )
    assert not requests


def test_production_endpoint_behind_neutral_context_requires_acknowledgement(kube_boundary):
    config, requests, _ = kube_boundary
    config["clusters"][0][1] = "https://prod.example.invalid"
    with pytest.raises(SafetyBlockedError, match="acknowledgement"):
        kube_rightsize.build_report()
    with pytest.raises(SafetyBlockedError, match="API server"):
        kube_rightsize.build_report(
            production_acknowledged=True,
            read_policy=KubernetesReadPolicy(allowed_servers=["https://sandbox.example.invalid"]),
        )
    assert not requests


def test_triage_never_returns_out_of_scope_data_for_bundling(kube_boundary):
    _, _, responses = kube_boundary
    responses["/api/v1/namespaces/payments/pods"] = {
        "items": [{"kind": "Pod", "metadata": {"namespace": "finance", "name": "canary"}}],
    }
    report, collections = kube_triage.build_report(namespace="payments")
    assert "pods" not in collections
    assert "outside the authorized scope" in report.extensions["collection_errors"]["pods"]
    assert "canary" not in report.model_dump_json()
    assert report.metadata.partial


def test_finding_threshold_keeps_priority_over_partial_evidence(kube_boundary):
    _, _, responses = kube_boundary
    responses["/apis/metrics.k8s.io/v1beta1/namespaces/payments/pods"] = {
        "items": [{"metadata": {"namespace": "finance"}}],
    }
    report = kube_rightsize.build_report(namespace="payments", threshold=Severity.MEDIUM)
    assert report.metadata.partial
    assert [finding.id for finding in report.findings] == ["KUBE-METRICS-UNAVAILABLE"]
    assert exit_code_for_report(report) == 1


def test_valid_empty_lists_produce_complete_success(kube_boundary):
    _, requests, _ = kube_boundary
    report = kube_rightsize.build_report()
    assert len(requests) == 2
    assert not report.findings
    assert not report.metadata.partial
    assert exit_code_for_report(report) == 0


@pytest.mark.parametrize(
    ("resource", "fields"),
    [
        ("events", {"related": {"namespace": "finance", "name": "canary"}}),
        ("endpoints", {"subsets": [{"addresses": [{"targetRef": {"namespace": "finance"}}]}]}),
    ],
)
def test_triage_rejects_cross_namespace_structured_references(kube_boundary, resource, fields):
    _, _, responses = kube_boundary
    responses[f"/api/v1/namespaces/payments/{resource}"] = {
        "items": [{"metadata": {"namespace": "payments"}, **fields}],
    }
    report, collections = kube_triage.build_report(namespace="payments")
    assert resource not in collections
    assert (
        "reference outside the authorized scope" in report.extensions["collection_errors"][resource]
    )


def test_triage_drops_unknown_list_envelope_fields(kube_boundary):
    _, _, responses = kube_boundary
    responses["/api/v1/namespaces/payments/pods"] = {
        "items": [],
        "extra": {"namespace": "finance"},
        "metadata": {"namespace": "finance", "resourceVersion": "42"},
    }
    _, collections = kube_triage.build_report(namespace="payments")
    assert collections["pods"] == {"items": [], "metadata": {"resourceVersion": "42"}}


def test_empty_metrics_list_for_existing_pods_leaves_usage_unverified(kube_boundary):
    _, _, responses = kube_boundary
    responses["/api/v1/namespaces/payments/pods"] = {
        "items": [{"kind": "Pod", "metadata": {"namespace": "payments"}}],
    }
    report = kube_rightsize.build_report(namespace="payments")
    assert report.metadata.partial
    assert report.extensions["collection_errors"]["metrics"] == (
        "Metrics API returned no samples for the collected Pods"
    )
