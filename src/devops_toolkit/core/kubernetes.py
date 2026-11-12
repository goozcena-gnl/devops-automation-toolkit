"""Authorize live Kubernetes reads before invoking the API."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from devops_toolkit.core.exceptions import (
    CommandExecutionError,
    ConfigurationError,
    SafetyBlockedError,
)
from devops_toolkit.core.safety import SafetyPolicy, require_safe_target
from devops_toolkit.core.subprocess import CommandResult, run_command

_KUBECTL = "kubectl.exe" if sys.platform == "win32" else "kubectl"
_NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_API_VERSION = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_AUTH_ERROR = re.compile(
    r"\((?:Forbidden|Unauthorized)\)|\b(?:401 Unauthorized|403 Forbidden)\b"
    r"|^error: You must be logged in to the server\b",
    re.IGNORECASE | re.MULTILINE,
)


# Project only the values needed for authorization. config view is local and does
# not invoke authentication plugins. Never request raw credentials or user data.
_TARGETS_TEMPLATE = (
    '{"current":{{with index . "current-context"}}{{printf "%q" .}}{{else}}""{{end}},'
    '"contexts":[{{range $i,$v := .contexts}}{{if $i}},{{end}}'
    '[{{printf "%q" $v.name}},{{printf "%q" $v.context.cluster}}]{{end}}],'
    '"clusters":[{{range $i,$v := .clusters}}{{if $i}},{{end}}'
    '[{{printf "%q" $v.name}},{{printf "%q" $v.cluster.server}},'
    '{{with index $v.cluster "tls-server-name"}}{{printf "%q" .}}{{else}}""{{end}}]{{end}}]}'
)


class KubernetesAuthorizationError(CommandExecutionError):
    """kubectl reported a server authentication or authorization failure."""


@dataclass(frozen=True)
class KubernetesTarget:
    context: str
    cluster: str
    server: str
    tls_server_name: str

    @property
    def args(self) -> list[str]:
        return [
            _KUBECTL,
            f"--context={self.context}",
            f"--cluster={self.cluster}",
            f"--server={self.server}",
            f"--tls-server-name={self.tls_server_name}",
        ]


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value.isprintable() and value == value.strip()


def _index_targets(rows: object, *, columns: int) -> dict[str, list[str]]:
    if not isinstance(rows, list):
        raise ConfigurationError("Invalid Kubernetes target configuration")
    targets: dict[str, list[str]] = {}
    for entry in rows:
        if (
            not isinstance(entry, list)
            or len(entry) != columns
            or not all(map(_valid_name, entry[:2]))
            or (columns == 3 and entry[2] != "" and not _valid_name(entry[2]))
        ):
            raise ConfigurationError("Invalid Kubernetes target configuration")
        name, *values = entry
        if name in targets:
            raise ConfigurationError("Ambiguous Kubernetes target configuration")
        targets[name] = values
    return targets


def resolve_target(
    context: str | None, timeout_seconds: int, *, use_current: bool = False
) -> KubernetesTarget:
    if context is not None and not _valid_name(context):
        raise ConfigurationError("Invalid Kubernetes context name")
    result = run_command(
        [_KUBECTL, "config", "view", f"-o=go-template={_TARGETS_TEMPLATE}"],
        timeout_seconds=timeout_seconds,
        max_output_chars=1_000_000,
        sanitize_output=False,
    )
    if not result.succeeded or result.truncated:
        raise ConfigurationError("Unable to resolve Kubernetes target from local configuration")
    try:
        payload = json.loads(result.stdout)
    except (ValueError, RecursionError) as exc:
        raise ConfigurationError("Invalid Kubernetes target configuration") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("Invalid Kubernetes target configuration")
    contexts = _index_targets(payload.get("contexts"), columns=2)
    if context is None:
        if use_current:
            current = payload.get("current")
            if not isinstance(current, str) or not current:
                raise ConfigurationError("No current Kubernetes context is configured")
            context = current
        elif len(contexts) == 1:
            context = next(iter(contexts))
        else:
            raise ConfigurationError("Select a Kubernetes context explicitly with --context")
    if context not in contexts:
        raise ConfigurationError("Selected Kubernetes context does not exist")
    (cluster,) = contexts[context]
    endpoint_config = _index_targets(payload.get("clusters"), columns=3).get(cluster)
    if endpoint_config is None:
        raise ConfigurationError("Selected Kubernetes cluster does not exist")
    server, tls_server_name = endpoint_config
    try:
        endpoint = urlsplit(server)
        if (
            endpoint.scheme not in {"https", "http"}
            or not endpoint.hostname
            or endpoint.username is not None
            or "\\" in server
            or endpoint.query
            or endpoint.fragment
            or any(char.isspace() for char in server)
        ):
            raise ValueError
    except ValueError as exc:
        raise ConfigurationError("Invalid Kubernetes API server in local configuration") from exc
    return KubernetesTarget(context, cluster, server, tls_server_name)


@dataclass(frozen=True)
class KubernetesReadPolicy:
    allowed_contexts: Sequence[str] | None = None
    allowed_namespaces: Sequence[str] | None = None
    allowed_servers: Sequence[str] | None = None
    allow_cluster_scope: bool = False

    def authorize(
        self,
        context: str | None,
        *,
        timeout_seconds: int,
        safety_policy: SafetyPolicy | None,
        production_acknowledged: bool,
        namespace: str,
        all_namespaces: bool,
        require_cluster_scope: bool = False,
    ) -> KubernetesTarget:
        target = resolve_target(context, timeout_seconds, use_current=require_cluster_scope)
        if self.allowed_contexts is not None and target.context not in self.allowed_contexts:
            raise SafetyBlockedError("Kubernetes context is not in the configured allowlist")
        if self.allowed_servers is not None and target.server not in self.allowed_servers:
            raise SafetyBlockedError("Kubernetes API server is not in the configured allowlist")
        safety = safety_policy or SafetyPolicy()
        hostname = urlsplit(target.server).hostname or ""
        for identity in (
            target.context,
            target.cluster,
            target.server,
            target.tls_server_name,
            hostname,
            *hostname.split("."),
        ):
            require_safe_target(identity, safety, production_acknowledged=production_acknowledged)
        if not _NAMESPACE.fullmatch(namespace):
            raise ConfigurationError("Invalid Kubernetes namespace: expected a DNS label")
        if self.allowed_namespaces is not None and (
            all_namespaces or namespace not in self.allowed_namespaces
        ):
            raise SafetyBlockedError(
                "Requested Kubernetes namespace scope is not in the configured allowlist"
            )
        if require_cluster_scope and self.allow_cluster_scope is not True:
            raise SafetyBlockedError("Live Kubernetes upgrade requires allow_cluster_scope: true")
        return target


DEFAULT_KUBERNETES_READ_POLICY = KubernetesReadPolicy()


def resource_path(api: str, resource: str, namespace: str | None) -> str:
    return (
        f"{api}/namespaces/{namespace}/{resource}" if namespace is not None else f"{api}/{resource}"
    )


def command_error(result: CommandResult, *, required: bool = False) -> str | None:
    if result.timed_out:
        return "kubectl request timed out"
    if result.truncated:
        return "kubectl output was truncated"
    if result.returncode == 0:
        return None
    if _AUTH_ERROR.search(result.stderr):
        if required:
            raise KubernetesAuthorizationError(
                "Kubernetes API denied authentication or authorization"
            )
        return "Kubernetes API denied authentication or authorization"
    return "kubectl request failed"


def read_json(
    args: list[str], timeout_seconds: int, *, required: bool = False
) -> tuple[dict[str, Any], str | None]:
    result = run_command(
        args, timeout_seconds=timeout_seconds, max_output_chars=10_000_000, sanitize_output=False
    )
    error = command_error(result, required=required)
    if error:
        return {}, error
    try:
        payload = json.loads(result.stdout)
    except (ValueError, RecursionError):
        return {}, "kubectl returned invalid JSON"
    if not isinstance(payload, dict):
        return {}, "kubectl returned an unexpected JSON response"
    return payload, None


def _object_references(item: dict[str, Any], kinds: tuple[str, ...]) -> Iterator[object]:
    if kinds == ("Event",):
        yield item.get("involvedObject")
        yield item.get("related")
    if kinds == ("Endpoints",):
        subsets = item.get("subsets")
        if isinstance(subsets, list):
            for subset in subsets:
                if isinstance(subset, dict):
                    for key in ("addresses", "notReadyAddresses"):
                        addresses = subset.get(key)
                        if isinstance(addresses, list):
                            for address in addresses:
                                if isinstance(address, dict):
                                    yield address.get("targetRef")


def read_list(
    args: list[str],
    timeout_seconds: int,
    *,
    namespace: str | None = None,
    namespaced: bool = True,
    required: bool = False,
    allowed_kinds: tuple[str, ...] = (),
) -> tuple[dict[str, Any], str | None]:
    payload, error = read_json(args, timeout_seconds, required=required)
    if error:
        return {}, error
    kind = payload.get("kind")
    if (
        kind is not None
        and allowed_kinds
        and kind not in ("List", *(f"{item_kind}List" for item_kind in allowed_kinds))
    ):
        return {}, "kubectl response contains an unexpected resource list"
    items = payload.get("items")
    if not isinstance(items, list):
        return {}, "kubectl response is missing a resource list"
    list_metadata = payload.get("metadata")
    if isinstance(list_metadata, dict) and list_metadata.get("continue"):
        return {}, "kubectl response contains an incomplete resource list"
    for item in items:
        metadata = item.get("metadata") if isinstance(item, dict) else None
        if not isinstance(metadata, dict):
            return {}, "kubectl response contains invalid resource metadata"
        if allowed_kinds and item.get("kind") is not None and item["kind"] not in allowed_kinds:
            return {}, "kubectl response contains an unexpected resource kind"
        item_namespace = metadata.get("namespace")
        if namespaced:
            if (
                not isinstance(item_namespace, str)
                or not _NAMESPACE.fullmatch(item_namespace)
                or (namespace is not None and item_namespace != namespace)
            ):
                return {}, "kubectl response contains a resource outside the authorized scope"
        elif item_namespace not in (None, ""):
            return {}, "kubectl response contains a resource outside the authorized scope"
        if namespace is not None:
            for reference in _object_references(item, allowed_kinds):
                if isinstance(reference, dict) and reference.get("namespace") not in (
                    None,
                    "",
                    namespace,
                ):
                    return {}, "kubectl response contains a reference outside the authorized scope"

    # A List carries its evidence in items and a small Kubernetes ListMeta envelope.
    # Drop unrelated top-level values before passing data to bundle writers.
    validated: dict[str, Any] = {
        key: payload[key] for key in ("apiVersion", "kind", "items") if key in payload
    }
    if isinstance(list_metadata, dict):
        validated["metadata"] = {
            key: list_metadata[key]
            for key in ("resourceVersion", "continue", "remainingItemCount", "selfLink")
            if key in list_metadata
        }
    return validated, None


def read_api_versions(
    target: KubernetesTarget, timeout_seconds: int
) -> tuple[list[str], str | None]:
    result = run_command(
        [*target.args, "api-versions"],
        timeout_seconds=timeout_seconds,
        max_output_chars=2_000_000,
        sanitize_output=False,
    )
    error = command_error(result)
    if error:
        return [], error
    versions = result.stdout.splitlines()
    if not versions or not all(map(_valid_api_version, versions)):
        return [], "kubectl returned an unexpected API version list"
    return versions, None


def _valid_api_version(value: str) -> bool:
    group, separator, version = value.rpartition("/")
    return bool(_API_VERSION.fullmatch(version)) and (
        not separator
        or (len(group) <= 253 and all(_NAMESPACE.fullmatch(label) for label in group.split(".")))
    )
