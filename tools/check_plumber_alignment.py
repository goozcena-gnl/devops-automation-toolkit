"""Verify Plumber's immutable action SHA against its explicit binary release tag."""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent

API = "https://api.github.com/repos/getplumber/plumber"
SHA = re.compile(r"[0-9a-fA-F]{40}")
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
MAX_BYTES = 131_072
MAX_DEPTH = 32
MAX_EVENTS = 20_000
MAX_TAG_DEPTH = 4
MAX_REQUESTS = 12
TOTAL_SECONDS = 45
REQUEST_SECONDS = 6


class AlignmentError(ValueError):
    """The workflow is invalid or its action and binary version disagree."""


class Unavailable(RuntimeError):
    """GitHub resolution is unavailable; verification is incomplete."""


class UniqueLoader(yaml.BaseLoader):
    """Keep scalar strings (including 'on') and reject ambiguous mapping keys."""


def mapping(loader: UniqueLoader, node: yaml.MappingNode) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        if not isinstance(key_node, yaml.ScalarNode):
            raise AlignmentError("Workflow mapping keys must be scalar strings")
        key = str(loader.construct_object(key_node))
        if key in result:
            raise AlignmentError("Workflow contains duplicate mapping keys")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward the optional GitHub token to a redirect destination."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise Unavailable("GitHub redirect refused; verification is incomplete")


def unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class GitHubClient:
    """Bound public API reads by bytes, request count and a shared deadline."""

    def __init__(
        self,
        *,
        token: str | None = None,
        opener: Any = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.token = token
        self.opener = opener if opener is not None else urllib.request.build_opener(NoRedirect())
        self.clock = clock
        self.deadline = clock() + TOTAL_SECONDS
        self.requests = 0

    def remaining(self) -> float:
        seconds = self.deadline - self.clock()
        if seconds <= 0:
            raise Unavailable("GitHub time budget exceeded; verification is incomplete")
        return seconds

    def fetch(self, endpoint: str) -> dict[str, Any]:
        allowed = endpoint.startswith(API + "/git/ref/tags/") and VERSION.fullmatch(
            endpoint.removeprefix(API + "/git/ref/tags/")
        )
        allowed = allowed or (
            endpoint.startswith(API + "/git/tags/")
            and SHA.fullmatch(endpoint.removeprefix(API + "/git/tags/"))
        )
        if not allowed or self.requests >= MAX_REQUESTS:
            raise Unavailable(
                "GitHub request budget or endpoint invalid; verification is incomplete"
            )
        self.requests += 1
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "plumber-alignment-check"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            request = urllib.request.Request(endpoint, headers=headers)  # noqa: S310
            with self.opener.open(
                request, timeout=min(REQUEST_SECONDS, self.remaining())
            ) as response:
                chunks: list[bytes] = []
                size = 0
                while True:
                    self.remaining()
                    chunk = response.read1(min(8192, MAX_BYTES + 1 - size))
                    self.remaining()
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise Unavailable(
                            "GitHub response exceeds size limit; verification is incomplete"
                        )
            payload = json.loads(b"".join(chunks), object_pairs_hook=unique_json)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            # Never print response bodies, URLs, headers or underlying exceptions.
            raise Unavailable("GitHub resolution unavailable; verification is incomplete") from exc
        if not isinstance(payload, dict):
            raise Unavailable("Invalid GitHub JSON mapping; verification is incomplete")
        return payload


def git_object(payload: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(payload, dict):
        raise Unavailable("Invalid GitHub JSON mapping; verification is incomplete")
    obj = payload.get("object")
    if not isinstance(obj, dict):
        raise Unavailable("Invalid GitHub object; verification is incomplete")
    sha, kind = obj.get("sha"), obj.get("type")
    if (
        not isinstance(sha, str)
        or SHA.fullmatch(sha) is None
        or not isinstance(kind, str)
        or kind not in {"commit", "tag"}
    ):
        raise Unavailable("Invalid GitHub object; verification is incomplete")
    return sha.lower(), kind


def reference(payload: Mapping[str, Any], version: str) -> tuple[str, str]:
    if not isinstance(payload, dict) or payload.get("ref") != "refs/tags/" + version:
        raise Unavailable("GitHub tag reference mismatch; verification is incomplete")
    return git_object(payload)


def resolve_release(version: str, fetch: Callable[[str], dict[str, Any]]) -> str:
    if VERSION.fullmatch(version) is None:
        raise AlignmentError("Plumber version must be an explicit stable vMAJOR.MINOR.PATCH tag")
    endpoint = f"{API}/git/ref/tags/{version}"
    original = reference(fetch(endpoint), version)
    sha, kind = original
    visited: set[str] = set()
    for depth in range(MAX_TAG_DEPTH + 1):
        if kind == "commit":
            if reference(fetch(endpoint), version) != original:
                raise Unavailable("GitHub tag moved during resolution; verification is incomplete")
            return sha
        if depth == MAX_TAG_DEPTH or sha in visited:
            raise Unavailable("GitHub tag cycle or depth limit; verification is incomplete")
        visited.add(sha)
        payload = fetch(f"{API}/git/tags/{sha}")
        identity = payload.get("sha") if isinstance(payload, dict) else None
        if not isinstance(identity, str) or identity.lower() != sha:
            raise Unavailable("GitHub tag identity mismatch; verification is incomplete")
        sha, kind = git_object(payload)
    raise Unavailable("GitHub tag could not be resolved; verification is incomplete")


def check_text(text: str, resolver: Callable[[str], str]) -> int:
    try:
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise AlignmentError("Workflow exceeds size limit")
        depth = 0
        for count, event in enumerate(yaml.parse(text), start=1):
            if getattr(event, "tag", None) not in {
                None,
                "tag:yaml.org,2002:str",
                "tag:yaml.org,2002:map",
                "tag:yaml.org,2002:seq",
            }:
                raise AlignmentError("Workflow contains an unsupported YAML tag")
            if isinstance(event, AliasEvent):
                raise AlignmentError("Workflow aliases are not supported")
            if isinstance(event, CollectionStartEvent):
                depth += 1
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
            if depth > MAX_DEPTH or count > MAX_EVENTS:
                raise AlignmentError("Workflow exceeds structural limits")
        # BaseLoader constructs inert scalar strings, never Python objects.
        loader = UniqueLoader(text)
        try:
            config = loader.get_single_data()
        finally:
            loader.dispose()
    except (yaml.YAMLError, UnicodeError) as exc:
        raise AlignmentError("Workflow YAML is invalid") from exc
    if not isinstance(config, dict) or not isinstance(config.get("jobs"), dict):
        raise AlignmentError("Workflow jobs must be a mapping")
    pairs: list[tuple[str, str]] = []
    for job in config["jobs"].values():
        if not isinstance(job, dict):
            raise AlignmentError("Workflow job must be a mapping")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise AlignmentError("Workflow steps must be a list")
        for step in steps:
            if not isinstance(step, dict):
                raise AlignmentError("Workflow step must be a mapping")
            uses = step.get("uses", "")
            if not isinstance(uses, str) or "${{" in uses:
                raise AlignmentError("Workflow action reference must be a literal string")
            if not uses.lower().startswith("getplumber/plumber"):
                continue
            match = re.fullmatch(r"getplumber/plumber@([0-9a-fA-F]{40})", uses, re.IGNORECASE)
            if match is None:
                raise AlignmentError("Plumber action must use an immutable full SHA")
            inputs = step.get("with")
            if not isinstance(inputs, dict):
                raise AlignmentError("Plumber inputs must be a mapping")
            version = inputs.get("version")
            if not isinstance(version, str) or VERSION.fullmatch(version) is None:
                raise AlignmentError(
                    "Plumber version must be an explicit stable vMAJOR.MINOR.PATCH tag"
                )
            pairs.append((match[1].lower(), version))
    if not pairs:
        raise AlignmentError("Expected Plumber action was not found")
    cache: dict[str, str] = {}
    for pinned, version in pairs:
        if version not in cache:
            resolved = resolver(version)
            if not isinstance(resolved, str) or SHA.fullmatch(resolved) is None:
                raise Unavailable("Invalid resolved commit; verification is incomplete")
            cache[version] = resolved.lower()
        if pinned != cache[version]:
            raise AlignmentError("Plumber action SHA does not match the declared binary release")
    return len(pairs)


def run(argv: Sequence[str], resolver: Callable[[str], str] | None = None) -> int:
    if list(argv) == ["--help"]:
        print(
            "Usage: check_plumber_alignment.py WORKFLOW.yml\nExit: 0 verified; 1 invalid/mismatch; 2 unavailable"
        )
        return 0
    if len(argv) != 1:
        print("Expected one workflow path; use --help", file=sys.stderr)
        return 1
    try:
        with Path(argv[0]).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise AlignmentError("Workflow exceeds size limit")
        text = raw.decode("utf-8")
        if resolver is None:
            client = GitHubClient(token=os.environ.get("GITHUB_TOKEN"))

            def resolver(version: str) -> str:
                return resolve_release(version, client.fetch)

        count = check_text(text, resolver)
    except Unavailable:
        print(
            "Plumber alignment unavailable: GitHub evidence is incomplete; rerun after recovery",
            file=sys.stderr,
        )
        return 2
    except (OSError, UnicodeError, AlignmentError):
        print(
            "Plumber alignment failed: invalid workflow, input or version mismatch", file=sys.stderr
        )
        return 1
    print(f"Plumber alignment verified for {count} step(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
