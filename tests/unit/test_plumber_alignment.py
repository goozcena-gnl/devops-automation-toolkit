"""Exercise the Plumber guard offline, including malformed and unavailable evidence."""

from __future__ import annotations

import io
import json
import runpy
import urllib.error
from pathlib import Path

import pytest

checker = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "tools/check_plumber_alignment.py")
)
AlignmentError = checker["AlignmentError"]
Unavailable = checker["Unavailable"]
Client = checker["GitHubClient"]
check_text = checker["check_text"]
resolve_release = checker["resolve_release"]
run = checker["run"]
API = checker["API"]
NEW = "bdac4bb86e112220f05aaaa52264b9a25e21a9f5"
OLD = "d3536bae4727b9290d9e69ee25c4350ddbcd91cd"
VERSION = "v0.6.3"
ENDPOINT = API + "/git/ref/tags/" + VERSION


def workflow(ref=NEW, version=VERSION):
    return f"jobs:\n  audit:\n    steps:\n      - uses: getplumber/plumber@{ref}\n        with:\n          version: {version}\n"


def tag(sha=NEW, kind="commit"):
    return {"ref": "refs/tags/" + VERSION, "object": {"sha": sha, "type": kind}}


def test_aligned_release_and_original_mismatch():
    assert check_text(workflow(), lambda _: NEW) == 1
    with pytest.raises(AlignmentError):
        check_text(workflow(version="v0.6.0"), lambda _: OLD)


@pytest.mark.parametrize(
    "ref",
    ["v0.6.3", "latest", NEW[:7], NEW + "/path", "${{ inputs.sha }}", NEW + "x", "", "z" * 40],
)
def test_nonimmutable_action_refs(ref):
    with pytest.raises(AlignmentError):
        check_text(workflow(ref=ref), lambda _: NEW)


@pytest.mark.parametrize(
    "version",
    [
        "latest",
        "v0.6",
        "0.6.3",
        "v00.6.3",
        "v0.6.3-rc.1",
        "v0.6.3/path",
        "${{ inputs.version }}",
        "null",
    ],
)
def test_unverifiable_binary_tags(version):
    with pytest.raises(AlignmentError):
        check_text(workflow(version=version), lambda _: NEW)


def test_missing_version_and_action():
    with pytest.raises(AlignmentError):
        check_text(workflow().replace("version:", "other:"), lambda _: NEW)
    with pytest.raises(AlignmentError):
        check_text("jobs: {audit: {steps: []}}", lambda _: NEW)


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "jobs: []",
        "jobs: {audit: null}",
        "jobs: {audit: {steps: null}}",
        "jobs: {audit: {steps: [invalid]}}",
        "jobs: {audit: {steps: [{uses: []}]}}",
        workflow().replace("with:\n          version: v0.6.3", "with: null"),
        "jobs: {",
        "? [key, list]\n: value",
        workflow() + "jobs: {}\n",
        workflow().replace("version: v0.6.3", "version: v0.6.3\n          version: v0.6.0"),
    ],
)
def test_malformed_yaml_never_calls_network(text):
    def forbidden(_):
        pytest.fail("Malformed configuration must be rejected before network access")

    with pytest.raises(AlignmentError):
        check_text(text, forbidden)


def test_aliases_and_structure_limits():
    for text in [
        "a: &a [value]\nb: *a",
        "a: " + "[" * 33 + "0" + "]" * 33,
        "x: " + "a" * checker["MAX_BYTES"],
        "x: [" + "0," * 10_000 + "]",
    ]:
        with pytest.raises(AlignmentError):
            check_text(text, lambda _: NEW)


def test_multiple_steps_cache_and_sha_case():
    text = workflow(ref=NEW.upper()).replace("getplumber/plumber", "GetPlumber/Plumber")
    text += (
        "  second:\n    steps:\n      - uses: getplumber/plumber@"
        + NEW
        + "\n        with: {version: v0.6.3}\n"
    )
    calls = []

    def resolver(version):
        calls.append(version)
        return NEW.upper()

    assert check_text(text, resolver) == 2
    assert calls == [VERSION]


def test_lightweight_and_annotated_tags():
    assert resolve_release(VERSION, lambda _: tag()) == NEW
    objects = {
        ENDPOINT: tag(OLD, "tag"),
        API + "/git/tags/" + OLD: {"sha": OLD, "object": {"sha": NEW, "type": "commit"}},
    }
    assert resolve_release(VERSION, objects.__getitem__) == NEW


def test_moved_tag_and_tag_moving_during_resolution():
    with pytest.raises(AlignmentError):
        check_text(workflow(), lambda v: resolve_release(v, lambda _: tag(OLD)))
    responses = iter([tag(), tag(OLD)])
    with pytest.raises(Unavailable):
        resolve_release(VERSION, lambda _: next(responses))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {},
        {"ref": "wrong", "object": {}},
        {"ref": "refs/tags/" + VERSION, "object": []},
        tag("short"),
        tag(kind=[]),
        tag(kind="tree"),
    ],
)
def test_invalid_git_objects(payload):
    with pytest.raises(Unavailable):
        resolve_release(VERSION, lambda _: payload)


def test_tag_cycle_depth_and_identity():
    with pytest.raises(Unavailable):
        resolve_release(
            VERSION,
            lambda url: (
                tag(OLD, "tag")
                if url == ENDPOINT
                else {"sha": OLD, "object": {"sha": OLD, "type": "tag"}}
            ),
        )
    calls = []

    def deep(url):
        calls.append(url)
        if url == ENDPOINT:
            return tag("1" * 40, "tag")
        old = url.rsplit("/", 1)[1]
        return {"sha": old, "object": {"sha": str(len(calls)) * 40, "type": "tag"}}

    with pytest.raises(Unavailable):
        resolve_release(VERSION, deep)
    assert len(calls) == 5
    with pytest.raises(Unavailable):
        resolve_release(VERSION, lambda url: tag(OLD, "tag") if url == ENDPOINT else {"sha": None})


class FakeOpener:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response)


def test_network_headers_bounds_and_official_endpoints():
    opener = FakeOpener(json.dumps(tag()).encode())
    client = Client(token="synthetic-token", opener=opener, clock=lambda: 0)
    assert client.fetch(ENDPOINT) == tag()
    request, timeout = opener.calls[0]
    assert request.get_header("Authorization") == "Bearer synthetic-token"
    assert timeout == 6
    for endpoint in ["http://api.github.com", "https://evil.invalid/", ENDPOINT + "/extra"]:
        with pytest.raises(Unavailable):
            client.fetch(endpoint)
    assert len(opener.calls) == 1
    client.requests = checker["MAX_REQUESTS"]
    with pytest.raises(Unavailable):
        client.fetch(ENDPOINT)


@pytest.mark.parametrize(
    "response",
    [
        b"[",
        b"[]",
        b"null",
        b'{"object": null, "object": {}}',
        b"\xff",
        b"x" * (checker["MAX_BYTES"] + 1),
        OSError("synthetic-token"),
        urllib.error.HTTPError(ENDPOINT, 403, "synthetic-token", {}, None),
    ],
    ids=[
        "invalid-json",
        "array",
        "null",
        "duplicate-json-key",
        "invalid-utf8",
        "too-large",
        "network",
        "http403",
    ],
)
def test_network_failure_is_sanitized(response):
    with pytest.raises(Unavailable) as caught:
        Client(opener=FakeOpener(response)).fetch(ENDPOINT)
    assert "synthetic-token" not in str(caught.value)


def test_deadline_and_redirects():
    times = iter([0, 46])
    opener = FakeOpener(b"{}")
    with pytest.raises(Unavailable):
        Client(opener=opener, clock=lambda: next(times)).fetch(ENDPOINT)
    assert not opener.calls
    times = iter([0, 0, 0, 46])
    with pytest.raises(Unavailable):
        Client(opener=FakeOpener(b"{}"), clock=lambda: next(times)).fetch(ENDPOINT)
    with pytest.raises(Unavailable):
        checker["NoRedirect"]().redirect_request(
            None, None, 302, "redirect", {}, "https://evil.invalid"
        )


def test_cli_exit_codes_and_redaction(tmp_path, capsys):
    path = tmp_path / "workflow.yml"
    path.write_text(workflow(), encoding="utf-8")
    assert run([str(path)], lambda _: NEW) == 0
    assert run([str(path)], lambda _: OLD) == 1

    def unavailable(_):
        raise Unavailable("synthetic-token")

    assert run([str(path)], unavailable) == 2
    assert "synthetic-token" not in capsys.readouterr().err
    assert run([]) == 1
    assert run(["--help"]) == 0
    assert run([str(path), "extra"]) == 1
    assert run([str(path) + ".missing"]) == 1
    path.write_bytes(b"\xff")
    assert run([str(path)]) == 1
    path.write_bytes(b"a" * (checker["MAX_BYTES"] + 1))
    assert run([str(path)]) == 1
    assert "Traceback" not in capsys.readouterr().err


def test_resolver_must_return_a_commit():
    for result in [None, "short", []]:
        with pytest.raises(Unavailable):
            check_text(workflow(), lambda _, result=result: result)


def test_custom_yaml_tags_are_not_constructed():
    with pytest.raises(AlignmentError):
        check_text(
            workflow() + "extra: !!python/object/apply:builtins.str [input]\n", lambda _: NEW
        )


def test_exact_workflow_and_response_size_boundaries():
    text = workflow() + "#"
    text += "a" * (checker["MAX_BYTES"] - len(text.encode()))
    assert check_text(text, lambda _: NEW) == 1
    with pytest.raises(AlignmentError):
        check_text(text + "a", lambda _: NEW)
    payload = b"{}" + b" " * (checker["MAX_BYTES"] - 2)
    assert Client(opener=FakeOpener(payload)).fetch(ENDPOINT) == {}


def test_exact_depth_and_request_boundaries():
    assert check_text(workflow() + "extra: " + "[" * 31 + "0" + "]" * 31, lambda _: NEW) == 1
    with pytest.raises(AlignmentError):
        check_text(workflow() + "extra: " + "[" * 32 + "0" + "]" * 32, lambda _: NEW)
    client = Client(opener=FakeOpener(b"{}"))
    client.requests = checker["MAX_REQUESTS"] - 1
    assert client.fetch(ENDPOINT) == {}
    with pytest.raises(Unavailable):
        client.fetch(ENDPOINT)


def test_maximum_annotated_depth_is_supported():
    def fetch(url):
        if url == ENDPOINT:
            return tag("1" * 40, "tag")
        identity = url.rsplit("/", 1)[1]
        number = int(identity[0])
        return {
            "sha": identity,
            "object": {
                "sha": str(number + 1) * 40 if number < 4 else NEW,
                "type": "tag" if number < 4 else "commit",
            },
        }

    assert resolve_release(VERSION, fetch) == NEW


@pytest.mark.parametrize("status", [404, 429, 503])
def test_api_unavailability_is_never_success(status):
    with pytest.raises(Unavailable):
        Client(
            opener=FakeOpener(urllib.error.HTTPError(ENDPOINT, status, "synthetic-token", {}, None))
        ).fetch(ENDPOINT)
