"""One-shot, sanitized Ubuntu evidence; no remediation or Podman execution.

The subprocess boundary bounds time and bytes; it is not an OS write sandbox.
Only fixed read commands are eligible. Raw output never leaves process memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import selectors
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

BASELINE = "93cfc5a6c8c23135376e223fb7b5d43cee0f8d0b"
REPOSITORY = "goozcena-gnl/devops-automation-toolkit"
BRANCH = "codex/sre-ubuntu-diagnostic"
MAX_BYTES = 65_536
MAX_ARTIFACT = 100 * 1024
MAX_PAYLOAD = 96 * 1024  # Leave ZIP framing/compression overhead below the 100 KiB ceiling.
TIMEOUT = 5.0
CLEANUP_TIMEOUT = 1.0
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": "/nonexistent"}
PROPERTIES = "LoadState,ActiveState,SubState,Result,Where,Type,ExecMount"
COMMANDS = {
    "unit_show": (
        "/usr/bin/systemctl",
        "show",
        "mnt.mount",
        "--no-pager",
        "--property=" + PROPERTIES,
    ),
    "unit_status": ("/usr/bin/systemctl", "status", "mnt.mount", "--no-pager", "--lines=40"),
    "unit_journal": (
        "/usr/bin/journalctl",
        "-b",
        "-u",
        "mnt.mount",
        "--no-pager",
        "--lines=100",
        "--output=json",
    ),
    "mount": (
        "/usr/bin/findmnt",
        "--target",
        "/mnt",
        "--json",
        "--output",
        "TARGET,FSTYPE,OPTIONS",
    ),
    "block": ("/usr/bin/lsblk", "--json", "--output", "TYPE,FSTYPE,MOUNTPOINTS"),
    "kernel_dmesg": ("/usr/bin/dmesg", "--level=err,warn", "--color=never"),
    "kernel_journal": (
        "/usr/bin/journalctl",
        "-k",
        "-b",
        "--no-pager",
        "--lines=200",
        "--output=json",
    ),
}
FILES = ("sre-result.json", "run-provenance.json", "SHA256SUMS")
CATEGORIES = {
    "COLLECTED",
    "EMPTY_ACCESSIBLE",
    "ACCESS_DENIED",
    "ACCESS_LIMITED",
    "STDERR_PRESENT",
    "JOURNAL_UNAVAILABLE",
    "COMMAND_FAILED",
    "COMMAND_ABSENT",
    "TIMEOUT",
    "OUTPUT_LIMIT",
    "TRANSPORT_INDETERMINATE",
    "MALFORMED",
    "UNIT_FAILED",
    "UNIT_ABSENT",
}
ENUMS = {
    "LoadState": {"loaded", "not-found", "masked", "error", "bad-setting", "stub", "merged"},
    "ActiveState": {"active", "inactive", "failed", "activating", "deactivating", "maintenance"},
    "SubState": {
        "mounted",
        "dead",
        "failed",
        "mounting",
        "unmounting",
        "remounting",
        "mounting-done",
        "cleaning",
    },
    "Result": {
        "success",
        "exit-code",
        "signal",
        "timeout",
        "resources",
        "dependency",
        "start-limit-hit",
        "assert",
        "protocol",
        "core-dump",
    },
    "Type": {"", "ext4", "xfs", "btrfs", "tmpfs", "none", "auto", "fuse", "overlay"},
}
MARKERS = {
    "permission_denied": ("permission denied", "operation not permitted", "access denied"),
    "mount_failed": ("failed to mount", "mount process exited"),
    "dependency_failed": ("dependency failed",),
    "missing_mountpoint": ("mount point does not exist", "mountpoint does not exist"),
    "filesystem_error": ("wrong fs type", "unknown filesystem", "bad superblock"),
    "io_error": ("i/o error", "buffer i/o", "blk_update_request"),
    "oom": ("out of memory", "oom-kill"),
    "no_space": ("no space left",),
}


class HarnessError(Exception):
    """Fixed public diagnostic only; never attach provider exception text."""


@contextmanager
def interruption_guard():
    def stop(_signum, _frame):
        raise HarnessError("INTERRUPTED")

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@dataclass
class Capture:
    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int | None = None
    duration_ms: int = 0
    stop: str | None = None


class PosixSession:
    """Private process group, nonblocking multiplexed capture and bounded cleanup."""

    def __init__(self, argv: tuple[str, ...]):
        if argv not in COMMANDS.values():
            raise HarnessError("COMMAND_OUT_OF_POLICY")
        self.selector = selectors.DefaultSelector()
        try:
            self.process = subprocess.Popen(  # noqa: S603 -- exact fixed argv allowlist above.
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=ENV.copy(),
                cwd="/",
                close_fds=True,
                start_new_session=True,
            )
        except BaseException:
            self.selector.close()
            raise
        try:
            for name in ("stdout", "stderr"):
                pipe = getattr(self.process, name)
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, name)
        except BaseException:
            self.finish()
            raise

    @property
    def open(self) -> bool:
        return bool(self.selector.get_map())

    def poll(self) -> int | None:
        return self.process.poll()

    def read(self, timeout: float, limit: int) -> tuple[str, bytes] | None:
        events = self.selector.select(timeout)
        if not events:
            return None
        key = events[0][0]
        data = os.read(key.fileobj.fileno(), min(8192, limit))
        if not data:
            self.selector.unregister(key.fileobj)
        return key.data, data

    def finish(self) -> int:
        # The group belongs to this Popen(start_new_session=True), never to a service.
        # Kill descendants even if the group leader already exited.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            self.selector.close()
            for name in ("stdout", "stderr"):
                pipe = getattr(self.process, name)
                if pipe is not None:
                    pipe.close()
        return self.process.wait(timeout=CLEANUP_TIMEOUT)


def capture(argv: tuple[str, ...], *, factory=PosixSession, clock=time.monotonic) -> Capture:
    if argv not in COMMANDS.values():
        raise HarnessError("COMMAND_OUT_OF_POLICY")
    started = clock()
    session = None
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    result = Capture()
    try:
        session = factory(argv)
        while session.open or session.poll() is None:
            remaining = TIMEOUT - (clock() - started)
            if remaining <= 0:
                result.stop = "TIMEOUT"
                break
            size = sum(len(v) for v in streams.values())
            item = session.read(min(0.05, remaining), MAX_BYTES - size)
            if item is not None:
                name, data = item
                if name not in streams or len(data) > MAX_BYTES - size:
                    raise HarnessError("INVALID_TRANSPORT")
                streams[name].extend(data)
                if sum(len(v) for v in streams.values()) >= MAX_BYTES:
                    result.stop = "OUTPUT_LIMIT"
                    break
        result.returncode = session.poll()
    except FileNotFoundError:
        result.stop = "COMMAND_ABSENT" if session is None else "TRANSPORT_INDETERMINATE"
    except OSError:
        result.stop = "TRANSPORT_INDETERMINATE"
    finally:
        if session is not None:
            try:
                stopped_code = session.finish()
            except Exception:
                raise HarnessError("PROCESS_CLEANUP_FAILED") from None
            if result.returncode is None:
                result.returncode = stopped_code
        result.duration_ms = max(0, int((clock() - started) * 1000))
    result.stdout, result.stderr = bytes(streams["stdout"]), bytes(streams["stderr"])
    return result


def summarize(name: str, result: Capture) -> dict:
    """Allowlisted enums, integers and boolean indicators only; no raw string survives."""
    facts = {}
    category = result.stop or "COLLECTED"
    partial = result.stop is not None
    try:
        out = result.stdout.decode("utf-8", errors="strict")
        err = result.stderr.decode("utf-8", errors="strict")
    except UnicodeError:
        out, err = "", ""
        if result.stop is None:
            category = "MALFORMED"
        partial = True
    lowered = (out + "\n" + err).lower()
    denied = any(marker in lowered for marker in MARKERS["permission_denied"])
    journal_unavailable = any(
        x in lowered
        for x in (
            "no journal files were found",
            "failed to open journal",
            "journal is not available",
        )
    )
    if result.stop is None and category != "MALFORMED":
        if result.returncode != 0:
            category = (
                "ACCESS_DENIED"
                if denied
                else "JOURNAL_UNAVAILABLE"
                if journal_unavailable
                else "COMMAND_FAILED"
            )
            partial = True
        elif denied:
            category, partial = "ACCESS_LIMITED", True
        elif journal_unavailable:
            category, partial = "JOURNAL_UNAVAILABLE", True
        elif err:
            category, partial = "STDERR_PRESENT", True
        elif not out.strip() or out.strip() == "-- No entries --":
            category = "EMPTY_ACCESSIBLE"
    if result.stop is None and out and category != "MALFORMED":
        try:
            if name == "unit_show":
                props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
                for key, allowed in ENUMS.items():
                    value = props.get(key)
                    facts[key] = value if value in allowed else "UNRECOGNIZED"
                    if value not in allowed:
                        partial = True
                facts["where_is_mnt"] = props.get("Where") == "/mnt"
                exec_mount = props.get("ExecMount", "")
                status = re.search(r"\bstatus=(\d{1,3})\b", exec_mount)
                facts["mount_exit_status"] = int(status[1]) if status else None
                if props.get("LoadState") == "not-found":
                    category, partial = "UNIT_ABSENT", True
                elif props.get("ActiveState") == "failed" and category == "COLLECTED":
                    category = "UNIT_FAILED"
            elif name in {"unit_journal", "kernel_journal"} and out.strip() != "-- No entries --":
                rows = [json.loads(line) for line in out.splitlines() if line.strip()]
                if len(rows) > 200 or any(not isinstance(row, dict) for row in rows):
                    raise ValueError
                facts["entries"] = len(rows)
                # MESSAGE is examined in memory; never retain it, even if malformed.
                messages = [row.get("MESSAGE", "") for row in rows]
                if any(not isinstance(msg, str) for msg in messages):
                    raise ValueError
                text = "\n".join(messages).lower()
                facts.update(
                    {
                        key: sum(any(m in msg.lower() for m in markers) for msg in messages)
                        for key, markers in MARKERS.items()
                    }
                )
                del text
            elif name in {"mount", "block"}:
                data = json.loads(out)
                rows = data["filesystems" if name == "mount" else "blockdevices"]
                if not isinstance(rows, list) or len(rows) > 256:
                    raise ValueError
                # Do not serialize names, labels, UUIDs, paths, options or device identities.
                stack, seen, mnt = list(rows), 0, False
                while stack:
                    row = stack.pop()
                    if not isinstance(row, dict):
                        raise ValueError
                    seen += 1
                    if seen > 256:
                        raise ValueError
                    mnt |= row.get("target") == "/mnt" or "/mnt" in (row.get("mountpoints") or [])
                    children = row.get("children", [])
                    if not isinstance(children, list):
                        raise ValueError
                    stack.extend(children)
                facts.update({"records": seen, "mnt_present": mnt})
            elif name in {"unit_status", "kernel_dmesg"}:
                facts["lines"] = len(out.splitlines())
                facts.update({key: lowered.count(markers[0]) for key, markers in MARKERS.items()})
        except (ValueError, TypeError, KeyError, RecursionError):
            facts = {}
            category, partial = "MALFORMED", True
    if any(v == "UNRECOGNIZED" for v in facts.values()) and category == "COLLECTED":
        category = "MALFORMED"
    return {
        "id": name,
        "argv": list(COMMANDS[name]),
        "exit_code": result.returncode,
        "duration_ms": result.duration_ms,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "category": category,
        "partial": partial,
        "facts": facts,
    }


def diagnose(provenance: dict, *, execute=capture) -> dict:
    # Unexpected launcher errors propagate: no remaining command, retry or correction.
    observations = [summarize(name, execute(argv)) for name, argv in COMMANDS.items()]
    return {
        "diagnostic_schema": "sre-experiment-1",
        "source_sha": provenance["source_sha"],
        "evidence_status": "INCOMPLETE",
        "partial": True,
        "historical_cause": "NOT_ESTABLISHED",
        "observations": observations,
        "podman": {
            "status": "SKIP",
            "evidence_status": "INCOMPLETE",
            "reason": "CONFINEMENT_NOT_PROVEN",
            "exit_code": None,
            "duration_ms": None,
        },
    }


def preflight() -> dict:
    # No subprocess or provider access in preflight.
    if sys.platform != "linux" or platform.machine() != "x86_64" or os.getuid() == 0:
        raise HarnessError("TARGET_NOT_ELIGIBLE")
    with Path("/etc/os-release").open("rb") as stream:
        release = stream.read(8193)
    if len(release) > 8192:
        raise HarnessError("OS_METADATA_INVALID")
    fields = dict(line.split("=", 1) for line in release.decode().splitlines() if "=" in line)
    if (
        fields.get("ID", "").strip('"') != "ubuntu"
        or fields.get("VERSION_ID", "").strip('"') != "24.04"
    ):
        raise HarnessError("TARGET_NOT_ELIGIBLE")
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise HarnessError("EVENT_NOT_ELIGIBLE")
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    with event_path.open("rb") as stream:
        event_bytes = stream.read(65_537)
    if len(event_bytes) > 65_536:
        raise HarnessError("EVENT_TOO_LARGE")
    event = json.loads(event_bytes)
    pr = event["pull_request"]
    sha = pr["head"]["sha"]
    if not (
        event["action"] == "opened"
        and pr["draft"] is True
        and pr["head"]["repo"]["full_name"] == REPOSITORY
        and pr["head"]["ref"] == BRANCH
        and pr["base"]["ref"] == "main"
        and pr["base"]["sha"] == BASELINE
        and event["repository"]["full_name"] == REPOSITORY
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_ACTOR") == "goozcena-gnl"
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and re.fullmatch(r"[0-9a-f]{40}", sha)
    ):
        raise HarnessError("EVENT_NOT_ELIGIBLE")
    # checkout is intentionally shallow. Read .git/HEAD and its local ref, never invoke git.
    head = Path(".git/HEAD").read_text(encoding="ascii").strip()
    if head != sha:  # Require detached checkout, reject symbolic refs and worktree indirection.
        raise HarnessError("CHECKOUT_SHA_MISMATCH")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    image = os.environ.get("ImageVersion", "")  # noqa: SIM112 -- official runner variable spelling.
    kernel = platform.release()
    if not (
        run_id.isascii()
        and run_id.isdigit()
        and len(run_id) <= 20
        and os.environ.get("ImageOS") == "ubuntu24"  # noqa: SIM112 -- official runner variable.
        and re.fullmatch(r"\d{8}\.\d{1,5}\.\d{1,3}", image)
        and re.fullmatch(r"\d+\.\d+\.\d+-\d+-azure", kernel)
    ):
        raise HarnessError("PROVENANCE_NOT_RECOGNIZED")
    return {
        "source_sha": sha,
        "baseline_sha": BASELINE,
        "run_id": run_id,
        "run_attempt": 1,
        "image_os": "ubuntu24",
        "image_version": image,
        "architecture": "x64",
        "kernel_release": kernel,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "uid_nonroot": True,
        "event": "pull_request:opened",
        "comparability": "DIFFERENT_EPHEMERAL_RUNNER",
    }


def encoded(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def validate_payloads(result: dict, provenance: dict) -> None:
    expected_provenance = {
        "source_sha",
        "baseline_sha",
        "run_id",
        "run_attempt",
        "image_os",
        "image_version",
        "architecture",
        "kernel_release",
        "python_version",
        "uid_nonroot",
        "event",
        "comparability",
    }
    if set(provenance) != expected_provenance or not (
        re.fullmatch(r"[0-9a-f]{40}", provenance["source_sha"])
        and provenance["baseline_sha"] == BASELINE
        and provenance["run_attempt"] == 1
        and re.fullmatch(r"[0-9]{1,20}", provenance["run_id"])
        and provenance["image_os"] == "ubuntu24"
        and provenance["architecture"] == "x64"
        and re.fullmatch(r"\d{8}\.\d{1,5}\.\d{1,3}", provenance["image_version"])
        and re.fullmatch(r"\d+\.\d+\.\d+-\d+-azure", provenance["kernel_release"])
        and re.fullmatch(r"3\.\d{1,2}\.\d{1,3}", provenance["python_version"])
        and provenance["uid_nonroot"] is True
        and provenance["event"] == "pull_request:opened"
        and provenance["comparability"] == "DIFFERENT_EPHEMERAL_RUNNER"
    ):
        raise HarnessError("PROVENANCE_INVALID")
    expected_result = {
        "diagnostic_schema",
        "source_sha",
        "evidence_status",
        "partial",
        "historical_cause",
        "observations",
        "podman",
    }
    if set(result) != expected_result or not (
        result["diagnostic_schema"] == "sre-experiment-1"
        and result["source_sha"] == provenance["source_sha"]
        and result["evidence_status"] == "INCOMPLETE"
        and result["partial"] is True
        and result["historical_cause"] == "NOT_ESTABLISHED"
        and result["podman"]
        == {
            "status": "SKIP",
            "evidence_status": "INCOMPLETE",
            "reason": "CONFINEMENT_NOT_PROVEN",
            "exit_code": None,
            "duration_ms": None,
        }
    ):
        raise HarnessError("RESULT_INVALID")
    observations = result["observations"]
    if len(observations) != len(COMMANDS):
        raise HarnessError("RESULT_INVALID")
    fact_keys = (
        set(ENUMS)
        | set(MARKERS)
        | {"where_is_mnt", "mount_exit_status", "entries", "records", "mnt_present", "lines"}
    )
    for name, obs in zip(COMMANDS, observations, strict=True):
        if set(obs) != {
            "id",
            "argv",
            "exit_code",
            "duration_ms",
            "stdout_bytes",
            "stderr_bytes",
            "category",
            "partial",
            "facts",
        } or not (
            obs["id"] == name
            and obs["argv"] == list(COMMANDS[name])
            and obs["category"] in CATEGORIES
            and type(obs["partial"]) is bool
            and (obs["exit_code"] is None or type(obs["exit_code"]) is int)
            and type(obs["duration_ms"]) is int
            and 0 <= obs["duration_ms"] <= 30_000
            and all(type(obs[k]) is int and obs[k] >= 0 for k in ("stdout_bytes", "stderr_bytes"))
            and obs["stdout_bytes"] + obs["stderr_bytes"] <= MAX_BYTES
            and isinstance(obs["facts"], dict)
            and set(obs["facts"]) <= fact_keys
        ):
            raise HarnessError("OBSERVATION_INVALID")
        for key, value in obs["facts"].items():
            if key in ENUMS:
                if value not in ENUMS[key] | {"UNRECOGNIZED"}:
                    raise HarnessError("FACT_INVALID")
            elif value is not None and not (
                type(value) is bool or (type(value) is int and 0 <= value <= MAX_BYTES)
            ):
                raise HarnessError("FACT_INVALID")


def write_bundle(directory: Path, result: dict, provenance: dict) -> None:
    validate_payloads(result, provenance)
    payloads = {"sre-result.json": encoded(result), "run-provenance.json": encoded(provenance)}
    payloads["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(body).hexdigest()}  {name}\n" for name, body in payloads.items()
    ).encode("ascii")
    if sum(map(len, payloads.values())) > MAX_PAYLOAD:
        raise HarnessError("ARTIFACT_LIMIT")
    directory.mkdir(mode=0o700, exist_ok=False)
    for name, body in payloads.items():
        with (directory / name).open("xb") as stream:
            stream.write(body)


def validate_bundle(directory: Path) -> None:
    if directory.is_symlink() or {p.name for p in directory.iterdir()} != set(FILES):
        raise HarnessError("ARTIFACT_INVALID")
    blobs = {}
    for name in FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT:
            raise HarnessError("ARTIFACT_INVALID")
        with path.open("rb") as stream:
            blobs[name] = stream.read(MAX_ARTIFACT + 1)
    if sum(map(len, blobs.values())) > MAX_PAYLOAD:
        raise HarnessError("ARTIFACT_LIMIT")
    validate_payloads(
        json.loads(blobs["sre-result.json"]), json.loads(blobs["run-provenance.json"])
    )
    expected = "".join(f"{hashlib.sha256(blobs[n]).hexdigest()}  {n}\n" for n in FILES[:2])
    if blobs["SHA256SUMS"] != expected.encode("ascii"):
        raise HarnessError("DIGEST_MISMATCH")


def main(args=None) -> int:
    args = sys.argv[1:] if args is None else args
    output = Path("sre-diagnostic-output")
    try:
        if args == ["--collect"]:
            with interruption_guard():
                provenance = preflight()
                result = diagnose(provenance)
                write_bundle(output, result, provenance)
            print("SRE_DIAGNOSTIC_INCOMPLETE")
            return 2  # Intentional: Podman was not measured; no green health inference.
        if args == ["--validate-artifacts"]:
            validate_bundle(output)
            print("SRE_ARTIFACTS_VALIDATED")
            return 0
    except Exception:
        # No exception interpolation, traceback, raw outputs or environment serialization.
        print("SRE_LAUNCHER_FAILED_INCOMPLETE", file=sys.stderr)
        return 70
    print("SRE_ARGUMENTS_REJECTED", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
