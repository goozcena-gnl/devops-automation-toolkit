"""Synthetic only: no Ubuntu command, child process, DNS or provider call."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

MODULE_PATH = Path(__file__).resolve().parents[2] / "tools/sre_readonly_probe.py"
SPEC = importlib.util.spec_from_file_location("sre_readonly_probe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

SECRET = "SYNTHETIC_TOKEN_SUPER_PRIVATE_1234567890"
HEALTHY = b"LoadState=loaded\nActiveState=active\nSubState=mounted\nResult=success\nWhere=/mnt\nType=ext4\nExecMount={ code=exited ; status=0 }\n"


def provenance():
    return {
        "source_sha": "a" * 40,
        "baseline_sha": probe.BASELINE,
        "run_id": "123",
        "run_attempt": 1,
        "image_os": "ubuntu24",
        "image_version": "20261018.339.1",
        "architecture": "x64",
        "kernel_release": "7.0.0-1017-azure",
        "python_version": "3.12.14",
        "uid_nonroot": True,
        "event": "pull_request:opened",
        "comparability": "DIFFERENT_EPHEMERAL_RUNNER",
    }


def example(name):
    if name == "unit_show":
        return probe.Capture(stdout=HEALTHY, returncode=0)
    if name == "unit_status":
        return probe.Capture(stdout=b"Active: active (mounted)\n", returncode=0)
    if name in {"unit_journal", "kernel_journal"}:
        return probe.Capture(stdout=b'{"MESSAGE":"safe synthetic event"}\n', returncode=0)
    if name == "mount":
        return probe.Capture(
            stdout=b'{"filesystems":[{"target":"/mnt","fstype":"ext4"}]}', returncode=0
        )
    if name == "block":
        return probe.Capture(stdout=b'{"blockdevices":[{"mountpoints":["/mnt"]}]}', returncode=0)
    return probe.Capture(returncode=0)


def result_bundle():
    return probe.diagnose(
        provenance(),
        execute=lambda argv: example(
            next(name for name, command in probe.COMMANDS.items() if argv == command)
        ),
    )


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class FakeSession:
    def __init__(self, clock, frames=(), *, rc=0, infinite=False, idle=False, error=None):
        self.clock = clock
        self.frames = list(frames)
        self.rc = rc
        self.infinite = infinite
        self.idle = idle
        self.error = error
        self.finished = 0
        self.limits = []

    @property
    def open(self):
        return bool(self.frames) or self.infinite or self.idle

    def poll(self):
        return None if self.open else self.rc

    def read(self, timeout, limit):
        self.clock.value += timeout
        self.limits.append(limit)
        if self.error:
            raise self.error
        if self.infinite:
            return "stdout", b"x" * min(limit, 4096)
        if self.frames:
            return self.frames.pop(0)
        return None

    def finish(self):
        self.finished += 1
        return self.rc if self.poll() is not None else -9


class CaptureTests(unittest.TestCase):
    def run_fake(self, **kwargs):
        clock = Clock()
        session = FakeSession(clock, **kwargs)
        value = probe.capture(probe.COMMANDS["unit_show"], factory=lambda _: session, clock=clock)
        self.assertEqual(session.finished, 1)
        return value, session

    def test_stdout_stderr_separate_and_actual_exit_code(self):
        value, _ = self.run_fake(frames=[("stdout", b"out"), ("stderr", b"err")], rc=7)
        self.assertEqual((value.stdout, value.stderr, value.returncode), (b"out", b"err", 7))

    def test_negative_signal_code_preserved(self):
        value, _ = self.run_fake(rc=-15)
        self.assertEqual(value.returncode, -15)

    def test_timeout_not_inferred_from_text(self):
        value, _ = self.run_fake(frames=[("stderr", b"timeout example")], rc=3)
        self.assertIsNone(value.stop)
        self.assertEqual(value.returncode, 3)

    def test_idle_timeout_and_cleanup(self):
        value, _ = self.run_fake(idle=True)
        self.assertEqual((value.stop, value.returncode), ("TIMEOUT", -9))
        self.assertLessEqual(value.duration_ms, 5001)

    def test_infinite_output_strict_ceiling(self):
        value, session = self.run_fake(infinite=True)
        self.assertEqual(value.stop, "OUTPUT_LIMIT")
        self.assertEqual(len(value.stdout) + len(value.stderr), probe.MAX_BYTES)
        self.assertTrue(all(0 < limit <= probe.MAX_BYTES for limit in session.limits))

    def test_combined_stdout_stderr_ceiling(self):
        value, _ = self.run_fake(frames=[("stdout", b"a" * 32768), ("stderr", b"b" * 32768)])
        self.assertEqual(value.stop, "OUTPUT_LIMIT")
        self.assertEqual(len(value.stdout) + len(value.stderr), 65536)

    def test_transport_read_error_preserves_nonzero(self):
        value, _ = self.run_fake(idle=True, error=OSError(SECRET))
        self.assertEqual(value.stop, "TRANSPORT_INDETERMINATE")
        self.assertEqual(value.returncode, -9)

    def test_absent_command_without_process(self):
        with patch.object(probe, "PosixSession"):

            def absent(_):
                raise FileNotFoundError(SECRET)

            value = probe.capture(probe.COMMANDS["unit_show"], factory=absent)
        self.assertEqual(value.stop, "COMMAND_ABSENT")
        self.assertIsNone(value.returncode)

    def test_unapproved_command_never_spawns(self):
        factory = MagicMock()
        with self.assertRaises(probe.HarnessError):
            probe.capture(("/usr/bin/podman", "info"), factory=factory)
        factory.assert_not_called()

    def test_spawn_failure_is_indeterminate_not_success(self):
        def denied(_):
            raise PermissionError(SECRET)

        value = probe.capture(probe.COMMANDS["unit_show"], factory=denied)
        self.assertEqual(value.stop, "TRANSPORT_INDETERMINATE")
        self.assertIsNone(value.returncode)

    def test_interruption_always_cleans_up_group(self):
        clock = Clock()
        session = FakeSession(clock, idle=True, error=probe.HarnessError("INTERRUPTED"))
        with self.assertRaises(probe.HarnessError):
            probe.capture(probe.COMMANDS["unit_show"], factory=lambda _: session, clock=clock)
        self.assertEqual(session.finished, 1)

    def test_invalid_transport_and_cleanup(self):
        clock = Clock()
        session = FakeSession(clock, frames=[("stdout", b"x" * 65537)])
        with self.assertRaises(probe.HarnessError):
            probe.capture(probe.COMMANDS["unit_show"], factory=lambda _: session, clock=clock)
        self.assertEqual(session.finished, 1)

    def test_cleanup_failure_stops_supervisor(self):
        clock = Clock()
        session = FakeSession(clock)
        session.finish = MagicMock(side_effect=subprocess.TimeoutExpired("synthetic", 1))
        with self.assertRaisesRegex(probe.HarnessError, "^PROCESS_CLEANUP_FAILED$"):
            probe.capture(probe.COMMANDS["unit_show"], factory=lambda _: session, clock=clock)


class PosixBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.selector = MagicMock()
        self.process = MagicMock(pid=12345)
        self.process.stdout.fileno.return_value = 20
        self.process.stderr.fileno.return_value = 21
        self.process.wait.return_value = -9
        self.selector_patch = patch.object(
            probe.selectors, "DefaultSelector", return_value=self.selector
        )
        self.popen_patch = patch.object(probe.subprocess, "Popen", return_value=self.process)
        self.nonblock_patch = patch.object(probe.os, "set_blocking", create=True)
        self.kill_patch = patch.object(probe.os, "killpg", create=True)
        self.signal_patch = patch.object(probe.signal, "SIGKILL", 9, create=True)
        self.enterContext(self.signal_patch)
        self.enterContext(self.selector_patch)
        self.popen = self.enterContext(self.popen_patch)
        self.enterContext(self.nonblock_patch)
        self.kill = self.enterContext(self.kill_patch)

    def test_private_group_clean_environment_and_no_shell(self):
        session = probe.PosixSession(probe.COMMANDS["unit_show"])
        kwargs = self.popen.call_args.kwargs
        self.assertTrue(kwargs["start_new_session"])
        self.assertTrue(kwargs["close_fds"])
        self.assertEqual(kwargs["env"], probe.ENV)
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
        self.assertEqual(session.finish(), -9)
        self.kill.assert_called_once_with(12345, probe.signal.SIGKILL)
        self.process.wait.assert_called_once_with(timeout=1.0)
        self.process.stdout.close.assert_called_once()

    def test_private_session_also_rejects_unapproved_command(self):
        with self.assertRaises(probe.HarnessError):
            probe.PosixSession(("/usr/bin/podman", "info"))
        self.popen.assert_not_called()

    def test_descendant_group_killed_when_leader_already_exited(self):
        self.process.poll.return_value = 0
        session = probe.PosixSession(probe.COMMANDS["unit_show"])
        session.finish()
        self.kill.assert_called_once_with(12345, probe.signal.SIGKILL)

    def test_already_reaped_group_is_allowed(self):
        self.kill.side_effect = ProcessLookupError
        probe.PosixSession(probe.COMMANDS["unit_show"]).finish()
        self.process.wait.assert_called_once()

    def test_registration_failure_closes_process(self):
        self.selector.register.side_effect = RuntimeError(SECRET)
        with self.assertRaises(RuntimeError):
            probe.PosixSession(probe.COMMANDS["unit_show"])
        self.kill.assert_called_once()
        self.process.wait.assert_called_once()

    def test_read_is_bounded(self):
        session = probe.PosixSession(probe.COMMANDS["unit_show"])
        key = MagicMock(data="stderr")
        key.fileobj.fileno.return_value = 21
        self.selector.select.return_value = [(key, 1)]
        with patch.object(probe.os, "read", return_value=b"x") as read:
            self.assertEqual(session.read(0.05, 3), ("stderr", b"x"))
            read.assert_called_once_with(21, 3)
        session.finish()

    def test_eof_unregisters_pipe(self):
        session = probe.PosixSession(probe.COMMANDS["unit_show"])
        key = MagicMock(data="stdout")
        self.selector.select.return_value = [(key, 1)]
        with patch.object(probe.os, "read", return_value=b""):
            session.read(0.05, 5)
        self.selector.unregister.assert_called_once_with(key.fileobj)
        session.finish()


class PatchIsolationTests(unittest.TestCase):
    def test_absent_set_blocking_is_mocked_then_removed(self):
        original_popen = probe.subprocess.Popen
        original_selector = probe.selectors.DefaultSelector
        with patch.dict(probe.os.__dict__):
            probe.os.__dict__.pop("set_blocking", None)
            case = PosixBoundaryTests("test_read_is_bounded")
            result = unittest.TestResult()
            case.run(result)
            self.assertEqual(result.testsRun, 1)
            self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
            self.assertFalse(hasattr(probe.os, "set_blocking"))
            self.assertIs(probe.subprocess.Popen, original_popen)
            self.assertIs(probe.selectors.DefaultSelector, original_selector)

    def test_setup_failure_restores_every_started_patch(self):
        missing = object()
        targets = (
            (probe.signal, "SIGKILL"),
            (probe.selectors, "DefaultSelector"),
            (probe.subprocess, "Popen"),
            (probe.os, "set_blocking"),
            (probe.os, "killpg"),
        )
        for fail_after in range(1, len(targets) + 1):
            with self.subTest(fail_after=fail_after):
                originals = [getattr(obj, name, missing) for obj, name in targets]
                case = PosixBoundaryTests("test_read_is_bounded")
                enter_context = case.enterContext
                calls = 0

                def enter_then_fail(context, *, _enter=enter_context, _fail=fail_after):
                    nonlocal calls
                    value = _enter(context)
                    calls += 1
                    if calls == _fail:
                        raise RuntimeError("SYNTHETIC_SETUP_FAILURE")
                    return value

                result = unittest.TestResult()
                with patch.object(case, "enterContext", side_effect=enter_then_fail):
                    case.run(result)
                self.assertEqual(calls, fail_after)
                self.assertEqual(len(result.errors), 1)
                self.assertIn("SYNTHETIC_SETUP_FAILURE", result.errors[0][1])
                self.assertEqual(result.failures, [])
                for (obj, name), original in zip(targets, originals, strict=True):
                    self.assertIs(getattr(obj, name, missing), original)


class SummaryTests(unittest.TestCase):
    def test_mount_healthy(self):
        value = probe.summarize("unit_show", example("unit_show"))
        self.assertEqual(value["facts"]["ActiveState"], "active")
        self.assertEqual(value["facts"]["mount_exit_status"], 0)
        self.assertFalse(value["partial"])

    def test_mount_failed(self):
        value = probe.summarize(
            "unit_show",
            probe.Capture(
                stdout=HEALTHY.replace(b"active", b"failed")
                .replace(b"success", b"exit-code")
                .replace(b"status=0", b"status=32"),
                returncode=0,
            ),
        )
        self.assertEqual(value["category"], "UNIT_FAILED")
        self.assertEqual(value["facts"]["mount_exit_status"], 32)

    def test_mount_absent(self):
        value = probe.summarize(
            "unit_show",
            probe.Capture(stdout=HEALTHY.replace(b"loaded", b"not-found"), returncode=1),
        )
        self.assertEqual(value["category"], "UNIT_ABSENT")
        self.assertTrue(value["partial"])
        self.assertEqual(value["exit_code"], 1)

    def test_status_exit_three_is_not_masked(self):
        value = probe.summarize(
            "unit_status", probe.Capture(stdout=b"Active: failed", returncode=3)
        )
        self.assertEqual(value["exit_code"], 3)
        self.assertTrue(value["partial"])

    def test_journal_accessible(self):
        value = probe.summarize("unit_journal", example("unit_journal"))
        self.assertEqual(value["category"], "COLLECTED")
        self.assertEqual(value["facts"]["entries"], 1)

    def test_kernel_access_denied(self):
        value = probe.summarize(
            "kernel_dmesg",
            probe.Capture(
                stderr=b"dmesg: read kernel buffer failed: Operation not permitted", returncode=1
            ),
        )
        self.assertEqual(value["category"], "ACCESS_DENIED")
        self.assertEqual(value["exit_code"], 1)

    def test_journal_inaccessible(self):
        value = probe.summarize(
            "kernel_journal", probe.Capture(stderr=b"Permission denied", returncode=1)
        )
        self.assertEqual(value["category"], "ACCESS_DENIED")

    def test_journal_unavailable_even_with_zero_exit(self):
        value = probe.summarize(
            "unit_journal", probe.Capture(stderr=b"No journal files were found.", returncode=0)
        )
        self.assertEqual(value["category"], "JOURNAL_UNAVAILABLE")
        self.assertTrue(value["partial"])

    def test_journal_access_limited_zero_exit(self):
        value = probe.summarize(
            "kernel_journal",
            probe.Capture(
                stdout=b'{"MESSAGE":"synthetic"}', stderr=b"Permission denied", returncode=0
            ),
        )
        self.assertEqual(value["category"], "ACCESS_LIMITED")
        self.assertTrue(value["partial"])

    def test_empty_accessible_both_kernel_paths(self):
        for name in ("kernel_dmesg", "kernel_journal"):
            with self.subTest(name=name):
                value = probe.summarize(name, probe.Capture(returncode=0))
                self.assertEqual(value["category"], "EMPTY_ACCESSIBLE")
                self.assertFalse(value["partial"])

    def test_no_entries_sentinel(self):
        value = probe.summarize(
            "kernel_journal", probe.Capture(stdout=b"-- No entries --\n", returncode=0)
        )
        self.assertEqual(value["category"], "EMPTY_ACCESSIBLE")

    def test_stderr_does_not_become_clean(self):
        value = probe.summarize(
            "kernel_dmesg", probe.Capture(stderr=b"unknown warning", returncode=0)
        )
        self.assertEqual(value["category"], "STDERR_PRESENT")
        self.assertTrue(value["partial"])

    def test_malformed_utf8_is_partial(self):
        value = probe.summarize("unit_status", probe.Capture(stdout=b"\xff", returncode=0))
        self.assertEqual(value["category"], "MALFORMED")

    def test_invalid_json_is_partial(self):
        for name in ("mount", "block", "kernel_journal"):
            with self.subTest(name=name):
                value = probe.summarize(name, probe.Capture(stdout=b"not json", returncode=0))
                self.assertEqual(value["category"], "MALFORMED")

    def test_unknown_systemd_property_not_serialized(self):
        value = probe.summarize(
            "unit_show",
            probe.Capture(stdout=HEALTHY.replace(b"active", SECRET.encode()), returncode=0),
        )
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertTrue(value["partial"])

    def test_journal_secrets_and_identities_not_serialized(self):
        raw = json.dumps({"MESSAGE": SECRET, "_HOSTNAME": SECRET, "_CMDLINE": SECRET}).encode()
        value = probe.summarize("kernel_journal", probe.Capture(stdout=raw, returncode=0))
        self.assertNotIn(SECRET, json.dumps(value))

    def test_devices_paths_and_urls_not_serialized(self):
        raw = json.dumps(
            {
                "filesystems": [
                    {
                        "target": SECRET,
                        "source": "https://x.invalid/?key=" + SECRET,
                        "options": SECRET,
                        "fstype": SECRET,
                    }
                ]
            }
        ).encode()
        value = probe.summarize("mount", probe.Capture(stdout=raw, returncode=0))
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertNotIn("https", json.dumps(value))

    def test_truncation_timeout_and_transport_categories_remain_distinct(self):
        for stop in ("OUTPUT_LIMIT", "TIMEOUT", "TRANSPORT_INDETERMINATE"):
            with self.subTest(stop=stop):
                value = probe.summarize(
                    "unit_show", probe.Capture(stdout=b"not-complete", returncode=-9, stop=stop)
                )
                self.assertEqual(value["category"], stop)
                self.assertTrue(value["partial"])

    def test_nested_lsblk_and_mnt_presence(self):
        raw = b'{"blockdevices":[{"mountpoints":[],"children":[{"mountpoints":["/mnt"]}]}]}'
        value = probe.summarize("block", probe.Capture(stdout=raw, returncode=0))
        self.assertEqual(value["facts"], {"records": 2, "mnt_present": True})


class BundleTests(unittest.TestCase):
    def test_signal_handler_restores_previous_handler(self):
        previous = object()
        with patch.object(probe.signal, "signal", return_value=previous) as install:
            with probe.interruption_guard():
                callback = install.call_args.args[1]
                with self.assertRaisesRegex(probe.HarnessError, "^INTERRUPTED$"):
                    callback(15, None)
            self.assertEqual(install.call_args.args, (probe.signal.SIGTERM, previous))

    def test_podman_is_skipped_without_any_execution(self):
        execute = MagicMock(
            side_effect=lambda argv: example(
                next(k for k, v in probe.COMMANDS.items() if argv == v)
            )
        )
        result = probe.diagnose(provenance(), execute=execute)
        self.assertEqual(execute.call_count, 7)
        self.assertEqual(result["podman"]["status"], "SKIP")
        self.assertTrue(result["partial"])
        self.assertFalse(any("podman" in str(call) for call in execute.call_args_list))

    def test_launcher_exception_stops_before_remaining_commands(self):
        execute = MagicMock(side_effect=RuntimeError(SECRET))
        with self.assertRaises(RuntimeError):
            probe.diagnose(provenance(), execute=execute)
        self.assertEqual(execute.call_count, 1)

    def test_artifact_roundtrip_and_size(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "out"
            probe.write_bundle(directory, result_bundle(), provenance())
            probe.validate_bundle(directory)
            self.assertLessEqual(sum(p.stat().st_size for p in directory.iterdir()), 100 * 1024)
            self.assertEqual({p.name for p in directory.iterdir()}, set(probe.FILES))

    def test_secret_absent_from_all_artifacts(self):
        def execute(_):
            return probe.Capture(stdout=SECRET.encode(), stderr=SECRET.encode(), returncode=7)

        result = probe.diagnose(provenance(), execute=execute)
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "out"
            probe.write_bundle(directory, result, provenance())
            for path in directory.iterdir():
                self.assertNotIn(SECRET.encode(), path.read_bytes())

    def test_arbitrary_field_or_value_rejected_before_write(self):
        for mutate in (
            lambda r: r.update({"raw": SECRET}),
            lambda r: r["observations"][0]["facts"].update({"raw": SECRET}),
            lambda r: r["observations"][0].update({"category": SECRET}),
            lambda r: r["observations"][0]["facts"].update({"ActiveState": SECRET}),
        ):
            with self.subTest(mutate=mutate):
                result = result_bundle()
                mutate(result)
                with self.assertRaises(probe.HarnessError):
                    probe.validate_payloads(result, provenance())

    def test_existing_directory_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root, self.assertRaises(FileExistsError):
            probe.write_bundle(Path(root), result_bundle(), provenance())

    def test_extra_file_refuses_upload(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "out"
            probe.write_bundle(directory, result_bundle(), provenance())
            (directory / "raw.log").write_text(SECRET)
            with self.assertRaises(probe.HarnessError):
                probe.validate_bundle(directory)

    def test_modified_digest_refuses_upload(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "out"
            probe.write_bundle(directory, result_bundle(), provenance())
            (directory / "SHA256SUMS").write_text("invalid")
            with self.assertRaises(probe.HarnessError):
                probe.validate_bundle(directory)

    def test_oversized_artifact_refuses_upload(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "out"
            probe.write_bundle(directory, result_bundle(), provenance())
            (directory / "sre-result.json").write_bytes(b"x" * (probe.MAX_ARTIFACT + 1))
            with self.assertRaises(probe.HarnessError):
                probe.validate_bundle(directory)

    def test_main_never_prints_raw_exception(self):
        out, err = io.StringIO(), io.StringIO()
        with (
            patch.object(probe, "preflight", side_effect=RuntimeError(SECRET)),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            self.assertEqual(probe.main(["--collect"]), 70)
        self.assertNotIn(SECRET, out.getvalue() + err.getvalue())
        self.assertEqual(err.getvalue(), "SRE_LAUNCHER_FAILED_INCOMPLETE\n")

    def test_main_refuses_unknown_argument(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(probe.main(["--podman"]), 64)

    def test_main_reports_incomplete_not_pass(self):
        with (
            patch.object(probe, "preflight", return_value=provenance()),
            patch.object(probe, "diagnose", return_value=result_bundle()),
            patch.object(probe, "write_bundle") as write,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(probe.main(["--collect"]), 2)
            write.assert_called_once()


class PreflightTests(unittest.TestCase):
    def event(self):
        return {
            "action": "opened",
            "repository": {"full_name": probe.REPOSITORY},
            "pull_request": {
                "draft": True,
                "head": {
                    "sha": "a" * 40,
                    "ref": probe.BRANCH,
                    "repo": {"full_name": probe.REPOSITORY},
                },
                "base": {"sha": probe.BASELINE, "ref": "main"},
            },
        }

    def check(self, *, event=None, env=None, head=None, uid=1001, machine="x86_64"):
        environment = {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_EVENT_PATH": "event.json",
            "GITHUB_REPOSITORY": probe.REPOSITORY,
            "GITHUB_ACTOR": "goozcena-gnl",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "123",
            "ImageVersion": "20261018.339.1",
            "ImageOS": "ubuntu24",
        }
        environment.update(env or {})
        payload = json.dumps(self.event() if event is None else event).encode()

        def open_event(path, *_args, **_kwargs):
            if path.as_posix() == "/etc/os-release":
                return io.BytesIO(b'ID=ubuntu\nVERSION_ID="24.04"\n')
            return io.BytesIO(payload)

        with (
            patch.object(probe.sys, "platform", "linux"),
            patch.object(probe.platform, "machine", return_value=machine),
            patch.object(probe.platform, "release", return_value="7.0.0-1017-azure"),
            patch.object(probe.os, "getuid", return_value=uid, create=True),
            patch.dict(os.environ, environment, clear=True),
            patch.object(Path, "read_bytes", return_value=b'ID=ubuntu\nVERSION_ID="24.04"\n'),
            patch.object(Path, "read_text", return_value=head or "a" * 40),
            patch.object(Path, "open", open_event),
        ):
            return probe.preflight()

    def test_expected_target_and_sha(self):
        self.assertEqual(self.check()["source_sha"], "a" * 40)

    def test_rerun_denied(self):
        with self.assertRaises(probe.HarnessError):
            self.check(env={"GITHUB_RUN_ATTEMPT": "2"})

    def test_root_denied(self):
        with self.assertRaises(probe.HarnessError):
            self.check(uid=0)

    def test_wrong_architecture_denied(self):
        with self.assertRaises(probe.HarnessError):
            self.check(machine="aarch64")

    def test_changed_baseline_denied(self):
        event = self.event()
        event["pull_request"]["base"]["sha"] = "b" * 40
        with self.assertRaises(probe.HarnessError):
            self.check(event=event)

    def test_wrong_checkout_denied(self):
        with self.assertRaises(probe.HarnessError):
            self.check(head="b" * 40)

    def test_non_open_events_denied(self):
        for action in ("synchronize", "reopened", "ready_for_review", "edited"):
            event = self.event()
            event["action"] = action
            with self.subTest(action=action), self.assertRaises(probe.HarnessError):
                self.check(event=event)

    def test_fork_denied(self):
        event = self.event()
        event["pull_request"]["head"]["repo"]["full_name"] = "other/repo"
        with self.assertRaises(probe.HarnessError):
            self.check(event=event)

    def test_non_draft_denied(self):
        event = self.event()
        event["pull_request"]["draft"] = False
        with self.assertRaises(probe.HarnessError):
            self.check(event=event)

    def test_unknown_image_denied(self):
        with self.assertRaises(probe.HarnessError):
            self.check(env={"ImageVersion": SECRET})

    def test_wrong_branch_denied(self):
        event = self.event()
        event["pull_request"]["head"]["ref"] = "unapproved"
        with self.assertRaises(probe.HarnessError):
            self.check(event=event)


if __name__ == "__main__":
    unittest.main()
