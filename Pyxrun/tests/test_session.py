# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Session lifecycle tests using stand-in executables, with no physical hardware.

XTC Tools and XSI are still required when importing the packages under test.
"""
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from Pyxrun import Session, SessionError, SessionTimeout
from Pyxrun import run

pytestmark = pytest.mark.skipif(os.name == "nt", reason="stand-in tools are POSIX scripts")

XRUN = r'''
import os, signal, subprocess, sys, time
mode = os.environ.get("FAKE_XRUN", "exit0")
Path = __import__("pathlib").Path
Path(os.environ["FAKE_DIR"], "xrun.args").write_text("\n".join(sys.argv[1:]))
Path(os.environ["FAKE_DIR"], "xrun.pid").write_text(str(os.getpid()))
if mode == "exit0":
    print("hello"); print("PASS")
elif mode == "exit7":
    print("hello"); print("launcher failed", file=sys.stderr); sys.exit(7)
elif mode == "flood":
    sys.stdout.write("x" * 79 + "\n" and ("x" * 79 + "\n") * 52000); print("PASS")
elif mode == "serve":
    print("ready", flush=True); print("RESULT 42", flush=True); time.sleep(600)
elif mode == "silent":
    time.sleep(600)
elif mode == "stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready", flush=True); time.sleep(600)
elif mode in ("child", "stubborn_child"):
    code = "import time; time.sleep(600)"
    if mode == "stubborn_child":
        code = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"
    child = subprocess.Popen([sys.executable, "-c", code])
    Path(os.environ["FAKE_DIR"], "child.pid").write_text(str(child.pid))
    print("ready", flush=True); time.sleep(600)
elif mode == "exception":
    print("xrun: Application exception", file=sys.stderr); sys.exit(255)
elif mode == "partial":
    sys.stdout.write("no newline"); sys.stderr.write("line\r\n")
elif mode == "cwd":
    print(os.getcwd())
elif mode == "noise":
    while True:
        print("running", flush=True); time.sleep(0.001)
elif mode == "noisy_tail":
    def stop(*args):
        print("shutdown diagnostic", flush=True); sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    print("ready\nPASS\nafter completion", flush=True); time.sleep(600)
elif mode == "stderr_marker":
    print("PASS", file=sys.stderr, flush=True); time.sleep(600)
elif mode == "late_exception":
    def stop(*args):
        print("Application exception", file=sys.stderr, flush=True); sys.exit(255)
    signal.signal(signal.SIGTERM, stop)
    print("PASS", flush=True); time.sleep(600)
elif mode == "progress":
    print("ready", flush=True); time.sleep(0.1)
    print("progress", flush=True); time.sleep(600)
elif mode == "closed_pipes":
    os.close(1); os.close(2); time.sleep(600)
'''

XGDB = r'''
import os, sys, time
Path = __import__("pathlib").Path
with Path(os.environ["FAKE_DIR"], "xgdb.calls").open("a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
mode = os.environ.get("FAKE_XGDB", "ok")
if mode == "fail":
    print("cannot connect", file=sys.stderr); sys.exit(1)
if mode == "hang":
    time.sleep(600)
'''


@pytest.fixture
def tools(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("xrun", XRUN), ("xflash", XRUN), ("xgdb", XGDB)):
        script = bin_dir / name
        script.write_text(f"#!{sys.executable}\n{body}")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_DIR", str(tmp_path))
    monkeypatch.setattr(Session, "stop_grace", 1)
    xe = tmp_path / "app.xe"
    xe.write_bytes(b"XE")

    class Tools:
        path = tmp_path

        def app(self, mode="exit0", attach="xscope", **options):
            monkeypatch.setenv("FAKE_XRUN", mode)
            return Session(xe, "SERIAL", attach=attach, **options)

        def args(self):
            return (tmp_path / "xrun.args").read_text().splitlines()

        def xgdb_calls(self):
            calls = tmp_path / "xgdb.calls"
            return calls.read_text().splitlines() if calls.exists() else []

        def alive(self, name="xrun"):
            try:
                os.kill(int((tmp_path / f"{name}.pid").read_text()), 0)
            except ProcessLookupError:
                return False
            return True

    return Tools()


def gone(tools, name="xrun"):
    deadline = time.monotonic() + 5
    while tools.alive(name) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not tools.alive(name)


# ---- Existing behaviour ------------------------------------------------------------------

def test_unattached_run_and_recovery(tools):
    """An unattached run captures output and reconnects to the selected adapter."""
    with tools.app(attach=None) as app:
        assert app.proc is None and "PASS" in app.proc_stdout
    assert tools.args() == ["--adapter-id", "SERIAL", str(app.xe_path)]
    assert tools.xgdb_calls() == ["-ex connect --adapter-id SERIAL --batch"]


def test_unattached_failure_is_reported(tools):
    """An unattached launch failure still stops helpers and recovers the target."""
    with pytest.raises(AssertionError, match="xrun failed"):
        with tools.app("exit7", attach=None):
            pass
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_unattached_timeout_stops_helpers_and_recovers_target(tools):
    """A timed-out unattached run stops launcher descendants before recovery."""
    # Allow cold interpreter/script startup before requiring a helper to exist.
    with pytest.raises(subprocess.TimeoutExpired) as failure:
        with tools.app("child", attach=None, timeout=2):
            pass
    assert "ready" in failure.value.stdout
    assert gone(tools) and gone(tools, "child")
    assert len(tools.xgdb_calls()) == 1


def test_unattached_startup_error_survives_failed_recovery(tools, monkeypatch):
    """Recovery failure does not replace the original unattached startup failure."""
    monkeypatch.setenv("FAKE_XGDB", "fail")
    with pytest.raises(AssertionError, match="xrun failed") as failure:
        tools.app("exit7", attach=None).__enter__()
    assert gone(tools) and len(tools.xgdb_calls()) == 1
    if hasattr(failure.value, "__notes__"):
        assert "Connecting to XTAG SERIAL failed" in failure.value.__notes__[0]


def test_xflash_commands(tools):
    """Factory and write-all flashing construct the expected adapter and target flags."""
    with tools.app(attach=None, xflash=True):
        pass
    assert tools.args() == ["--adapter-id", "SERIAL", "--factory", str(tools.path / "app.xe")]
    with tools.app(attach=None, xflash=True, writeall=True, target="XK-EVK-XU316"):
        pass
    assert tools.args()[2:] == ["--write-all", str(tools.path / "app.xe"), "--target", "XK-EVK-XU316"]


@pytest.mark.parametrize("attach, flags", [("io", ["--io"]), ("xscope", ["--xscope"])])
def test_attach_commands_and_terminated_app_passes(tools, attach, flags):
    """Both I/O attachment modes treat an intentional stop as successful cleanup."""
    with tools.app("serve", attach=attach) as app:
        app.wait_for_output("ready")
    assert tools.args() == ["--adapter-id", "SERIAL", *flags, str(app.xe_path)]
    assert gone(tools)
    assert "RESULT 42" in app.proc_stdout and app.proc_stderr == ""
    assert app.proc_returncode != 0  # Stopped here, so the status is not an error.
    assert len(tools.xgdb_calls()) == 1


def test_xscope_io_only_flag(tools):
    """The I/O-only flag is passed for xSCOPE and rejected for JTAG attachment."""
    with tools.app(xscope_io_only=True) as app:
        app.wait()
    assert tools.args()[2:4] == ["--xscope", "--xscope-io-only"]
    with pytest.raises(AssertionError):
        tools.app(attach="io", xscope_io_only=True)


def test_application_arguments_follow_the_args_flag(tools):
    """Run arguments follow --args and the XE, and cannot be passed to xflash."""
    with tools.app(appargs=["12345", 6]) as app:
        app.wait()
    assert tools.args() == ["--adapter-id", "SERIAL", "--xscope", "--args", str(app.xe_path), "12345", "6"]
    with tools.app(attach=None, appargs=["x"]) as app:
        pass
    assert tools.args() == ["--adapter-id", "SERIAL", "--args", str(app.xe_path), "x"]
    with pytest.raises(AssertionError):
        tools.app(attach=None, xflash=True, appargs=["x"])


def test_target_exception_is_reported(tools):
    """An application exception is reported even without an explicit wait call."""
    with pytest.raises(AssertionError, match="xrun process failed"):
        with tools.app("exception") as app:
            time.sleep(0.5)
    assert app.proc_returncode == 255


def test_xgdb_failure_and_timeout_are_reported(tools, monkeypatch):
    """Recovery reports both failed connections and bounded xgdb timeouts."""
    monkeypatch.setenv("FAKE_XGDB", "fail")
    with pytest.raises(AssertionError, match="Connecting to XTAG SERIAL failed"):
        with tools.app("serve") as app:
            app.wait_for_output("ready")
    monkeypatch.setenv("FAKE_XGDB", "hang")
    monkeypatch.setattr(Session, "xgdb_timeout", 0.5)
    with pytest.raises(AssertionError, match="timed out"):
        with tools.app("serve") as app:
            app.wait_for_output("ready")
    assert gone(tools)


# ---- Output ------------------------------------------------------------------------------

def test_large_output_does_not_block_the_application(tools):
    """Output larger than pipe capacity is fully drained without blocking execution."""
    with tools.app("flood") as app:
        app.wait(timeout=20)  # More than 4 MiB; a pipe holds 64 KiB.
        assert app.lines[-1] == "PASS" and len(app.lines) == 52001
    assert len(app.proc_stdout) == 52000 * 80 + 5


def test_lines_from_both_streams_without_final_newline(tools):
    """Partial final lines from both streams are retained with raw captures unchanged."""
    with tools.app("partial") as app:
        app.wait()
    assert sorted(app.lines) == ["line", "no newline"]
    assert app.proc_stdout == "no newline" and app.proc_stderr == "line\r\n"


def test_log_is_written_while_running_and_kept_on_failure(tools):
    """Logs are visible during execution, survive failure and reset for the next run."""
    log = tools.path / "logs" / "run.log"
    with pytest.raises(RuntimeError):
        with tools.app("serve", log_path=log) as app:
            app.wait_for_output("RESULT")
            assert b"RESULT 42" in log.read_bytes()
            raise RuntimeError("test failed")
    assert b"RESULT 42" in log.read_bytes()
    with tools.app(attach=None, log_path=log):
        pass
    assert log.read_text() == "hello\nPASS\n"


def test_cwd_is_where_xrun_runs(tools):
    """The launcher executes in the caller-selected working directory."""
    work = tools.path / "work"
    work.mkdir()
    with tools.app("cwd", cwd=work) as app:
        app.wait()
    assert Path(app.lines[0]).resolve() == work.resolve()


@pytest.mark.parametrize("attach, xflash", [("xscope", False), (None, False), (None, True)])
def test_relative_paths_resolve_before_using_cwd(tools, monkeypatch, attach, xflash):
    """Relative XE and log paths remain caller-relative after changing launcher cwd."""
    monkeypatch.chdir(tools.path)
    work = tools.path / "work"
    work.mkdir()
    log = Path("logs/run.log")
    with Session("app.xe", "SERIAL", attach=attach, xflash=xflash, cwd=work, log_path=log) as app:
        if attach:
            app.wait()
    assert str(tools.path / "app.xe") in tools.args()
    assert app.log_path == tools.path / log
    assert app.log_path.read_text() == "hello\nPASS\n"
    assert not (work / log).exists()


@pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink"])
@pytest.mark.parametrize("attach, xflash", [("xscope", False), (None, False), (None, True)])
def test_session_log_cannot_overwrite_the_executable(tools, monkeypatch, alias, attach, xflash):
    """All launch modes reject direct, relative and linked log aliases of the XE."""
    xe = tools.path / "app.xe"
    log = xe
    if alias == "relative":
        monkeypatch.chdir(tools.path)
        log = Path("app.xe")
    elif alias in ("symlink", "hardlink"):
        log = tools.path / "run.log"
        if alias == "symlink":
            log.symlink_to(xe)
        else:
            log.hardlink_to(xe)
    with pytest.raises(ValueError, match="overwrite the executable"):
        tools.app(attach=attach, xflash=xflash, log_path=log)
    assert xe.read_bytes() == b"XE"
    assert not (tools.path / "xrun.args").exists()


def test_log_path_is_checked_again_before_opening(tools):
    """A log path changed to an XE hard link after construction is still rejected."""
    log = tools.path / "run.log"
    app = tools.app(log_path=log)
    log.hardlink_to(tools.path / "app.xe")
    with pytest.raises(ValueError, match="overwrite the executable"):
        app._open_log()
    assert (tools.path / "app.xe").read_bytes() == b"XE"


def test_log_checks_the_open_file_before_truncating(tools, monkeypatch):
    """An XE symlink substituted during open is detected before truncating the file."""
    log = tools.path / "run.log"
    app = tools.app(log_path=log)
    original_open = os.open

    def replace_with_link(path, *args, **kwargs):
        if path == log:
            log.symlink_to(tools.path / "app.xe")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_with_link)
    with pytest.raises(ValueError, match="overwrite the executable"):
        app._open_log()
    assert (tools.path / "app.xe").read_bytes() == b"XE"


@pytest.fixture
def broken_log(monkeypatch):
    original_open = Session._open_log

    def install(operation):
        class BrokenLog:
            def __init__(self, real):
                self.real = real

            def write(self, chunk):
                if operation == "write":
                    raise OSError("log disk full")
                return self.real.write(chunk)

            def flush(self):
                if operation == "flush":
                    raise OSError("log disk full")
                self.real.flush()

            def close(self):
                self.real.close()
                if operation == "close":
                    raise OSError("log disk full")

        def open_log(self):
            original_open(self)
            if self._log is not None and not isinstance(self._log, BrokenLog):
                self._log = BrokenLog(self._log)

        monkeypatch.setattr(Session, "_open_log", open_log)

    return install


@pytest.mark.parametrize("operation", ["write", "flush", "close"])
def test_log_failures_keep_draining_and_fail_after_recovery(tools, broken_log, operation):
    """Log write, flush and close failures preserve draining and fail after recovery."""
    broken_log(operation)
    with pytest.raises(SessionError, match="Writing log .* failed: log disk full"):
        with tools.app("flood", log_path=tools.path / "run.log") as app:
            app.wait(timeout=20)
            assert len(app.lines) == 52001 and app.lines[-1] == "PASS"
    assert len(app.proc_stdout) == 52000 * 80 + 5
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_unattached_log_failure_is_reported_after_recovery(tools, broken_log):
    """Unattached logging failures are reported without skipping target recovery."""
    broken_log("write")
    with pytest.raises(SessionError, match="Writing log .* failed: log disk full"):
        with tools.app(attach=None, log_path=tools.path / "run.log") as app:
            assert app.proc_stdout == "hello\nPASS\n"
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_logging_failure_does_not_replace_the_test_failure(tools, broken_log):
    """A log error is secondary to the original test-body error during cleanup."""
    broken_log("write")
    with pytest.raises(ValueError, match="the real failure") as failure:
        with tools.app("serve", log_path=tools.path / "run.log") as app:
            app.wait_for_output("ready")
            raise ValueError("the real failure")
    assert gone(tools) and len(tools.xgdb_calls()) == 1
    if hasattr(failure.value, "__notes__"):
        assert "log disk full" in failure.value.__notes__[0]


# ---- Deadlines and completion ------------------------------------------------------------

def test_wait_returns_for_a_finished_application(tools):
    """Normal completion exposes all output and closes both pipes on context exit."""
    with tools.app() as app:
        app.wait()
        assert app.lines == ["hello", "PASS"]
    assert app.proc_returncode == 0
    assert app.proc.stdout.closed and app.proc.stderr.closed


def test_wait_enforces_its_deadline(tools):
    """Waiting on a silent application times out and stops the launcher promptly."""
    started = time.monotonic()
    with pytest.raises(SessionTimeout, match="did not finish within 0.5s"):
        with tools.app("silent") as app:
            app.wait(timeout=0.5)
    assert time.monotonic() - started < 10 and gone(tools)


def test_wait_reports_a_failing_exit_status(tools):
    """A non-zero launcher status includes its diagnostic output in the failure."""
    with pytest.raises(SessionError, match="status 7") as failure:
        with tools.app("exit7") as app:
            app.wait()
    assert "launcher failed" in str(failure.value)


def test_unexpected_exit_fails_even_when_the_test_does_not_wait(tools):
    """Context teardown detects an unexpected non-zero exit without an explicit wait."""
    with pytest.raises(AssertionError, match="xrun exited with status 7"):
        with tools.app("exit7"):
            time.sleep(0.5)


def test_wait_for_output_matchers_continue_from_the_last_match(tools):
    """Successive substring, regex and callable waits do not reuse consumed lines."""
    import re
    with tools.app("serve") as app:
        assert app.wait_for_output("ready") == "ready"
        assert app.wait_for_output(re.compile(r"RESULT (\d+)")) == "RESULT 42"
        with pytest.raises(SessionTimeout):
            app.wait_for_output(lambda line: line.startswith("RESULT"), timeout=0.3)


def test_wait_for_output_fails_when_output_ends(tools):
    """A matcher that never succeeds fails when the application's output ends."""
    with pytest.raises(SessionError, match="Output ended"):
        with tools.app() as app:
            app.wait_for_output("never printed")


def test_max_runtime_stops_a_test_that_does_not_wait(tools):
    """The watchdog bounds silent applications even when the test never calls wait."""
    with pytest.raises(SessionTimeout, match="max_runtime of 0.5s"):
        with tools.app("silent", max_runtime=0.5):
            time.sleep(1.5)
    assert gone(tools)


def test_max_runtime_forces_a_stubborn_launcher_before_context_exit(tools):
    """The watchdog kills a SIGTERM-resistant launcher before deferred target recovery."""
    with pytest.raises(SessionTimeout, match="max_runtime of 0.5s"):
        with tools.app("stubborn", max_runtime=0.5) as app:
            app.wait_for_output("ready")
            assert app.proc.wait(timeout=4) == -9
            assert gone(tools)
            assert not tools.xgdb_calls()  # Still inside the test's host-side work.
    assert len(tools.xgdb_calls()) == 1


def test_max_runtime_kills_helpers_even_if_launcher_exits_on_sigterm(tools):
    """Watchdog escalation kills surviving helpers even after the launcher exits."""
    with pytest.raises(SessionTimeout, match="max_runtime of 0.5s"):
        with tools.app("stubborn_child", max_runtime=0.5) as app:
            app.wait_for_output("ready")
            app.proc.wait(timeout=4)
            assert gone(tools, "child")  # Escalation cannot depend on xrun still being alive.
            assert not tools.xgdb_calls()
    assert len(tools.xgdb_calls()) == 1


def test_teardown_cancels_watchdog_escalation_without_racing(tools, monkeypatch):
    """Concurrent teardown and watchdog escalation finish without duplicate recovery."""
    sent_term = threading.Event()
    forced_while_stopping = []
    with pytest.raises(SessionTimeout):
        with tools.app("stubborn") as app:
            app.wait_for_output("ready")
            original_signal = app._signal

            def signal(force=False):
                if force:
                    forced_while_stopping.append(app._stopping)
                original_signal(force=force)
                sent_term.set()

            monkeypatch.setattr(app, "_signal", signal)
            watchdog = threading.Thread(target=app._overrun)
            watchdog.start()
            assert sent_term.wait(3)
    watchdog.join(timeout=3)
    assert not watchdog.is_alive()
    assert forced_while_stopping and all(forced_while_stopping)
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_cancelled_watchdog_does_not_start_stopping_xrun(tools, monkeypatch):
    """A cancelled watchdog sends no stop signal and does not mark an overrun."""
    app = tools.app()
    app.proc = SimpleNamespace(poll=lambda: None)
    app._watchdog_cancel.set()
    monkeypatch.setattr(app, "_signal", lambda **kwargs: pytest.fail("watchdog was cancelled"))
    app._overrun()
    assert not app._overran


# ---- Start-up and teardown ---------------------------------------------------------------

def test_startup_failure_does_not_leave_xrun_running(tools, monkeypatch):
    """Failure to open an xSCOPE port stops the launched process and recovers the target."""
    def fail(self, timeout=10):
        while not (tools.path / "xrun.pid").exists():
            time.sleep(0.01)
        raise RuntimeError("port never opened")
    monkeypatch.setattr(Session, "wait_for_xscope_port", fail)
    with pytest.raises(RuntimeError, match="port never opened"):
        tools.app("silent", attach="xscope_app").__enter__()
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_xscope_port_wait_stops_when_xrun_exits(tools):
    """Waiting for an xSCOPE port fails promptly if the launcher exits first."""
    started = time.monotonic()
    with pytest.raises(AssertionError, match="before its xscope port"):
        tools.app("exit7", attach="xscope_app").__enter__()
    assert time.monotonic() - started < 5


def test_xrun_ignoring_the_stop_request_is_killed_and_target_recovered(tools):
    """Teardown escalates beyond SIGTERM when necessary and then recovers the target."""
    with tools.app("stubborn") as app:
        app.wait_for_output("ready")
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_helpers_started_by_xrun_are_stopped(tools):
    """Teardown stops both the launcher and the helper processes it started."""
    with tools.app("child") as app:
        app.wait_for_output("ready")
    assert gone(tools) and gone(tools, "child")


def test_teardown_failure_does_not_replace_the_test_failure(tools, monkeypatch):
    """Recovery failure is attached to, rather than replacing, the original test error."""
    monkeypatch.setenv("FAKE_XGDB", "fail")
    with pytest.raises(ValueError, match="the real failure") as failure:
        with tools.app("serve") as app:
            app.wait_for_output("ready")
            raise ValueError("the real failure")
    assert gone(tools)
    if hasattr(failure.value, "__notes__"):
        assert "Connecting to XTAG SERIAL failed" in failure.value.__notes__[0]


def test_terminate_twice_is_harmless(tools):
    """Explicit termination followed by context teardown remains safe."""
    with tools.app("serve") as app:
        app.wait_for_output("ready")
        app.terminate()
    assert len(tools.xgdb_calls()) == 2


@pytest.mark.parametrize("mode, expected", [("exit0", True), ("exit7", False),
                                           ("exception", False), ("silent", False)])
def test_run_entry_point_uses_lifecycle_and_keeps_logs(tools, monkeypatch, mode, expected):
    """The public runner preserves logs and recovery on success, failure and timeout."""
    from Pyxsim.testers import ComparisonTester

    monkeypatch.setenv("FAKE_XRUN", mode)
    log = tools.path / "run.log"
    assert run(tools.path / "app.xe", adapter_id="SERIAL", timeout=0.5,
               tester=ComparisonTester(["hello", "PASS"]), log_path=log) is expected
    assert log.exists()
    assert gone(tools)
    assert len(tools.xgdb_calls()) == 1


def test_run_entry_point_fails_when_recovery_fails(tools, monkeypatch):
    """A successful application cannot make the runner pass if target recovery fails."""
    monkeypatch.setenv("FAKE_XGDB", "fail")
    assert run(tools.path / "app.xe", adapter_id="SERIAL") is False


def test_run_until_stops_and_compares_at_completion(tools, monkeypatch):
    """Completion bounds comparison while logs retain trailing and shutdown output."""
    from Pyxsim.testers import ComparisonTester

    monkeypatch.setenv("FAKE_XRUN", "noisy_tail")
    log = tools.path / "observation.log"
    assert run(tools.path / "app.xe", adapter_id="SERIAL", timeout=3,
               until=lambda line: line == "PASS",
               tester=ComparisonTester(["ready", "PASS"]), log_path=log)
    assert "after completion" in log.read_text()
    assert "shutdown diagnostic" in log.read_text()
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_quiet_run_retains_complete_log(tools, capsys):
    """Disabling stdout replay still writes the complete application log."""
    log = tools.path / "quiet.log"
    assert run(tools.path / "app.xe", adapter_id="SERIAL", echo=False, log_path=log)
    assert capsys.readouterr().out == ""
    assert log.read_text() == "hello\nPASS\n"


def test_quiet_run_can_print_reports_live_without_replay(tools, monkeypatch, capsys):
    """A quiet runner can print callback reports live without duplicate replay."""
    monkeypatch.setenv("FAKE_XRUN", "noisy_tail")
    log = tools.path / "live.log"

    def completed(line):
        print(line, flush=True)
        return line == "PASS"

    assert run(tools.path / "app.xe", adapter_id="SERIAL", until=completed,
               timeout=3, echo=False, log_path=log)
    assert capsys.readouterr().out == "ready\nPASS\n"
    assert "after completion" in log.read_text()
    assert "shutdown diagnostic" in log.read_text()


@pytest.mark.parametrize("mode", ["exit0", "stderr_marker", "closed_pipes"])
def test_run_until_does_not_accept_missing_stdout_observation(tools, monkeypatch, mode):
    """Clean exit, stderr markers and closed pipes cannot replace stdout completion."""
    monkeypatch.setenv("FAKE_XRUN", mode)
    marker = "never printed" if mode == "exit0" else "PASS"
    assert not run(tools.path / "app.xe", adapter_id="SERIAL", timeout=0.5,
                   until=marker, log_path=tools.path / "failed-observation.log")
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_run_until_does_not_accept_target_exception_after_marker(tools, monkeypatch):
    """A target exception reported after the completion marker still fails the run."""
    monkeypatch.setenv("FAKE_XRUN", "late_exception")
    assert not run(tools.path / "app.xe", adapter_id="SERIAL", until="PASS", timeout=3)
    assert gone(tools) and len(tools.xgdb_calls()) == 1


@pytest.mark.parametrize("error", [AssertionError("invalid report"), ValueError("bad report"),
                                  KeyboardInterrupt("interrupted")])
def test_run_until_callback_errors_preserve_logs_and_recover(tools, monkeypatch, error):
    """Matcher errors and interruptions keep output logs and finish recovery first."""
    monkeypatch.setenv("FAKE_XRUN", "serve")
    log = tools.path / "callback-failure.log"

    def reject(line):
        raise error

    with pytest.raises(type(error), match=str(error)):
        run(tools.path / "app.xe", adapter_id="SERIAL", until=reject, timeout=3, log_path=log)
    assert "ready" in log.read_text()
    assert gone(tools) and len(tools.xgdb_calls()) == 1


def test_continuous_output_does_not_extend_deadline(tools):
    """A noisy producer cannot extend the absolute deadline of an output wait."""
    with tools.app("noise") as app:
        started = time.monotonic()

        def never_matches(line):
            time.sleep(0.01)  # The producer outpaces the callback.
            return False

        with pytest.raises(SessionTimeout):
            app.wait_for_output(never_matches, timeout=0.3)
        assert time.monotonic() - started < 3


def test_output_keeps_draining_while_match_callback_runs(tools):
    """Slow matcher callbacks do not block readers from capturing later output."""
    with tools.app("progress") as app:
        def completed(line):
            if line != "ready":
                return False
            deadline = time.monotonic() + 2
            while "progress" not in app.lines and time.monotonic() < deadline:
                time.sleep(0.01)
            assert "progress" in app.lines
            return True

        assert app.wait_for_output(completed, timeout=3) == "ready"


def test_invalid_observation_options(tools):
    """Output waits reject unsupported matchers and stream selections."""
    with tools.app("serve") as app:
        with pytest.raises(TypeError, match="matcher"):
            app.wait_for_output(False)
        with pytest.raises(ValueError, match="stream"):
            app.wait_for_output("ready", stream="invalid")
