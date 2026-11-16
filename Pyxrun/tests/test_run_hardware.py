# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""The public run helper delegates execution and recovery to Session."""
import re
from types import SimpleNamespace

import pytest

import Pyxrun
from Pyxsim.testers import AssertiveComparisonTester, ComparisonTester


@pytest.fixture
def hardware(tmp_path, monkeypatch):
    xe = tmp_path / "firmware with spaces.xe"
    xe.write_bytes(b"XE")
    state = SimpleNamespace(options=None, closed=False, failure=None, until_calls=[],
                            output="  ready  \n\nPASS\n", diagnostic="host diagnostic\n")

    class App:
        def __init__(self, executable, adapter, **options):
            assert executable == xe
            assert adapter == "SERIAL"
            state.options = options

        def __enter__(self):
            return self

        def wait(self, timeout=None):
            assert 0 < timeout <= state.options["timeout"]
            if state.failure:
                raise state.failure

        def wait_for_output(self, match, timeout=None, *, stream=None):
            state.until_calls.append((timeout, stream))
            self.wait(timeout)
            for line in state.output.splitlines():
                if match(line):
                    return line
            raise Pyxrun.SessionError("Output ended before the awaited line")

        def __exit__(self, *args):
            self.proc_stdout = state.output
            self.proc_stderr = state.diagnostic
            state.closed = True

    monkeypatch.setattr(Pyxrun, "Session", App)
    state.run = lambda **options: Pyxrun.run(xe, adapter_id="SERIAL", **options)
    state.xe = xe
    return state


@pytest.mark.parametrize("assertive", [False, True])
def test_run_uses_existing_checkers_and_returns_bool(hardware, assertive, capsys):
    """Both checker types return success with full xSCOPE defaults and diagnostics."""
    checker = (AssertiveComparisonTester(["ready", "PASS"], False, True) if assertive
               else ComparisonTester(["ready", "PASS"]))
    assert hardware.run(tester=checker) is True
    assert hardware.closed
    assert hardware.options["attach"] == "xscope"
    assert hardware.options["xscope_io_only"] is False
    assert hardware.options["timeout"] == 600
    assert "host diagnostic" in capsys.readouterr().err


def test_run_checks_only_after_teardown(hardware):
    """Output comparison runs after session cleanup and receives normalised stdout."""
    def check(lines):
        assert hardware.closed
        assert lines == ["ready", "PASS"]

    assert hardware.run(tester=SimpleNamespace(run=check)) is True


def test_run_without_checker(hardware):
    """A successful execution needs no output checker to return True."""
    assert hardware.run() is True


def test_quiet_run_still_checks_output_and_reports_stderr(hardware, capsys):
    """Quiet mode suppresses stdout replay, not comparison or stderr diagnostics."""
    checker = ComparisonTester(["ready", "PASS"])
    assert hardware.run(tester=checker, echo=False) is True
    captured = capsys.readouterr()
    assert "ready" not in captured.out and "PASS" not in captured.out
    assert checker.result is True  # The checker's own status output is not suppressed.
    assert "host diagnostic" in captured.err


def test_quiet_execution_failure_is_not_suppressed(hardware, capsys):
    """Quiet mode still reports execution failures and returns False."""
    hardware.failure = Pyxrun.SessionError("application failed")
    assert hardware.run(echo=False) is False
    assert "application failed" in capsys.readouterr().err


def test_run_forwards_hardware_options(hardware, tmp_path):
    """The wrapper forwards deadlines, paths, xSCOPE options and application arguments."""
    work = tmp_path / "work"
    log = tmp_path / "run.log"
    assert hardware.run(timeout=4, cwd=work, log_path=log, xscope_io_only=True)
    assert hardware.options == dict(attach="xscope", timeout=4, cwd=work,
                                   log_path=log, xscope_io_only=True, appargs=None)
    assert hardware.run(appargs=["12345"])
    assert hardware.options["appargs"] == ["12345"]


def test_run_legacy_jtag_is_explicit(hardware):
    """JTAG I/O is used only when the caller explicitly selects attach='io'."""
    assert hardware.run(attach="io")
    assert hardware.options["attach"] == "io"


def test_boolean_comparison_failure(hardware):
    """A boolean checker's output mismatch makes the hardware run fail."""
    assert hardware.run(tester=ComparisonTester(["wrong"])) is False


def test_assertive_comparison_failure_propagates_after_teardown(hardware):
    """An assertive checker's mismatch propagates only after cleanup completes."""
    with pytest.raises(AssertionError):
        hardware.run(tester=AssertiveComparisonTester(["wrong"], False, True))
    assert hardware.closed


@pytest.mark.parametrize("error", [Pyxrun.SessionTimeout("deadline"),
                                  Pyxrun.SessionError("exit 7"),
                                  AssertionError("target exception")])
def test_execution_failure_returns_false_without_checking(hardware, capsys, error):
    """Execution errors are reported after cleanup without comparing invalid output."""
    hardware.failure = error

    def check(lines):
        pytest.fail("must not compare failed execution")

    assert hardware.run(tester=SimpleNamespace(run=check)) is False
    assert hardware.closed
    assert str(error) in capsys.readouterr().err


def test_launch_errors_propagate(hardware):
    """Missing launcher errors propagate rather than masquerading as mismatches."""
    hardware.failure = FileNotFoundError("xrun not found")
    with pytest.raises(FileNotFoundError, match="xrun not found"):
        hardware.run()


@pytest.mark.parametrize("options", [
    {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")},
    {"timeout": float("inf")}, {"attach": None}, {"attach": "xscope_app"},
    {"attach": "io", "xscope_io_only": True}, {"tester": object()}, {"until": False},
])
def test_invalid_options_fail_before_execution(hardware, options):
    """Invalid deadlines, attachment modes, checkers and matchers never launch a session."""
    with pytest.raises((ValueError, TypeError)):
        hardware.run(**options)
    assert hardware.options is None


@pytest.mark.parametrize("adapter", [None, "", " ", 0])
def test_adapter_required(hardware, adapter):
    """A non-empty adapter ID is required before constructing a hardware session."""
    with pytest.raises(ValueError, match="adapter_id"):
        Pyxrun.run(hardware.xe, adapter_id=adapter)
    assert hardware.options is None


def test_missing_executable(hardware):
    """A missing XE is rejected before any session can access hardware."""
    hardware.xe.unlink()
    with pytest.raises(FileNotFoundError):
        hardware.run()
    assert hardware.options is None


def test_log_cannot_overwrite_executable(hardware):
    """The wrapper rejects a log path that would destroy the XE."""
    with pytest.raises(ValueError, match="overwrite"):
        hardware.run(log_path=hardware.xe)
    assert hardware.xe.read_bytes() == b"XE"
    assert hardware.options is None


@pytest.mark.parametrize("match", ["PASS", re.compile(r"^PASS$"),
                                 lambda line: line == "PASS"])
def test_until_compares_only_through_completion(hardware, match):
    """Each matcher form bounds checker input at the observed stdout completion line."""
    hardware.output += "not part of comparison\n"

    def check(lines):
        assert hardware.closed
        assert lines == ["ready", "PASS"]

    assert hardware.run(until=match, tester=SimpleNamespace(run=check)) is True
    assert hardware.until_calls[0][1] == "stdout"


def test_until_requires_observation_even_on_clean_exit(hardware):
    """A clean exit is not success if the requested completion line never appeared."""
    assert hardware.run(until="never printed") is False
    assert hardware.closed


@pytest.mark.parametrize("error", [AssertionError("invalid report"), ValueError("bad report"),
                                  KeyboardInterrupt("interrupted")])
def test_until_callback_errors_propagate_after_cleanup(hardware, error):
    """Completion-callback errors and interruptions propagate after session cleanup."""
    def reject(line):
        raise error

    with pytest.raises(type(error), match=str(error)):
        hardware.run(until=reject)
    assert hardware.closed
