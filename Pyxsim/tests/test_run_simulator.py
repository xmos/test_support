# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Run-only API tests using a mocked simulator and no firmware compilation.

XTC Tools and XSI are required for package imports; no simulation is launched.
"""
from types import SimpleNamespace

import pytest

import Pyxsim
from Pyxsim.testers import AssertiveComparisonTester, ComparisonTester


@pytest.fixture
def simulator(monkeypatch):
    state = SimpleNamespace(calls=[], success=True)

    def execute(xe, threads, **options):
        state.calls.append((xe, threads, options))
        print("  ready  \n\nPASS")
        return state.success

    def build(*args, **kwargs):
        pytest.fail("run() must not build")

    monkeypatch.setattr(Pyxsim, "run_with_pyxsim", execute)
    monkeypatch.setattr(Pyxsim, "_build", build)
    return state


@pytest.mark.parametrize("assertive", [False, True])
@pytest.mark.filterwarnings("error::DeprecationWarning")
def test_run_checks_output_and_returns_bool(simulator, capfd, assertive):
    """Both checker styles yield boolean success without building or warning."""
    checker = (AssertiveComparisonTester(["ready", "PASS"], False, True) if assertive
               else ComparisonTester(["ready", "PASS"]))
    assert Pyxsim.run("test.xe", tester=checker, capfd=capfd, timeout=4) is True
    assert simulator.calls == [("test.xe", [], {"timeout": 4})]


def test_run_forwards_backend_options(simulator):
    """Threads, simulator arguments, application arguments and plugins reach the backend."""
    threads = [object()]
    assert Pyxsim.run("test.xe", simthreads=threads, simargs=["--max-cycles", "100"],
                      appargs=["input"], plugins=[]) is True
    assert simulator.calls == [("test.xe", threads,
                                dict(timeout=600, simargs=["--max-cycles", "100"],
                                     appargs=["input"], plugins=[]))]


def test_run_boolean_comparison_failure(simulator, capfd):
    """A boolean checker's mismatch makes run() return False."""
    assert Pyxsim.run("test.xe", tester=ComparisonTester(["wrong"]), capfd=capfd) is False


def test_run_assertive_comparison_failure(simulator, capfd):
    """An assertive checker's mismatch propagates as an assertion failure."""
    with pytest.raises(AssertionError):
        Pyxsim.run("test.xe", tester=AssertiveComparisonTester(["wrong"], False, True),
                   capfd=capfd)


def test_failed_execution_is_not_compared(simulator, capfd):
    """Failed execution returns False without handing partial output to a checker."""
    simulator.success = False

    def check(lines):
        pytest.fail("must not compare failed execution")

    assert Pyxsim.run("test.xe", tester=SimpleNamespace(run=check), capfd=capfd) is False


def test_checker_cannot_be_silently_skipped(simulator):
    """A supplied tester requires capture so comparison cannot be silently skipped."""
    with pytest.raises(ValueError, match="capfd is required"):
        Pyxsim.run("test.xe", tester=ComparisonTester(["wrong"]))
    assert not simulator.calls


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_deadline_is_finite_and_positive(simulator, timeout):
    """Zero, negative, infinite and NaN deadlines fail before execution."""
    with pytest.raises(ValueError, match="timeout"):
        Pyxsim.run("test.xe", timeout=timeout)
    assert not simulator.calls


def test_run_rejects_implicit_build(simulator):
    """The run-only API rejects requests to build rather than invoking the build system."""
    with pytest.raises(ValueError, match="does not build"):
        Pyxsim.run("test.xe", do_xe_prebuild=True)
    assert not simulator.calls


def test_invalid_checker(simulator, capfd):
    """A tester without a callable run method is rejected before execution."""
    with pytest.raises(TypeError, match="tester"):
        Pyxsim.run("test.xe", tester=object(), capfd=capfd)
    assert not simulator.calls


def test_legacy_run_only_return_value_is_unchanged(simulator, capfd):
    """The deprecated wrapper preserves None from a successful assertive checker."""
    checker = AssertiveComparisonTester(["ready", "PASS"], False, True)
    with pytest.warns(DeprecationWarning, match="run_on_simulator_.*deprecated"):
        assert Pyxsim.run_on_simulator_("test.xe", tester=checker, capfd=capfd) is None


def test_build_and_run_requests_build_without_warning(monkeypatch, recwarn):
    """The legacy build-and-run entry point still requests a build without deprecation."""
    calls = []

    def execute(*args, **kwargs):
        calls.append((args, kwargs))
        return False

    monkeypatch.setattr(Pyxsim, "_run_on_simulator", execute)
    assert Pyxsim.run_on_simulator("test.xe") is False
    assert not recwarn.list
    assert calls == [(("test.xe",), {"do_xe_prebuild": True})]
