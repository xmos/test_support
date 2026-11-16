"""Compatibility checks for callers predating the run-only API."""
import warnings
from types import SimpleNamespace

import pytest

import Pyxsim


@pytest.mark.parametrize("result", [None, False, True, object()])
@pytest.mark.parametrize("entry_point", ["run_on_simulator_", "run_on_simulator"])
def test_legacy_positional_calls_preserve_checker_results(monkeypatch, capfd, result, entry_point):
    """Legacy positional calls forward arguments and return the checker's exact value."""
    calls = []
    threads = [object()]

    def execute(xe, simthreads, **options):
        calls.append((xe, simthreads, options))
        print("ready")
        return True

    def compare(lines):
        assert lines == ["ready"]
        return result

    monkeypatch.setattr(Pyxsim, "run_with_pyxsim", execute)
    monkeypatch.setattr(Pyxsim, "_build", lambda *args, **kwargs: (True, []))
    runner = getattr(Pyxsim, entry_point)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert runner("test.xe", SimpleNamespace(run=compare), threads,
                      capfd=capfd, simargs=["--max-cycles", "10"], appargs=["input"]) is result
    assert calls == [("test.xe", threads, {"simargs": ["--max-cycles", "10"], "appargs": ["input"]})]


@pytest.mark.parametrize("entry_point", ["run_on_simulator_", "run_on_simulator"])
@pytest.mark.parametrize("build_success", [False, True])
def test_legacy_build_options_remain_supported(monkeypatch, entry_point, build_success):
    """Legacy build options reach _build, and failed builds prevent simulation."""
    calls = []

    def build(xe, **options):
        calls.append(("build", xe, options))
        return build_success, []

    def execute(xe, simthreads, **options):
        calls.append(("run", xe, simthreads, options))
        return True

    monkeypatch.setattr(Pyxsim, "_build", build)
    monkeypatch.setattr(Pyxsim, "run_with_pyxsim", execute)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert getattr(Pyxsim, entry_point)(
            "test.xe", None, [], do_xe_prebuild=True, build_env={"CONFIG": "test"},
            build_config="debug", clean_before_build=True, clean_only=False,
            cmake=False, build_options=["-j2"], timeout=3,
        ) is build_success
    assert calls[0] == ("build", "test.xe", dict(
        env={"CONFIG": "test"}, build_config="debug", do_clean=True,
        clean_only=False, cmake=False, build_options=["-j2"],
    ))
    assert calls[1:] == ([("run", "test.xe", [], {"timeout": 3})] if build_success else [])


def test_legacy_checker_without_capture_is_still_optional(monkeypatch):
    """Unlike run(), the legacy wrapper still permits a checker without capture."""
    def compare(lines):
        pytest.fail("legacy API skipped comparison without capfd")

    monkeypatch.setattr(Pyxsim, "run_with_pyxsim", lambda *args, **kwargs: True)
    with pytest.warns(DeprecationWarning):
        assert Pyxsim.run_on_simulator_("test.xe", SimpleNamespace(run=compare)) is True


@pytest.mark.parametrize("entry_point", ["run_on_simulator_", "run_on_simulator"])
def test_legacy_failed_execution_is_not_compared(monkeypatch, capfd, entry_point):
    """Both legacy runners return False without comparing output after execution failure."""
    def compare(lines):
        pytest.fail("must not compare failed execution")

    monkeypatch.setattr(Pyxsim, "run_with_pyxsim", lambda *args, **kwargs: False)
    monkeypatch.setattr(Pyxsim, "_build", lambda *args, **kwargs: (True, []))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert getattr(Pyxsim, entry_point)(
            "test.xe", SimpleNamespace(run=compare), [], capfd=capfd,
        ) is False


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("fails", [False, True])
def test_legacy_worker_call_retains_optional_plugins_and_cleanup(monkeypatch, remote, fails):
    """Local and remote worker calls preserve plugin arguments and always terminate."""
    calls = []

    class Backend:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))

        def register_simthread(self, thread):
            calls.append(("thread", thread))

        def register_plugin(self, plugin):
            calls.append(("plugin", plugin))

        def run(self):
            calls.append("run")
            if fails:
                raise RuntimeError("backend failed")

        def terminate(self):
            calls.append("terminate")

    monkeypatch.setitem(Pyxsim.__dict__, "pyxsim", SimpleNamespace(Xsi=Backend, XsiRemote=Backend))
    monkeypatch.delenv("XSI_ENDPOINT", raising=False)
    if remote:
        monkeypatch.setenv("XSI_ENDPOINT", "localhost:1234")
    if fails:
        with pytest.raises(RuntimeError, match="backend failed"):
            Pyxsim.do_run_pyxsim("test.xe", [], ["input"], ["thread"], ["plugin"])
    else:
        Pyxsim.do_run_pyxsim("test.xe", [], ["input"], ["thread"], ["plugin"])
    assert calls == [
        (("localhost:1234",) if remote else (),
         dict(xe_path="test.xe", simargs=[], appargs=["input"], tmp_root=None)),
        ("thread", "thread"), ("plugin", "plugin"), "run", "terminate",
    ]


def test_legacy_simulator_imports_and_discovery():
    """Named, wildcard and attribute imports expose the same simulator API."""
    from Pyxsim import Xsi, XsiRemote, pyxsim

    assert Xsi is pyxsim.Xsi and XsiRemote is pyxsim.XsiRemote
    assert Pyxsim.pyxsim is pyxsim
    names = {}
    exec('from Pyxsim import *', names)
    for name in ('Xsi', 'XsiRemote', 'pyxsim', 'Xe', 'SimThread', 'run_on_simulator_',
                 'run_on_simulator', 'run_with_pyxsim', 'do_run_pyxsim', 'run', 'build'):
        assert name in names, name
        assert names[name] is getattr(Pyxsim, name), name
    assert {'Xsi', 'XsiRemote', 'pyxsim'} <= set(dir(Pyxsim))
