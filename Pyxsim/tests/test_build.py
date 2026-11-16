# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Build-helper tests using a stand-in cmake, with no real firmware compilation.

XTC Tools and XSI are required for package imports, not for the stand-in commands.
"""
import os
import signal
import stat
import subprocess
import sys
import time

import pytest

import Pyxsim
from Pyxsim import BuildError

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the stand-in tool is a POSIX script")

CMAKE = r"""
import os, subprocess, sys, time
from pathlib import Path
Path(os.environ["FAKE_DIR"], "cmake.args").write_text("\n".join(sys.argv[1:]))
Path(os.environ["FAKE_DIR"], "cmake.pid").write_text(str(os.getpid()))
mode = os.environ.get("FAKE_CMAKE", "ok")
if mode == "fail":
    print("main.c:3: error: expected ';'"); sys.exit(2)
if mode == "hang":
    time.sleep(600)
if mode == "descendants":
    grandchild = '''import os, signal, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(os.environ["FAKE_DIR"], "compiler.pid").write_text(str(os.getpid()))
print("compiler ready", flush=True)
time.sleep(5)
Path(os.environ["FAKE_DIR"], "late-object").write_text("abandoned compiler wrote this")
time.sleep(600)
'''
    child = '''import os, signal, subprocess, sys, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(os.environ["FAKE_DIR"], "make.pid").write_text(str(os.getpid()))
subprocess.Popen([sys.executable, "-c", sys.argv[1]])
time.sleep(600)
'''
    subprocess.Popen([sys.executable, "-c", child, grandchild])
    time.sleep(600)
if mode == "ok":
    xe = Path(os.environ["FAKE_XE"]); xe.parent.mkdir(parents=True, exist_ok=True); xe.write_bytes(b"XE")
print("built")
"""


@pytest.fixture
def project(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    tools.mkdir()
    script = tools / "cmake"
    script.write_text(f"#!{sys.executable}\n{CMAKE}")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tools}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_DIR", str(tmp_path))
    tests = tmp_path / "tests"
    (tests / "build").mkdir(parents=True)
    (tests / "build" / "CMakeCache.txt").write_text("")
    xe = tests / "app" / "bin" / "fast" / "app_fast.xe"
    monkeypatch.setenv("FAKE_XE", str(xe))
    return tmp_path, xe


def args(root):
    return (root / "cmake.args").read_text().splitlines()


def test_pyxrun_exports_the_same_build():
    """Hardware and simulator packages expose the identical build helper and error type."""
    import Pyxrun

    assert Pyxrun.build is Pyxsim.build
    assert Pyxrun.BuildError is Pyxsim.BuildError


def test_builds_the_target_in_the_nearest_build_directory(project):
    """The default build directory selects the XE's target and produces that executable."""
    root, xe = project
    assert Pyxsim.build(xe) is None
    assert args(root) == ["--build", str((root / "tests" / "build").resolve()), "--target", "app_fast"]
    assert xe.is_file()


def test_explicit_build_directory(project):
    """An explicitly configured build directory overrides automatic discovery."""
    root, xe = project
    other = root / "build-other"
    other.mkdir()
    (other / "CMakeCache.txt").write_text("")
    Pyxsim.build(xe, build_dir=other)
    assert args(root)[1] == str(other.resolve())


def test_unconfigured_build_directory(project):
    """Missing CMake configuration is rejected before invoking a build command."""
    root, xe = project
    (root / "tests" / "build" / "CMakeCache.txt").unlink()
    with pytest.raises(BuildError, match="run cmake first"):
        Pyxsim.build(xe)
    with pytest.raises(BuildError, match="not a configured CMake build directory"):
        Pyxsim.build(xe, build_dir=root / "tests" / "build")
    assert not (root / "cmake.args").exists()


def test_failure_carries_the_build_output(project, monkeypatch):
    """Build failures include the exit status and compiler output in BuildError."""
    _, xe = project
    monkeypatch.setenv("FAKE_CMAKE", "fail")
    with pytest.raises(BuildError, match=r"status 2\n.*expected ';'"):
        Pyxsim.build(xe)


def test_success_without_the_executable_is_a_failure(project, monkeypatch):
    """Exit status zero is insufficient if the build did not produce the requested XE."""
    _, xe = project
    monkeypatch.setenv("FAKE_CMAKE", "no-output")
    with pytest.raises(BuildError, match="did not produce"):
        Pyxsim.build(xe)


def test_deadline(project, monkeypatch):
    """Hung builds time out, and non-positive deadlines are rejected."""
    _, xe = project
    monkeypatch.setenv("FAKE_CMAKE", "hang")
    with pytest.raises(BuildError, match="exceeded 0.5 seconds"):
        Pyxsim.build(xe, timeout=0.5)
    with pytest.raises(ValueError):
        Pyxsim.build(xe, timeout=0)


def test_deadline_stops_build_tool_and_compiler_descendants(project, monkeypatch):
    """Timed-out builds stop all descendants before they can write abandoned outputs."""
    root, xe = project
    monkeypatch.setenv("FAKE_CMAKE", "descendants")
    pids = []
    try:
        with pytest.raises(BuildError, match="exceeded 1 seconds") as failure:
            Pyxsim.build(xe, timeout=1)
        assert "compiler ready" in str(failure.value)
        pids = [int((root / f"{name}.pid").read_text()) for name in ("cmake", "make", "compiler")]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            # Zombies have stopped too; a container's PID 1 may reap them late.
            states = [subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                     capture_output=True, text=True, timeout=2).stdout.strip()
                      for pid in pids]
            if all(not state or state.startswith("Z") for state in states):
                break
            time.sleep(0.02)
        assert all(not state or state.startswith("Z") for state in states)
        assert not (root / "late-object").exists()
        assert not xe.exists()
    finally:
        # Clean up even if this regression fails on an older implementation.
        for name in ("cmake", "make", "compiler"):
            path = root / f"{name}.pid"
            if path.exists():
                try:
                    os.kill(int(path.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
