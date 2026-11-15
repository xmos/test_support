# Copyright 2016-2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""
Pyxsim pytest framework

This module provides functions to run tests for XMOS applications and
libraries.
"""
import math
import multiprocessing
import os
import re
import shutil
import sys
import subprocess
import tempfile
import warnings
from pathlib import Path

from Pyxsim.xmostest_subprocess import call_get_output
from . import pyxsim
from Pyxsim.xe import Xe
from Pyxsim.pyxsim import Xsi
from Pyxsim.pyxsim import XsiRemote
from Pyxsim.cmake_build import BuildError, build


# This function is called automatically by the runners
def _build(
    xe_path,
    build_config=None,
    env={},
    do_clean=False,
    clean_only=False,
    build_options=[],
    cmake=False,
):
    # Don't support build_config with cmake; extract the config name from xe_path
    if cmake and build_config is not None:
        msg = "ERROR: build_config option not supported with cmake"
        sys.stderr.write(msg)
        return (False, msg)

    # Work out the Makefile path
    path = None
    if cmake:
        path = Path.cwd() / "build"
        if not path.exists():
            msg = f"ERROR: cmake build directory doesn't exist at {path}"
            sys.stderr.write(msg)
            return (False, msg)
    else:
        m = re.match("(.*)/bin/(.*)", xe_path)
        if m:
            path = m.groups(0)[0]
            binpath = m.groups(0)[1]
            m = re.match("(.*)/(.*)", binpath)
            if m:
                build_config = m.groups(0)[0]

    if not path:
        msg = "ERROR: Cannot determine path to build: %s\n" % xe_path
        sys.stderr.write(msg)
        return (False, msg)

    # Copy the environment, to avoid modifying the env of the current shell
    my_env = os.environ.copy()
    if env:
        for key in env:
            my_env[key] = str(env[key])

    cmd = ["xmake"]
    if clean_only:
        cmd += ["clean"]
        do_clean = False

    if do_clean:
        call_get_output(["xmake", "clean"], cwd=path, env=my_env)

    if cmake:
        if not clean_only:
            cmd += [Path(xe_path).stem]
    else:
        if build_config is not None:
            cmd += ["CONFIG=%s" % build_config]

    cmd += build_options

    output = call_get_output(cmd, cwd=path, env=my_env, merge_out_and_err=True)

    success = True
    for x in output:
        s = str(x, "utf8")
        if s.find("Error") != -1:
            success = False
        if re.match(r"xmake: \*\*\* .* Stop.", s) is not None:
            success = False

    if not success:
        sys.stderr.write("ERROR: build failed.\n")
        for x in output:
            s = str(x, "utf8")
            sys.stderr.write(s)

    return (success, output)


def _split_capture_lines(text):
    return [x.strip() for x in text.split("\n") if x != ""]


def _filter_capture_lines(tester, lines):
    if tester and hasattr(tester, "filter_output"):
        filtered, suppressed = tester.filter_output(lines)
        if hasattr(tester, "format_suppression_summary"):
            return filtered, tester.format_suppression_summary(suppressed)
        return filtered, []
    return lines, []


def _replay_captured_output(capfd, tester, verbosity):
    cap_output, err = capfd.readouterr()
    output = _split_capture_lines(cap_output)
    err_lines = _split_capture_lines(err)

    if verbosity > 1:
        live_output, output_summary = _filter_capture_lines(tester, output)
        live_err, err_summary = _filter_capture_lines(tester, err_lines)

        with capfd.disabled():
            for line in live_output:
                sys.stdout.write(line + "\n")
            for line in output_summary + err_summary:
                sys.stdout.write(line + "\n")
            for line in live_err:
                sys.stderr.write(line + "\n")

    return output


def run(xe, tester=None, simthreads=None, *, timeout=600, capfd=None, **kwargs):
    """Run an already-built executable without invoking the build system.

    Like Pyxrun.run(), return a boolean for execution/comparison success;
    assertion-based checkers still raise on mismatch. A tester requires pytest's
    capfd fixture so its comparison cannot be silently skipped. Simulator options
    (simargs, appargs, plugins, etc.) pass through to the existing simulator runner.

    run() does not build. run_on_simulator() remains the way to build and then
    run; it and the deprecated run_on_simulator_() keep their existing behaviour,
    including their checker return values.
    """
    if kwargs.pop("do_xe_prebuild", False):
        raise ValueError("run() does not build; build the executable before calling run()")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    if tester is not None:
        if not callable(getattr(tester, "run", None)):
            raise TypeError("tester must have a callable run(lines) method")
        if capfd is None:
            raise ValueError("capfd is required when run() is given a tester")
    result = _run_on_simulator(
        xe, tester=tester, simthreads=[] if simthreads is None else simthreads,
        timeout=timeout, capfd=capfd, **kwargs,
    )
    return True if result is None else bool(result)


def run_on_simulator_(xe, tester=None, simthreads=[], **kwargs):
    """Deprecated: use run() for an already-built executable.

    Preserves the legacy checker return value and optional build arguments.
    """
    warnings.warn("Pyxsim.run_on_simulator_() is deprecated; use Pyxsim.run()",
                  DeprecationWarning, stacklevel=2)
    return _run_on_simulator(xe, tester=tester, simthreads=simthreads, **kwargs)


def _run_on_simulator(xe, tester=None, simthreads=[], **kwargs):

    do_xe_prebuild = kwargs.pop("do_xe_prebuild", False)
    capfd = kwargs.pop("capfd", None)
    verbosity = kwargs.pop("verbosity", 0)

    if do_xe_prebuild:
        build_env = kwargs.pop("build_env", {})
        build_config = kwargs.pop("build_config", None)
        do_clean = kwargs.pop("clean_before_build", False)
        clean_only = kwargs.pop("clean_only", False)
        cmake = kwargs.pop("cmake", None)
        build_options = kwargs.pop("build_options", [])

        build_success, build_output = _build(xe,
                                             build_config=build_config,
                                             env=build_env,
                                             do_clean=do_clean,
                                             clean_only=clean_only,
                                             build_options=build_options,
                                             cmake=cmake,
                                             )

        if not build_success:
            return False

    if capfd:
        pre_stdout, pre_stderr = capfd.readouterr()
        with capfd.disabled():
            sys.stdout.write(pre_stdout)
            sys.stderr.write(pre_stderr)

    sim_success = run_with_pyxsim(xe, simthreads, **kwargs)

    if not sim_success:
        if capfd:
            _replay_captured_output(capfd, tester, verbosity)
        return False

    if tester and capfd:
        output = _replay_captured_output(capfd, tester, verbosity)
        result = tester.run(output)
        return result

    if verbosity > 1 and capfd:
        cap_output, err = capfd.readouterr()
        with capfd.disabled():
            sys.stdout.write(cap_output)
            sys.stderr.write(err)

    return True


def run_on_simulator(*args, **kwargs):
    """Build the executable, then run it. Not deprecated: run() does not build."""
    kwargs["do_xe_prebuild"] = True

    result = _run_on_simulator(*args, **kwargs)

    return result


def do_run_pyxsim(xe, simargs, appargs, simthreads, plugins=None, tmp_root=None):
    # Get XSI_ENDPOINT environment variable if set, otherwise use local
    xsi_endpoint = os.environ.get("XSI_ENDPOINT")
    if xsi_endpoint:
        xsi = pyxsim.XsiRemote(
            xsi_endpoint, xe_path=xe, simargs=simargs, appargs=appargs, tmp_root=tmp_root
        )
    else:
        xsi = pyxsim.Xsi(xe_path=xe, simargs=simargs, appargs=appargs, tmp_root=tmp_root)
    try:
        for x in simthreads:
            xsi.register_simthread(x)
        if plugins:
            for plugin in plugins:
                xsi.register_plugin(plugin)
        xsi.run()
    finally:
        xsi.terminate()


def run_with_pyxsim(
    xe_path,
    simthreads,
    simargs=[],
    appargs=[],
    timeout=600,
    plugins=[],
    instTracing=False,
    vcdTracing=False,
):

    # Use 'fork' on Unix-like systems to preserve stdout/stderr capture
    # Windows continues to use default 'spawn' method
    if sys.platform != 'win32':
        ctx = multiprocessing.get_context('fork')
    else:
        ctx = multiprocessing.get_context()

    if instTracing or vcdTracing:

        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_filename = os.path.splitext(os.path.basename(xe_path))[0]
        log_filename = os.path.join(log_dir, f"xsim_trace_{log_filename}")

    if instTracing:

        simargs += [
            "--trace-to",
            log_filename + ".txt",
            "--enable-fnop-tracing",
        ]

    if vcdTracing:

        vcd_args = "-o {0}.vcd".format(log_filename)
        vcd_args += (
            " -tile tile[0] -ports -ports-detailed -instructions"
            " -functions -cycles -clock-blocks -pads -cores"
        )

        # This is slightly annoying to crate the obj just to grab Node Type..
        xe = Xe(xe_path)
        try:
            # Only enable USB tracing for XS3
            if "XS3" in xe.node_type:
                vcd_args += " -usb"
        finally:
            xe.close()

        simargs += ["--vcd-tracing", vcd_args]

    if os.environ.get("XSI_ENDPOINT"):
        timeout = None  # Don't timeout when running on remote server

    # The parent owns the worker's temp files so they are removed even if the
    # worker is terminated/killed or crashes without running its own cleanup.
    tmp_root = tempfile.mkdtemp(prefix="pyxsim_")
    try:
        p = ctx.Process(
            target=do_run_pyxsim,
            args=(xe_path, simargs, appargs, simthreads, plugins, tmp_root),
        )
        p.start()
        p.join(timeout=timeout)
        if p.is_alive():
            sys.stderr.write("Simulator timed out\n")
            p.terminate()
            p.join(timeout=1)
            if p.is_alive() and hasattr(p, "kill"):
                p.kill()
                p.join()
            return False

        if p.exitcode != 0:
            sys.stderr.write(f"Simulator process failed with exit code {p.exitcode}\n")
            return False

        return True
    finally:
        try:
            shutil.rmtree(tmp_root)
        except OSError as e:
            sys.stderr.write(f"Warning: failed to remove {tmp_root}: {e}\n")


class SimThread:
    def run(self, xsi):
        pass

    def wait(self, f):
        self.xsi._user_wait(f)

    def wait_for_port_pins_change(self, ps):
        self.xsi._wait_for_port_pins_change(ps)

    def wait_for_next_cycle(self):
        self.xsi._wait_for_next_cycle()

    def wait_until(self, t):
        self.xsi._wait_until(t)
