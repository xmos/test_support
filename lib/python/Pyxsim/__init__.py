# Copyright 2016-2022 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""
Pyxsim pytest framework

This module provides functions to run tests for XMOS applications and
libraries.
"""
import multiprocessing
import os
import re
import sys

from Pyxsim.xmostest_subprocess import call_get_output
from . import pyxsim


# This function is called automatically by the runners
def _build(
    xe_path,
    build_config=None,
    env={},
    do_clean=False,
    clean_only=False,
    build_options=[],
):

    # Work out the Makefile path
    path = None
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
    for key in env:
        my_env[key] = str(env[key])

    if clean_only:
        cmd = ["xmake", "clean"]
        do_clean = False
    else:
        cmd = ["xmake", "all"]

    if do_clean:
        call_get_output(["xmake", "clean"], cwd=path, env=my_env)

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


def run_on_simulator_(xe, tester=None, simthreads=[], **kwargs):

    do_xe_prebuild = kwargs.get("do_xe_prebuild", False)
    capfd = kwargs.pop("capfd", None)

    if do_xe_prebuild:
        build_env = kwargs.get("build_env", {})
        do_clean = kwargs.get("clean_before_build", False)
        build_success, build_output = _build(xe, env=build_env, do_clean=do_clean)

        if not build_success:
            return False

    for k in ["do_xe_prebuild", "build_env", "clean_before_build"]:
        if k in kwargs:
            kwargs.pop(k)

    run_with_pyxsim(xe, simthreads, tester, **kwargs)

    if tester and capfd:
        cap_output, err = capfd.readouterr()
        output = cap_output.split("\n")
        output = [x.strip() for x in output if x != ""]
        result = tester.run(output)
        return result

    return True


def run_on_simulator(*args, **kwargs):

    kwargs["do_xe_prebuild"] = True

    result = run_on_simulator_(*args, **kwargs)

    return result


def do_run_pyxsim(xe, simargs, appargs, simthreads):
    xsi = pyxsim.Xsi(xe_path=xe, simargs=simargs, appargs=appargs)
    for x in simthreads:
        xsi.register_simthread(x)
    xsi.run()
    xsi.terminate()


def run_with_pyxsim(
    xe,
    simthreads,
    simargs=[],
    appargs=[],
    timeout=600,
):
    p = multiprocessing.Process(
        target=do_run_pyxsim, args=(xe, simargs, appargs, simthreads)
    )
    p.start()
    p.join(timeout=timeout)
    if p.is_alive():
        sys.stderr.write("Simulator timed out\n")
        p.terminate()


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
