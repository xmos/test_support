# Copyright 2016-2021 XMOS LIMITED.
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
from pathlib import Path
from typing import Sequence
import subprocess

from .xmostest_subprocess import call_get_output
from . import pyxsim

# This function is called automatically by the runners
def _build(xe_path, build_config=None, env={}, do_clean=False, clean_only=False, 
            build_options=[], cmake=False, bin_child:str=None, silent=False):

    if cmake and not bin_child:
        sys.stderr.write("ERROR: A name must be provided for the " +\
                            "desired subdirectory of /bin/ for this build!")
        return
    
    path = None
    # Work out the Makefile path
    if cmake:
        # Set cmakelists_path to the root of the test directory. We're assuming this
        # is the parent of the directory named "bin".
        splitpath = Path(xe_path).resolve().parts
        bindex = splitpath.index("bin")
        path = Path(*splitpath[:bindex])
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
        if not cmake:
            return (False, msg)

    # Copy the environment, to avoid modifying the env of the current shell
    my_env = os.environ.copy()
    if env:
        for key in env:
            my_env[key] = str(env[key])

    if cmake:
        make_cmd = ["cmake", "-B", f"bin/{bin_child}"]
        build_cmd = ["cmake", "--build", f"bin/{bin_child}"]

        if clean_only:
            build_cmd += ["--target", "clean"]
            do_clean = False
        if do_clean:
            build_cmd += ["--clean-first"]

        if silent:
            output_args = {"stderr":subprocess.DEVNULL, "stdout":subprocess.DEVNULL}
        else:
            output_args = {"stderr":subprocess.STDOUT}

        subprocess.run(make_cmd, cwd=path, env=my_env, **output_args)
        subprocess.run(build_cmd, cwd=path, env=my_env, **output_args)

    else:
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
        if not silent:
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


def do_run_pyxsim(xe, simargs, appargs, simthreads, plugins=None):
    xsi = pyxsim.Xsi(xe_path=xe, simargs=simargs, appargs=appargs)
    for x in simthreads:
        xsi.register_simthread(x)
    if plugins:
        for plugin in plugins:
            xsi.register_plugin(plugin)
    xsi.run()
    xsi.terminate()


def run_with_pyxsim(
    xe,
    simthreads,
    simargs=[],
    appargs=[],
    timeout=600,
    plugins=[]
):

    p = multiprocessing.Process(
        target=do_run_pyxsim, args=(xe, simargs, appargs, simthreads, plugins)
    )
    p.start()
    p.join(timeout=timeout)
    if p.is_alive():
        sys.stderr.write("Simulator timed out\n")
        p.terminate()


def run_tester(caps, tester_list):
    result = []
    for i, ele in enumerate(caps):
        ele.remove("")
        if tester_list[i] != "Build Failed":
            result.append(tester_list[i].run(ele))
        else:
            result.append(False)
    return result


class SimThread:
    def run(self, _) -> None:
        pass

    def wait(self, f:int) -> None:
        self.xsi._user_wait(f)

    def wait_for_port_pins_change(self, ps:Sequence[str]) -> None:
        self.xsi._wait_for_port_pins_change(ps)

    def wait_for_next_cycle(self) -> None:
        self.xsi._wait_for_next_cycle()

    def wait_until(self, t:int) -> None:
        self.xsi._wait_until(t)
