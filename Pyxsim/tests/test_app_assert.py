# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""
Check that Pyxsim reports a failure when the simulated application asserts.

The firmware in ``test_app_assert/src/app.c`` prints a line, waits briefly and
then calls ``xassert(0)``. Because it is built with
``-DLIBXCORE_XASSERT_IS_ASSERT``, the assert ends the simulation with a
non-zero result instead of trapping silently.

``Pyxsim.run_on_simulator_()`` must turn that failed simulation into a return
value of ``False``. If it returns ``True``, a crashing application would be
reported as a passing test, so this test fails.

Run from this directory with the XTC tools sourced (the app targets
``XK-EVK-XU416``)::

    pytest -v test_app_assert.py

Instruction and VCD traces are written to ``logs/test_app_assert/``.
"""
import pytest
import re
import subprocess
from pathlib import Path
import fcntl
import Pyxsim as px
from contextlib import nullcontext

def get_test_log_dir(test_name: str) -> Path:
    """
    Create ``logs/<test_name>`` next to this file and return its path.

    Characters other than letters, digits, ``_``, ``.`` and ``-`` in
    ``test_name`` are replaced with ``_``. A file lock guards the directory
    creation so that parallel pytest workers (pytest-xdist) don't race.
    """
    logs_root = Path(__file__).parent / "logs"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", test_name)
    test_log_dir = logs_root / safe_name

    logs_root.mkdir(exist_ok=True)
    lock_file = logs_root / ".mkdir.lock"
    with open(lock_file, "w", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        test_log_dir.mkdir(parents=True, exist_ok=True)
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    return test_log_dir

def get_xsim_args(
    test_name,
    vcd_trace=False,
    instr_trace=False,
    max_cycles=None,
    enable_xscope=True,
):
    """
    Build the list of xsim arguments for a test run.

    Trace output files go in the directory returned by
    ``get_test_log_dir(test_name)``.

    :param test_name: Name used for the log directory.
    :param vcd_trace: Write a VCD trace of tile[0] (ports, instructions,
        functions, cores, cycles, clock blocks and pads) to ``vcd_trace.vcd``.
    :param instr_trace: Write an instruction trace, including fnops, to
        ``instr_trace.txt``.
    :param max_cycles: Stop the simulation after this many cycles. ``None``
        means no limit.
    :param enable_xscope: Record xSCOPE output offline to
        ``xscope_trace.xmt``.
    :returns: List of arguments to pass as ``simargs``.
    """
    output_dir = get_test_log_dir(test_name)

    sim_args = []
    if enable_xscope:
        xscope_file = f"{output_dir}/xscope_trace.xmt"
        sim_args += ['--xscope', f'-offline {xscope_file}']
    if max_cycles is not None:
        sim_args += ['--max-cycles', str(max_cycles)]
    if instr_trace:
        instr_trace_file = f"{output_dir}/instr_trace.txt"
        sim_args += ['--trace-to', instr_trace_file, '--enable-fnop-tracing']
    if vcd_trace:
        vcd_trace_file = f"{output_dir}/vcd_trace.vcd"
        vcd_args  = f'-o {vcd_trace_file}'
        vcd_args += (f' -tile tile[0] -ports -ports-detailed -instructions'
                        ' -functions -cores -cycles -clock-blocks -pads')
        sim_args += ['--vcd-tracing', vcd_args]

    return sim_args

def test_app_assert(capfd):
    """
    A simulated app that hits ``xassert(0)`` must make
    ``run_on_simulator_()`` return ``False``.

    Steps:

    1. Configure the CMake build in ``build/`` (``run_on_simulator_`` then
       builds the app because ``do_xe_prebuild=True``).
    2. Simulate ``test_app_assert.xe`` for at most 10,000,000 cycles with
       instruction and VCD tracing on.
    3. Print the result and the captured simulator output, then check that
       the result is ``False``.
    """
    build_dir = Path(__file__).parent / "build"
    build_dir.mkdir(exist_ok=True)
    subprocess.run(
        ["cmake", "-G", "Unix Makefiles", "-S", str(Path(__file__).parent), "-B", str(build_dir)],
        check=True,
    )
    binary = Path(f'test_app_assert/bin/test_app_assert.xe')

    simargs = get_xsim_args(
        "test_app_assert",
        vcd_trace=True,
        enable_xscope=False,
        instr_trace=True,
        max_cycles=10000000,
    )
    with capfd.disabled():
        print(f"Running simulator with cmd: {' '.join(simargs)}")
    #cap_context = capfd.disabled()
    cap_context = nullcontext()
    with cap_context:
        result = px.run_on_simulator_(  binary,
                                        simthreads=[],
                                        simargs=simargs,
                                        do_xe_prebuild=True,
                                        cmake=True,
                                        capfd=capfd,
                                        verbosity=2
                                    )

    out, err = capfd.readouterr()
    simulator_output = "\n".join([out, err])

    with capfd.disabled():
        print(f"{result=}")
        print("Simulator output:")
        print(simulator_output)

    assert result == False, f"ERROR: px.run_on_simulator_() returns result = True despite app crashing"