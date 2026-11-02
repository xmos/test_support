import pytest
import re
import subprocess
from pathlib import Path
import fcntl
import Pyxsim as px
from contextlib import nullcontext

def get_test_log_dir(test_name: str) -> Path:
    """Create tests/logs/<test_name> safely and return it."""
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
                                    )

    out, err = capfd.readouterr()
    simulator_output = "\n".join([out, err])

    with capfd.disabled():
        print(f"{result=}")
        print("Simulator output:")
        print(simulator_output)

    assert result == True, f"ERROR: px.run_on_simulator_() returns result = False"