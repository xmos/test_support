# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""
Pyxrun hardware execution

Flash or run an application on a board with the XTC tools, capture its output
and stop it again. Importing this package requires XTC Tools and XSI; no hardware
is accessed until a session is started.
"""
import math
from pathlib import Path
import sys
import time

from Pyxrun.session import Session, SessionError, SessionTimeout, _output_matcher
# Building is the same for the simulator and hardware: one implementation, exported by both.
from Pyxsim.cmake_build import BuildError, build

__all__ = ["build", "BuildError", "run", "Session", "SessionError", "SessionTimeout"]


def run(xe, tester=None, *, adapter_id, timeout=600, log_path=None, cwd=None,
        attach="xscope", xscope_io_only=False, until=None, appargs=None, echo=True):
    """Run an already-built application and optionally check its stdout.

    Return True on success and False on execution, recovery or comparison failure.
    Assertion-based checkers still raise on mismatch. Configuration and launch
    errors propagate, as do errors raised by completion callbacks. Checker input
    is normalised like Pyxsim's captured stdout; stderr is diagnostic output, not
    part of the comparison.

    Without ``until``, wait for a normal exit. With it, stop after a stdout line
    matches a substring, compiled regex or callable predicate. The predicate is
    called for each line and must return promptly. Comparison includes stdout
    only through the completion line; later output remains in the log. Ending
    output or reaching the deadline before completion fails even after exit zero.

    Execution defaults to full xSCOPE, including host-file servicing. The caller
    supplies an adapter ID and owns any reservation through teardown. ``timeout``
    bounds execution; Session's separate cleanup/recovery waits also apply.
    Relative XE and log paths are resolved before changing to ``cwd``.

    Set ``echo=False`` to suppress replaying captured stdout (for example a large
    PCM dump). Logs and checker input are unchanged; stderr and execution failures
    are still reported. A completion callback can print selected lines live.

    ``appargs`` are command-line arguments for the application, as for Pyxsim.run().
    The application must be built with ``-fcmdline-buffer-bytes`` large enough for
    them and the executable's path; without that option it sees no arguments.

    For multi-step interactive tests, xSCOPE-server attachment or flashing, use
    Session directly. This helper opens and closes that same lifecycle.
    """
    if not isinstance(adapter_id, str) or not adapter_id.strip():
        raise ValueError("adapter_id must be a non-empty string")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    if attach not in ("xscope", "io"):
        raise ValueError("run() requires attach='xscope' or 'io'; use Session for other modes")
    if xscope_io_only and attach != "xscope":
        raise ValueError("xscope_io_only requires attach='xscope'")
    if tester is not None and not callable(getattr(tester, "run", None)):
        raise TypeError("tester must have a callable run(lines) method")
    matches = None if until is None else _output_matcher(until)

    xe = Path(xe).resolve()
    if not xe.is_file():
        raise FileNotFoundError(xe)
    if log_path is not None:
        log_path = Path(log_path).resolve()
        if log_path == xe or (log_path.exists() and log_path.samefile(xe)):
            raise ValueError("log_path must not overwrite the executable")

    app = Session(xe, adapter_id, attach=attach, timeout=timeout,
                  log_path=log_path, cwd=cwd, xscope_io_only=xscope_io_only, appargs=appargs)
    observed = []
    callback_error = None

    def completed(line):
        nonlocal callback_error
        observed.append(line)
        try:
            return matches(line)
        except BaseException as error:
            callback_error = error
            raise

    deadline = time.monotonic() + timeout
    try:
        with app:
            remaining = max(0, deadline - time.monotonic())
            if until is None:
                app.wait(timeout=remaining)
            else:
                app.wait_for_output(completed, timeout=remaining, stream="stdout")
    except AssertionError as error:
        if error is callback_error:
            raise
        print(error, file=sys.stderr)
        return False

    # Teardown and target recovery finish before comparison (and before the
    # caller may release its reservation). Keep stderr out of golden output.
    if echo:
        print(app.proc_stdout or "", end="")
    print(app.proc_stderr or "", end="", file=sys.stderr)
    if tester is None:
        return True
    from Pyxsim import _split_capture_lines

    output = (app.proc_stdout or "") if until is None else "\n".join(observed)
    result = tester.run(_split_capture_lines(output))
    return True if result is None else bool(result)
