# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Bounded capture for finite tool commands, including their helper processes."""
import os
import signal
import subprocess


def _kill_tree(process):
    if os.name == "nt":
        # A new process group alone does not kill descendants on Windows.
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode and process.poll() is None:
                raise RuntimeError(f"Could not stop tool process tree: {result.stderr}")
        finally:
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_command(command, *, timeout, cwd=None, stderr=subprocess.PIPE):
    """Like a captured subprocess.run(), but stop helpers before reporting failure.

    POSIX helpers inherit a dedicated process group. Windows uses taskkill /T.
    Cleanup has its own bounded wait, separate from the execution timeout.
    """
    group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
             else {"start_new_session": True})
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                               text=True, errors="replace", cwd=cwd, **group)
    try:
        try:
            stdout, error_output = process.communicate(timeout=timeout)
        except BaseException as error:
            try:
                _kill_tree(process)
                stdout, error_output = process.communicate(timeout=5)
                if isinstance(error, subprocess.TimeoutExpired):
                    error.output, error.stderr = stdout, error_output
            except Exception as cleanup_error:
                message = f"Tool process cleanup also failed: {cleanup_error}"
                if isinstance(error, subprocess.TimeoutExpired):
                    output = error.output or ""
                    if isinstance(output, bytes):
                        output = output.decode(errors="replace")
                    error.output = f"{output}\n{message}"
                if hasattr(error, "add_note"):
                    error.add_note(message)
            raise
        if process.returncode:
            _kill_tree(process)
        return subprocess.CompletedProcess(command, process.returncode, stdout, error_output)
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
