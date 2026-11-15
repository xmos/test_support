# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
import os
import re
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from Pyxsim._process import run_command


class SessionError(AssertionError):
    """The application, xrun or its teardown failed."""


class SessionTimeout(SessionError):
    """A deadline expired before the application finished or produced the awaited output."""


def _output_matcher(match):
    if isinstance(match, str):
        return lambda line: match in line
    if isinstance(match, re.Pattern):
        return lambda line: match.search(line) is not None
    if callable(match):
        return match
    raise TypeError("output matcher must be a string, compiled regex or callable")


class Session:
    """Flash or run an xcore application; when attached, capture its output until terminated.

    ``attach`` selects how xrun stays attached: ``None`` (launch and return), ``"io"`` (JTAG),
    ``"xscope"`` or ``"xscope_app"`` (xSCOPE server on ``self.xscope_port``).

    While attached, stdout and stderr are read continuously, so an application's output can
    never fill a pipe and block it. ``lines`` and ``output`` give what has arrived so far.
    ``wait()`` waits for an application that finishes by itself and ``wait_for_output()`` for
    one that reports a result and keeps running; both take a deadline. Leaving the context
    stops xrun and reconnects with xgdb to stop the target.

    ``timeout`` bounds xflash, an unattached xrun, and is the default deadline of ``wait()``
    and ``wait_for_output()``. ``max_runtime`` requests a stop that many seconds after launch
    and forcibly stops an unresponsive xrun after ``stop_grace``, whatever the test is doing;
    teardown then raises SessionTimeout.

    ``log_path`` keeps the output in a file, written as it arrives, and must not alias the
    executable. XE and log paths are resolved relative to the caller, not ``cwd``.
    Log write failures do not stop capture; they are reported after cleanup.
    ``cwd`` is where an application's host file I/O is resolved.
    ``xscope_io_only`` adds ``--xscope-io-only`` to ``attach="xscope"``; do not set it for an
    application that uses host file system calls.

    ``appargs`` are command-line arguments for the application, which must be built with
    ``-fcmdline-buffer-bytes`` large enough for them and the executable's path.
    """

    # Seconds to wait for xrun after each of a polite and a forced stop.
    stop_grace = 10
    xgdb_timeout = 120

    def __init__(self, xe_path, adapter_id, attach=None, timeout=60, xflash=False, writeall=False,
                 target=None, *, log_path=None, cwd=None, xscope_io_only=False, max_runtime=None,
                 appargs=None):
        xe_path = Path(xe_path).resolve()
        assert xe_path.exists()
        assert attach in [None, "io", "xscope", "xscope_app"]
        assert not xscope_io_only or attach == "xscope", "xscope_io_only requires attach='xscope'"

        self.xe_path = xe_path
        self.attach = attach
        self.adapter_id = adapter_id
        self.proc = None
        self.proc_stdout = None
        self.proc_stderr = None
        self.proc_returncode = None
        self.timeout = timeout
        self.xflash = xflash
        self.writeall = writeall
        self.target = target
        self.log_path = None if log_path is None else Path(log_path).resolve()
        self._check_log_path()
        self.cwd = cwd
        self.xscope_io_only = xscope_io_only
        self.appargs = [str(arg) for arg in appargs or []]
        assert not self.appargs or not xflash, "appargs cannot be used with xflash"
        self.max_runtime = max_runtime

        self._log = None
        self._log_error = None
        self._cond = threading.Condition()
        self._streams = {}
        self._lines = []
        self._line_sources = []
        self._next_line = 0
        self._readers = []
        self._watchdog = None
        self._watchdog_cancel = threading.Event()
        self._stop_lock = threading.Lock()
        self._stopping = False
        self._overran = False
        self._stopped_by_us = False
        self._exit_reported = False

    # ---- Output ------------------------------------------------------------------------

    @property
    def lines(self):
        """Complete lines received so far from stdout and stderr, in order of arrival."""
        with self._cond:
            return list(self._lines)

    @property
    def output(self):
        """``lines`` as one string."""
        return "".join(line + "\n" for line in self.lines)

    def _check_log_path(self):
        if self.log_path is not None and (
                self.log_path == self.xe_path or
                (self.log_path.exists() and self.log_path.samefile(self.xe_path))):
            raise ValueError("log_path must not overwrite the executable")

    def _open_log(self):
        if self.log_path is not None and self._log is None:
            self._check_log_path()
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            # Open without truncating, then check the actual inode too. A link
            # changed after construction must not turn the log into the XE file.
            fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o666)
            try:
                if os.path.samestat(os.fstat(fd), self.xe_path.stat()):
                    raise ValueError("log_path must not overwrite the executable")
                os.ftruncate(fd, 0)
                self._log = os.fdopen(fd, "wb")
            except BaseException:
                os.close(fd)
                raise

    def _close_log(self):
        if self._log is not None:
            try:
                self._log.close()
            except (OSError, ValueError) as error:
                self._log_error = self._log_error or error
            self._log = None

    def _write_log(self, *chunks):
        if self._log is not None and self._log_error is None:
            try:
                for chunk in chunks:
                    self._log.write(chunk)
                self._log.flush()
            except (OSError, ValueError) as error:
                # Disable further log writes, not pipe reads. Report the error
                # only after xrun/helpers are stopped and the target recovered.
                self._log_error = error

    def _log_text(self, *texts):
        self._open_log()
        self._write_log(*((text or "").encode("utf-8", errors="replace") for text in texts))

    def _read(self, name, stream):
        pending = bytearray()
        try:
            while True:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    break
                pending.extend(chunk)
                with self._cond:
                    self._streams[name].extend(chunk)
                    self._write_log(chunk)
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending[:] = rest
                        self._lines.append(line.decode("utf-8", errors="replace").rstrip("\r"))
                        self._line_sources.append(name)
                    self._cond.notify_all()
        except (OSError, ValueError):
            pass  # The pipe was closed during teardown.
        finally:
            with self._cond:
                if pending:
                    self._lines.append(pending.decode("utf-8", errors="replace").rstrip("\r"))
                    self._line_sources.append(name)
                self._cond.notify_all()

    def _readers_alive(self):
        return any(reader.is_alive() for reader in self._readers)

    def _text(self, name):
        with self._cond:
            return self._streams[name].decode("utf-8", errors="replace")

    def _describe(self):
        return f"stdout:\n{self._text('stdout')}\nstderr:\n{self._text('stderr')}\n"

    # ---- Waiting -----------------------------------------------------------------------

    def wait(self, timeout=None):
        """Wait for an attached application to finish by itself.

        Returns once xrun has exited with status zero. Raises SessionTimeout at the deadline
        and SessionError for any other exit status.
        """
        assert self.proc is not None, "wait() requires an attached application"
        timeout = self.timeout if timeout is None else timeout
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SessionTimeout(
                f"Application did not finish within {timeout}s\n{self._describe()}"
            ) from None
        self._join_readers()
        self._check_overrun()
        self._exit_reported = True
        if self.proc.returncode != 0:
            raise SessionError(
                f"xrun exited with status {self.proc.returncode}\n{self._describe()}"
            )

    def wait_for_output(self, match, timeout=None, *, stream=None):
        """Wait for a line of output and return it, leaving the application running.

        ``match`` is a substring, a compiled regular expression (searched) or a function of
        the line. Each call continues after the line the previous call returned. Raises
        SessionTimeout at the deadline, and SessionError if the output ends first.
        By default both streams are considered; stream="stdout" or "stderr"
        selects one. Match callbacks must return promptly and run without holding
        the output-reader lock. Output never extends the absolute deadline.
        """
        assert self.proc is not None, "wait_for_output() requires an attached application"
        matches = _output_matcher(match)
        if stream not in (None, "stdout", "stderr"):
            raise ValueError("stream must be stdout, stderr or None")
        timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            with self._cond:
                self._check_overrun()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SessionTimeout(
                        f"Awaited output did not arrive within {timeout}s\n{self._describe()}"
                    )
                if self._next_line < len(self._lines):
                    line = self._lines[self._next_line]
                    source = self._line_sources[self._next_line]
                    self._next_line += 1
                elif not self._readers_alive():
                    break
                else:
                    self._cond.wait(min(remaining, 0.1))
                    continue
            if stream is None or stream == source:
                matched = matches(line)
                if time.monotonic() >= deadline:
                    raise SessionTimeout(
                        f"Awaited output did not arrive within {timeout}s\n{self._describe()}"
                    )
                self._check_overrun()
                if matched:
                    return line
        self._check_overrun()
        raise SessionError(f"Output ended before the awaited line\n{self._describe()}")

    def _check_overrun(self):
        if self._overran:
            raise SessionTimeout(
                f"Application stopped after max_runtime of {self.max_runtime}s\n{self._describe()}"
            )

    # ---- xSCOPE port -------------------------------------------------------------------

    # Get an available port number by binding a socket then closing it (assume nothing else will take it before it is used by xrun)
    def get_xscope_port_number(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("localhost", 0))
            sock.listen(1)
            port = sock.getsockname()[1]
        self.xscope_port = port

    def _sleep_while_running(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                self._join_readers()
                assert 0, (
                    f"xrun exited with status {self.proc.returncode} before its xscope port "
                    f"{self.xscope_port} was ready\n{self._describe()}"
                )
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))

    def wait_for_xscope_port(self, timeout=10):
        # Wait to allow the xrun command to start running
        self._sleep_while_running(3)

        for _ in range(timeout):
            self._sleep_while_running(1)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind(("localhost", self.xscope_port))
                except OSError:
                    # Failed to bind, so xrun has this port open and is ready to use
                    return

        assert 0, f"xscope port {self.xscope_port} not ready after {timeout}s"

    # ---- Launch ------------------------------------------------------------------------

    def _run_to_completion(self, name, cmd):
        self._open_log()
        try:
            ret = run_command(cmd, timeout=self.timeout, cwd=self.cwd)
        except subprocess.TimeoutExpired as error:
            self._log_text(*(x.decode(errors="replace") if isinstance(x, bytes) else x
                             for x in (error.stdout, error.stderr)))
            raise
        self.proc_stdout = ret.stdout
        self.proc_stderr = ret.stderr
        self._log_text(ret.stdout, ret.stderr)
        assert ret.returncode == 0, (
            f"{name} failed, cmd: {cmd}\n"
            + f"stdout:\n{ret.stdout}\n"
            + f"stderr:\n{ret.stderr}\n"
        )

    def __enter__(self):
        if self.xflash:
            if not self.writeall:
                xflash_cmd = [
                    "xflash",
                    "--adapter-id",
                    self.adapter_id,
                    "--factory",
                    self.xe_path,
                ]
            else:
                assert self.target is not None, "Error: target unspecified when doing xflash --write-all"
                xflash_cmd = [
                    "xflash",
                    "--adapter-id",
                    self.adapter_id,
                    "--write-all",
                    self.xe_path,
                    "--target",
                    self.target
                ]
            try:
                self._run_to_completion("xflash", xflash_cmd)
            finally:
                self._close_log()
            return self

        xrun_cmd = ["xrun", "--adapter-id", self.adapter_id]
        if self.attach == "io":
            xrun_cmd.append("--io")
        elif self.attach == "xscope":
            xrun_cmd.append("--xscope")
            if self.xscope_io_only:
                xrun_cmd.append("--xscope-io-only")
        elif self.attach == "xscope_app":
            self.get_xscope_port_number()
            xrun_cmd.append("--xscope-port")
            xrun_cmd.append(f"localhost:{self.xscope_port}")
        if self.appargs:
            # Application arguments are only passed on after --args, directly before the executable.
            xrun_cmd.append("--args")
        xrun_cmd.append(self.xe_path)
        xrun_cmd.extend(self.appargs)

        if not self.attach:
            # If not attaching, wait for the xrun command to complete
            try:
                self._run_to_completion("xrun", xrun_cmd)
            except BaseException as error:
                self._teardown_after(error)
                raise
            finally:
                self._close_log()
            return self

        # If attaching, store the Popen object to terminate it later. Anything that fails
        # from here on must not leave xrun running.
        try:
            self._open_log()
            self._streams = {"stdout": bytearray(), "stderr": bytearray()}
            # Its own process group, so that the helpers xrun starts can be stopped with it.
            group = {} if os.name == "nt" else {"start_new_session": True}
            self.proc = subprocess.Popen(
                xrun_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.cwd, **group
            )
            for name, stream in (("stdout", self.proc.stdout), ("stderr", self.proc.stderr)):
                reader = threading.Thread(target=self._read, args=(name, stream), daemon=True)
                self._readers.append(reader)
                reader.start()
            if self.max_runtime is not None:
                self._watchdog = threading.Timer(self.max_runtime, self._overrun)
                self._watchdog.daemon = True
                self._watchdog.start()

            if self.attach == "xscope_app":
                self.wait_for_xscope_port()
        except BaseException as error:
            self._teardown_after(error)
            raise

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is None:
            self.terminate()
        else:
            self._teardown_after(exc_val)

    def _teardown_after(self, error):
        """Tear down without replacing the failure that is already being reported."""
        try:
            self.terminate()
        except Exception as teardown_error:
            note = f"Teardown of XTAG {self.adapter_id} also failed: {teardown_error}"
            if hasattr(error, "add_note"):
                error.add_note(note)
            else:
                print(note)

    # ---- Teardown ----------------------------------------------------------------------

    def _signal(self, force=False):
        try:
            if os.name == "nt":
                self.proc.kill() if force else self.proc.terminate()
            else:
                os.killpg(self.proc.pid, signal.SIGKILL if force else signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

    def _overrun(self):
        with self._stop_lock:
            if (self._stopping or self._watchdog_cancel.is_set() or
                    self.proc is None or self.proc.poll() is not None):
                return
            self._overran = True
            self._stopped_by_us = True
            self._signal()
        if not self._watchdog_cancel.wait(self.stop_grace):
            with self._stop_lock:
                if not self._stopping:
                    # Kill the group even if xrun exited but left helpers alive.
                    self._signal(force=True)

    def _join_readers(self, timeout=5):
        deadline = time.monotonic() + timeout
        for reader in self._readers:
            reader.join(max(0, deadline - time.monotonic()))

    def _stop_process(self):
        """Stop xrun, forcibly if it does not respond. Returns a description of any failure."""
        self._watchdog_cancel.set()
        if self._watchdog is not None:
            self._watchdog.cancel()
        problem = None
        with self._stop_lock:
            self._stopping = True
            if self.proc.poll() is None:
                self._stopped_by_us = True
                self._signal()
                try:
                    self.proc.wait(timeout=self.stop_grace)
                except subprocess.TimeoutExpired:
                    self._signal(force=True)
                    try:
                        self.proc.wait(timeout=self.stop_grace)
                    except subprocess.TimeoutExpired:
                        problem = f"xrun (pid {self.proc.pid}) could not be stopped"
            if os.name != "nt":
                # Helpers that outlived xrun keep the adapter and pipes open.
                self._signal(force=True)
        self._join_readers()
        if self._readers_alive():
            problem = problem or "Output pipes remained open after stopping xrun"
        # Even readers that reached EOF leave their file objects open. Close both
        # handles on every path, rather than relying on garbage collection.
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
        self.proc_stdout = self._text("stdout")
        self.proc_stderr = self._text("stderr")
        self.proc_returncode = self.proc.returncode
        self._close_log()
        return problem

    def terminate(self):
        problem = None
        if self.proc:
            problem = self._stop_process()
        else:
            self._close_log()
        # Stop an application that was running by breaking in with xgdb
        # Allow a long timeout here because sometimes an XTAG can get stuck in a USB transaction when xrun
        # is killed, and this connect via xgdb can recover it but it takes a while to reboot the XTAG
        try:
            ret = subprocess.run(
                ["xgdb", "-ex", f"connect --adapter-id {self.adapter_id}", "--batch"],
                capture_output=True,
                text=True,
                timeout=self.xgdb_timeout,
            )
        except subprocess.TimeoutExpired:
            assert 0, f"Connecting to XTAG {self.adapter_id} timed out"

        assert ret.returncode == 0, (
            f"Connecting to XTAG {self.adapter_id} failed\n"
            + f"stdout:\n{ret.stdout}\n"
            + f"stderr:\n{ret.stderr}\n"
        )
        assert problem is None, problem
        if self._overran:
            self._overran = False  # Report it once; a second terminate() is then harmless.
            raise SessionTimeout(
                f"Application stopped after max_runtime of {self.max_runtime}s\n"
                f"stdout = {self.proc_stdout}\nstderr = {self.proc_stderr}"
            )
        # when terminating the xrun process it returns returncode 255, which is the same as the returncode when the application crashes with an exception.
        # that's why we cant use returncode for checking for error, and depend on parsing the stderr for errors instead
        failure_flag_strings = ['ET_ECALL', 'Application exception']
        assert not any(f in (self.proc_stderr or "") for f in failure_flag_strings), f"xrun process failed\nstdout = {self.proc_stdout}\nstderr = {self.proc_stderr}"
        # An exit that was not requested here is different: its status is xrun's own.
        if self.proc and not self._stopped_by_us and not self._exit_reported:
            self._exit_reported = True
            assert self.proc_returncode == 0, (
                f"xrun exited with status {self.proc_returncode}\n"
                f"stdout = {self.proc_stdout}\nstderr = {self.proc_stderr}"
            )
        if self._log_error is not None:
            raise SessionError(f"Writing log {self.log_path} failed: {self._log_error}")
