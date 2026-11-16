############
test_support
############

************
Introduction
************

``test_support`` provides shared Python infrastructure for XMOS simulation,
hardware execution and testbench code. It wraps the XSI simulator interface,
provides helper classes for simulator threads and plugins, implements comparison
testers, and includes common models used by library tests.

The main Python modules are:

* ``Pyxsim.pyxsim``: XSI wrapper, simulator thread support, plugin execution,
  and pin/port access helpers.
* ``Pyxsim.bus``: resolved wire and bus-driver model for Python testbenches.
* ``Pyxsim.testers``: output comparison and filtering helpers.
* ``Pyxsim.xe``: helpers for reading metadata from XE files.
* ``Pyxrun``: running an application on a board.

*****
Usage
*****

Install ``test_support`` into the Python environment used by the tests. During
library development this is normally done from the repository checkout in
editable mode:

.. code-block:: console

    python -m pip install -e .

Activate the XTC Tools environment before importing these packages. A known
limitation is that package imports load XSI immediately, even for output checkers,
bus models and hardware helpers that do not themselves use the simulator.

Use ``Pyxsim.run()`` or ``Pyxrun.run()`` to run an already-built ``.xe`` and
optionally compare its stdout using the same tester interface. Neither function
builds the application or reserves hardware. Execution/comparison failures return
``False``; assertion-based checkers still raise on mismatch. A successful
assertion-based comparison returns ``True`` from either runner. Configuration and
launch errors can raise; use ``assert ...run(...)`` in tests rather than ignoring
the result. Without a tester, success establishes execution, not functional
correctness.

A typical simulator pytest test constructs any required simulator threads,
creates a tester for the
expected output, and passes pytest's ``capfd`` fixture so simulator output can be
captured and replayed consistently.

.. code-block:: python

    from pathlib import Path

    import Pyxsim
    from Pyxsim.testers import ComparisonTester


    def test_example(capfd):
        xe = Path("bin/example.xe")
        tester = ComparisonTester(["ready", "done"])

        assert Pyxsim.run(
            xe,
            tester=tester,
            capfd=capfd,
        )

Pass ``simargs`` for xsim command-line arguments and ``appargs`` for arguments
passed to the simulated application. A tester requires ``capfd`` with
``Pyxsim.run()``; without it the runner raises rather than silently skipping
comparison. Pyxrun captures its own output and does not require ``capfd``.

Building from a test
####################

``Pyxsim.run()`` and ``Pyxrun.run()`` do not build. A test that must build what
it is about to run calls ``build()`` first. ``Pyxsim.build()`` and
``Pyxrun.build()`` are the same function:

.. code-block:: python

    Pyxsim.build(xe)
    assert Pyxsim.run(xe, tester, capfd=capfd)

    Pyxrun.build(xe)
    assert Pyxrun.run(xe, tester, adapter_id=adapter_id)

``build()`` builds the one target that produces ``xe`` in a CMake build
directory that has already been configured; it does not run the configure step.
The build directory defaults to the nearest ``build`` directory above the
executable, or pass ``build_dir``. A failure raises ``BuildError`` with the build
output, so it is not mistaken for a failed comparison.

On timeout or interruption, the build command and its helpers are stopped before
failure is reported, so an abandoned compiler cannot race a retry. This uses a
dedicated process group on POSIX and ``taskkill /T`` on Windows. Process cleanup
has a separate bounded wait.

Use it for two kinds of variation:

* A value from a fixed list, such as a channel count: declare one build
  configuration for each value in ``CMakeLists.txt``, with the value as a compiler
  definition, and have the test build and run the matching executable. Only the
  configurations a run selects are built. Reading the list from one file in both
  CMake and pytest keeps the two in step.
* A value chosen when the test runs, such as a random seed: compiler definitions
  are fixed when CMake configures, so the test writes the value to a header and
  then calls ``build()``. Give each configuration its own header, in the build
  directory, so that cases run in parallel do not share a file.

A value that the application only needs when it runs can instead be passed as a
command-line argument with ``appargs``, which needs no rebuild:

.. code-block:: python

    assert Pyxsim.run(xe, tester, capfd=capfd, appargs=[str(seed)])

``Pyxrun.run()`` and ``Pyxrun.Session`` take ``appargs`` in the same way for a
run on hardware. The application reads it from ``argv`` and must be built with
``-fcmdline-buffer-bytes=N``. Without that option it sees no arguments. ``N`` must
be large enough for the arguments and the executable's full path, which is
``argv[0]``; an application whose buffer is too small traps as it starts. A value
that sizes an array or selects code still has to be a compiler definition.

Simulator API compatibility
############################

Existing calls do not need to migrate to ``run()`` or ``build()``. The legacy
simulator entry points retain their positional arguments, optional build
arguments and checker return values (including ``None`` from an assertion-based
checker). The new ``run()`` normalises a successful ``None`` result to ``True``
and requires ``capfd`` when a tester is supplied; those stricter rules do not
apply to the legacy wrappers.

``Pyxsim.Xsi``, ``Pyxsim.XsiRemote`` and ``Pyxsim.pyxsim`` remain available through
attribute access, named imports and ``from Pyxsim import *``, with the same
eager XSI imports as upstream.

``Pyxsim.run_on_simulator_()`` is deprecated and emits ``DeprecationWarning``;
replace it with ``Pyxsim.run()``. Its behaviour and checker return value are
unchanged, and no removal version is scheduled.

``Pyxsim.run_on_simulator()``, which builds the executable and then runs it, is
not deprecated: ``run()`` deliberately does not build.

*****************
Comparison Tester
*****************

``ComparisonTester`` compares captured application output with expected lines. The expected
output can be supplied as a list of strings, a newline-separated string, or a
file object.

By default, comparison is ordered and exact. Set ``regexp=True`` to treat each
expected line as a regular expression. Set ``ordered=False`` when the expected
lines may appear in any order.

.. code-block:: python

    tester = ComparisonTester(
        [r"status: [0-9]+", "done"],
        regexp=True,
        ordered=True,
    )

Use ``ignore`` to suppress known non-deterministic or irrelevant lines:

.. code-block:: python

    tester = ComparisonTester(
        ["done"],
        ignore=[r"timestamp: .*"],
    )

Common xsim multidrive diagnostics are suppressed by default. Pass
``suppress_multidrive_messages=False`` if a test needs to assert on those
messages directly.

When pytest output capture is passed via ``capfd``, Pyxsim captures simulator and
simthread output and replays it according to the pytest verbosity level:

* ``pytest ...`` keeps output compact and reports pass/fail details.
* ``pytest ... -v`` enables verbose tester output, including captured
  ``OUTPUT:`` lines from the simulator stream.
* ``pytest ... -vv`` also prints the matching ``GOLDEN:`` lines from
  ``ComparisonTester`` and is useful when diagnosing mismatches.

****************
Hardware Running
****************

Use ``Pyxrun.run()`` for a finite application, or one that keeps running and
reports completion, on a board selected by its adapter ID. Activate the XTC Tools
environment first. It opens a ``Session`` for execution, cleanup and target
recovery; it is not a separate process runner.

For an application that prints its result and exits:

.. code-block:: python

    import Pyxrun
    from Pyxsim.testers import ComparisonTester


    def test_hardware(adapter_id, tmp_path):
        assert Pyxrun.run(
            "bin/example.xe", adapter_id=adapter_id, timeout=60,
            tester=ComparisonTester(["ready", "done"]),
            log_path=tmp_path / "xrun.log",
        )

For an application that reports a result and keeps running:

.. code-block:: python

    assert Pyxrun.run(
        "bin/player.xe", adapter_id=adapter_id, timeout=120,
        until=lambda line: line == "PASS: two complete plays",
        tester=ComparisonTester(["ready", "PASS: two complete plays"]),
        log_path=tmp_path / "player.log",
    )

``until`` is a substring, compiled regular expression or callable predicate,
evaluated against each stdout line. A predicate can validate a complete report
and return true only after the required observation; it must return promptly.
Exceptions from it propagate after cleanup, including assertion failures and
interruptions. The deadline is absolute and is not extended by output. Exiting
before the observation fails, even with exit status zero; stderr alone cannot
satisfy completion. An intentional stop does not hide recognised target
exceptions.

With ``until``, comparison includes stdout only through the matching line.
Additional output, including shutdown diagnostics, stays in the log but does
not become golden output. Without ``until``, comparison uses all captured stdout.

Set ``echo=False`` to avoid replaying stdout, for example when a benchmark emits
a large PCM dump. The complete capture remains available through ``log_path``,
and checker input is unchanged. Stderr and execution failures are still reported.
A completion callback can print selected lines as they arrive without a second
replay at the end.

``run()`` defaults to full xSCOPE, including host-file servicing. Set
``xscope_io_only=True`` only when no host-file system calls are needed, or use
``attach="io"`` explicitly for legacy JTAG I/O. It compares stdout using the same
line normalisation as Pyxsim; stderr is kept as diagnostics, not golden output.
Comparison happens after cleanup and recovery. The execution timeout defaults
to 600 seconds; separate bounded cleanup/recovery waits also apply. XE and log
paths are resolved relative to the caller, independently of ``cwd``.

Interactive hardware sessions
#############################

``Pyxrun.Session`` is the lifecycle used by ``run()``. Use it directly when a test
needs several interactions with a running application, xSCOPE-server attachment
or flashing. It stops the application when its context ends and provides direct
access to captured output. There is no second runner implementation.

For example, wait for readiness, perform host-side interactions, then wait for
the final result. Leaving the context stops the application:

.. code-block:: python

    from Pyxrun import Session

    with Session("bin/player.xe", adapter_id, attach="xscope") as app:
        app.wait_for_output("ready", timeout=30)
        # Perform the test's host-side interactions with the running device.
        app.wait_for_output("PASS: two complete plays", timeout=120)

``wait_for_output()`` takes a substring, a compiled regular expression or a
function of the line, and continues after the line it last returned. It observes
both streams by default; pass ``stream="stdout"`` or ``stream="stderr"`` to
select one. An exception raised by the function ends the run. Callbacks run
without holding the reader lock and must return promptly.

``attach`` selects how xrun stays attached:

* ``None``: launch the application and return; nothing is captured.
* ``"xscope"``: xSCOPE output. The application and board must be configured for
  xSCOPE. Add ``xscope_io_only=True`` unless the application uses host file
  system calls.
* ``"io"``: JTAG I/O. This halts the tile for every transfer, so prefer xSCOPE.
* ``"xscope_app"``: an xSCOPE server for a host program, on ``app.xscope_port``.

``xflash=True`` programs the application into flash instead of running it.

While attached, output is read continuously, so a large amount of it cannot
block the application. ``lines`` and ``output`` give what has arrived so far, and
``log_path`` keeps it in a file as it arrives, whatever the outcome. ``cwd`` is
the working directory of xrun, where an application's host file I/O is resolved.
XE and log paths resolve relative to the caller, independently of ``cwd``, also
when using ``Session`` directly. A log path must not name the executable, through
either the same path, a symlink or a hard link; this is checked before truncation.
If writing, flushing or closing a log fails, output capture continues and the
error is reported after process cleanup and target recovery. An existing test
failure remains the primary exception.

Session failures raise ``SessionError``, an ``AssertionError``:

* ``wait()`` and ``wait_for_output()`` raise ``SessionTimeout`` at their
  deadline, which defaults to ``timeout``.
* ``max_runtime`` requests a stop that many seconds after launch and forcibly
  stops an unresponsive launcher after a bounded grace period, even while the
  test is blocked in host-side work. Normal context teardown cancels escalation.
* xrun exiting by itself with a failing status, or reporting a target
  exception, fails the test. A status caused by stopping it does not.

Leaving the context stops xrun, forcibly if it does not respond, together with
any helper it started, and then reconnects with xgdb to stop the target. If the
test has already failed, a teardown failure is added to that exception as a
note instead of replacing it. On Windows only the xrun process itself is
stopped.

An unattached xrun that fails during startup also goes through target recovery:
its failed ``__enter__()`` cannot rely on Python calling ``__exit__()``. Finite
tool commands use the same process-tree cleanup as builds on timeout.

``Session`` does not reserve boards. Pass it an adapter ID that the test
already holds, and keep that reservation until the context has ended.

Deprecated hardware imports
###########################

``hardware_test_tools.XcoreApp`` is a deprecated compatibility import from the
private audio harness. Its class and exceptions alias the corresponding
``Pyxrun.Session`` objects; there is no second implementation. Use
``Pyxrun.run()`` for finite/observation-based tests or ``Pyxrun.Session`` for
interactive sessions. No removal version is scheduled.

*****************
Simulator Threads
*****************

Simulator threads let Python testbench code interact with the simulated xCORE
application while xsim is running. Define a class derived from
``Pyxsim.SimThread`` and implement ``run()``.

.. code-block:: python

    import Pyxsim


    class ExampleSimThread(Pyxsim.SimThread):
        def run(self):
            trigger = "tile[0]:XS1_PORT_1G"
            response = "tile[0]:XS1_PORT_1H"

            self.wait_for_port_pins_change([trigger])
            value = self.xsi.sample_port_pins(response)
            self.xsi.drive_port_pins(response, 1 - value)

Common simthread helpers are:

* ``wait_for_port_pins_change(ports)``: wait until one of the supplied ports
  changes drive state or value.
* ``wait_for_next_cycle()``: yield until the simulator advances.
* ``wait_until(time)``: wait until the simulator reaches an absolute time.
* ``wait(predicate)``: wait until a Python predicate returns true.
* ``xsi.drive_port_pins(port, value)``: drive a simulator port from Python.
* ``xsi.sample_port_pins(port)``: sample the current value of a simulator port.
* ``xsi.is_port_driving(port)``: test whether the xCORE application is actively
  driving a port pin.

*************************
XSI Port Sampling Warning
*************************

``sample_port_pins`` should not be treated as a pure observation in all
testbench situations. Sampling a port through XSI can affect Python-driven port
state in the simulator. This matters when Python code is also driving a resolved
value onto the same port, for example when emulating pull-ups or mirroring a
resolved bus model into xsim.

If a caller only wants to know whether the xCORE target is actively driving a
port, check ``is_port_driving()`` before calling ``sample_port_pins()``. Only
sample when the target is known to be driving; otherwise keep the corresponding
Python-side bus driver released.

.. code-block:: python

    if xsi.is_port_driving(sda_port):
        target_value = xsi.sample_port_pins(sda_port)
        target.sda.drive(target_value)
    else:
        target.sda.release()

This avoids accidentally disturbing the Python-driven resolved value while still
allowing target-driven values to be mirrored into the Python bus model.

******************
Resolved Bus Model
******************

``Pyxsim.bus`` models digital wires that may be driven by multiple named bus
participants. It distinguishes high-Z release from hard-drive high so that tests
can model open-drain and push-pull behaviour and detect hard clashes.

Create physical wires and driver objects, then bind them with ``Bus``:

.. code-block:: python

    from Pyxsim.bus import Bus, BusDriver, BusMode, BusWire

    scl = BusWire("scl", mode=BusMode.PUSH_PULL, pullup_enabled=False)
    sda = BusWire("sda", mode=BusMode.OPEN_DRAIN, pullup_enabled=True)

    controller = BusDriver("controller")
    target = BusDriver("target")

    Bus([scl, sda], [controller, target])

    controller.scl.drive(1)
    controller.sda.release()
    target.sda.drive(0)

    value = sda.resolved_value()

The ``Bus`` constructor validates wire and driver names and binds each driver to
each wire. Wire handles are exposed as attributes on the driver, such as
``controller.sda``.

``DriveMode.HIGH_Z`` represents a released line driver. ``DriveMode.DRIVE_LOW``
and ``DriveMode.DRIVE_HIGH`` represent hard-driven values. When all drivers are
high-Z and pull-up is enabled, the wire resolves high. If any driver drives low,
the resolved value is low unless another driver is hard-driving high.

Use ``release(driver)`` when the testbench is handing ownership of a wire to
another bus participant. Use ``drive(driver, 1)`` only when the protocol phase
really requires a hard high drive. If the wire has a modeled pull-up, released
drivers can still resolve to a high value without being recorded as hard-driving
high.

A hard-low and hard-high combination is reported as ``hard_clash`` in the wire
snapshot. Hard-drive operations raise ``BusWireHardClash`` immediately if they
create a hard-low versus hard-high conflict. The exception includes the wire
name, resolved value, active low drivers, active high drivers, and the
driver/mode being applied.

*********************
Tracing and Debugging
*********************

Enable instruction tracing with ``instTracing=True`` and VCD tracing with
``vcdTracing=True`` when running a simulation. Trace files are written under the
``logs`` directory using the ``xsim_trace_<xe-name>`` prefix.

.. code-block:: python

    Pyxsim.run(
        xe,
        simthreads=[ExampleSimThread()],
        instTracing=True,
        vcdTracing=True,
    )

Use the ``timeout`` argument to bound long-running simulations. If the simulator
process does not exit before the timeout expires, Pyxsim terminates it and the
run fails.

*********************************************
Usage within the RTL verification environment
*********************************************

``test_support`` may be used with XSI and the RTL verification environment to
provide stimuli into the RTL testbench inputs and to capture (and check) the
testbench outputs. In this mode it calls the XSI API which makes remote
procedure calls (implemented with GRPC) to XSI server methods in the
``dpivpi`` layer, which resides in the RTL simulation process.
This layer can drive or read the values of nets within the RTL simulation.

The ``XSI_ENDPOINT`` environment variable must be set to put test_support in
RTL mode. It must contain the address of the RTL RPC server and port
number, for example:

.. code-block:: console

    XSI_ENDPOINT=192.168.1.4:49152

The RTL verification environment will launch a pytest process with this
environment variable set to point to the RPC server that is running witin the
RTL simulation.

The RTL verification environment will wait for the launched process to
terminate. A process exit code of 0 indicates success, and a non-0 code
inidicates failure. Timeouts are managed by the RTL verification environment
and it may kill the lauched process when any of its timeouts expire.

The XSI RTL verification environment runs with a granularity of 1 nanosecond.
This means that each call to XSI clock() will run the simulation for a period
of 1 nanosecond.

********
Examples
********

``examples/code_coverage`` contains a minimal example of processing xsim trace
data for source coverage.

Pyxsim example
##############

Introduction
************

This example demonstrates a simple use of a simthread to interact with
the simulated xcore application, with the following sequence:

* xcore app enables two 1-bit ports on tile 0, with a trigger on the
  second port changing value

* simthread waits for the value on the first port to change

* xcore app changes the value on the first port

* simthread sees the first port change value and then changes the
  value on the second port

* xcore app wakes up from waiting for the second port to change

Build and run
*************

.. code-block:: console

   cmake -G "Unix Makefiles" -B build
   xmake -C build

Install the test_support package using pip, and then run:

.. code-block:: console

   python example_pyxsim.py

The expected output is:

.. code-block:: console

   [xcore] Change value on p0
   [simthread] Transition seen on p0
   [simthread] Change value on p1
   [xcore] Transition seen on p1

VCD/instruction tracing
***********************

VCD and instruction tracing are enabled by default in ``example_pyxsim.py``.
The data is captured in the ``logs`` directory, and can be viewed with
a waveform viewer such as ``gtkwave``.
