############
test_support
############

************
Introduction
************

``test_support`` provides shared Python infrastructure for XMOS simulation and
testbench code. It wraps the XSI simulator interface, provides helper classes
for simulator threads and plugins, implements comparison testers, and includes
common models used by library tests.

The main Python modules are:

* ``Pyxsim.pyxsim``: XSI wrapper, simulator thread support, plugin execution,
  and pin/port access helpers.
* ``Pyxsim.bus``: resolved wire and bus-driver model for Python testbenches.
* ``Pyxsim.testers``: output comparison and filtering helpers.
* ``Pyxsim.xe``: helpers for reading metadata from XE files.

*****
Usage
*****

Install ``test_support`` into the Python environment used by the tests. During
library development this is normally done from the repository checkout in
editable mode:

.. code-block:: console

    python -m pip install -e .

Tests usually import ``Pyxsim`` and run a built ``.xe`` under xsim. A typical
pytest test constructs any required simulator threads, creates a tester for the
expected output, and passes pytest's ``capfd`` fixture so simulator output can be
captured and replayed consistently.

.. code-block:: python

    from pathlib import Path

    import Pyxsim
    from Pyxsim.testers import ComparisonTester


    def test_example(capfd):
        xe = Path("bin/example.xe")
        tester = ComparisonTester(["ready", "done"])

        assert Pyxsim.run_on_simulator_(
            xe,
            tester=tester,
            capfd=capfd,
        )

Pass ``simargs`` for xsim command-line arguments and ``appargs`` for arguments
passed to the simulated application.

*****************
Comparison Tester
*****************

``ComparisonTester`` compares simulator output with expected lines. The expected
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

*******************
Resolved Bus Model
*******************

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

    Pyxsim.run_on_simulator_(
        xe,
        simthreads=[ExampleSimThread()],
        instTracing=True,
        vcdTracing=True,
    )

Use the ``timeout`` argument to bound long-running simulations. If the simulator
process does not exit before the timeout expires, Pyxsim terminates it and the
run fails.

********
Examples
********

``examples/pyxsim`` contains a small simulator-thread example. The xCORE
application changes one port, the Python simthread observes that change, then the
simthread drives another port to wake the application.

``examples/code_coverage`` contains a minimal example of processing xsim trace
data for source coverage.
