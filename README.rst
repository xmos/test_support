
Test Support
============

This repo contains helpers for testing XMOS xCORE applictions and includes the following:

- Python wrapper for the xCORE simulator (xsim)
- Python access functions for XE files
- Python code coverage measurement (xcov) for pytest

Basic usage: Pyxsim
-------------------

Pyxsim provides Python helpers for running xsim-based tests from pytest. A
typical test builds a simulator thread, optionally attaches plugins, and calls
``Pyxsim.run_on_simulator_`` with a tester such as ``ComparisonTester``.

When pytest output capture is passed via ``capfd``, Pyxsim captures simulator
and simthread output and replays it according to the pytest verbosity level:

* ``pytest ...`` keeps output compact and reports pass/fail details.
* ``pytest ... -v`` enables verbose tester output, including captured
  ``OUTPUT:`` lines from the simulator stream.
* ``pytest ... -vv`` also prints the matching ``GOLDEN:`` lines from
  ``ComparisonTester`` and is useful when diagnosing mismatches.

``ComparisonTester`` supports regular-expression matching, ordered or unordered
comparison, ignored output patterns, and optional suppression of common xsim
multidrive diagnostics.

Resolved bus wires
------------------

``Pyxsim.bus`` contains a small resolved-wire model for Python testbenches:

* ``BusWire`` models one digital bus wire with named drivers, protocol mode,
  and pull-up state.
* ``DriveMode.HIGH_Z`` represents a released line driver.
* ``DriveMode.DRIVE_LOW`` and ``DriveMode.DRIVE_HIGH`` represent hard-driven
  values.
* When all drivers are high-Z and pull-up is enabled, the wire resolves high.
* If any driver drives low, the resolved value is low unless another driver is
  hard-driving high.
* A hard-low and hard-high combination is reported as ``hard_clash`` in the
  wire snapshot.
* Hard-drive operations raise ``BusWireHardClash`` immediately if they create a
  hard-low versus hard-high conflict. The exception includes the wire name,
  resolved value, active low drivers, active high drivers, and the driver/mode
  being applied.

Example::

    from Pyxsim.bus import BusMode, BusWire

    sda = BusWire("sda", mode=BusMode.OPEN_DRAIN, pullup_enabled=True)
    sda.release("controller")
    sda.drive("target", 0)

    snapshot = sda.snapshot()
    assert snapshot.resolved == 0
    assert not snapshot.hard_clash

Use ``release(driver)`` when the testbench is handing ownership of a wire to
another bus participant. Use ``drive(driver, 1)`` only when the protocol phase
really requires a hard high drive. If the wire has a modeled pull-up, released
drivers can still resolve to a high value without being recorded as hard-driving
high.

Basic usage: xcoverage
----------------------

This only suit for xsim.

It requires disassembly and elf file which dumped from binary file (.xe file) by:

 * xobjdump --split [.xe].
 * xobjdump -S [.xe] -o [output_file_name.dump].
 * run the above 2 step by youself or run method from xcov: generate_elf_disasm("/path_to/(name-of-xe).xe", "/path_where_store_elf_and_disasm", "/path_to/(name-of-disasm).dump")

.xe must make with -g flag to enable the gdb bugger otherwise xcoverage won't work!.

It also needs a tracing file from xsim by running:

 * xsim --trace-to [output_file_name.txt] [.xe].

``xcov_process``
.......................

This is the main function to be called in your test.
It returns the average coverage and save the data in .xcov file in xcov dir.
.xcov file is necessary for the below "xcov_combine" function.

xcov_process(disasm, trace, xcov_dir).

 * @param disam: path to disasm file.
 * @param trace: path to trace file.
 * @param xcov_dir : path where xcov directory locates.
 * @return average coverage of all src file.
 * @output generate xcov file for xcov_combine and save in xcov dir.

``xcov_combine``
.......................

see example in examples/code_coverage

``combine_process``
.......................

see example in examples/code_coverage

``Mark the source code as not expected to be hit``
........................................................

Add a comment "//NOCOVER" or "//NOCOVERSTART" and "//NOCOVEREND" beside you source code. It wouldn't be counted in coverage.

see example in test/test_xcoverage

``Excluded File``
........................................................
Passing an excluded_file arg in xcov_process(), eg:

xcov_process(disasm, trace, xcov_dir, excluded_file=["/tests/shared/test_main.xc","/tests/shared/shared.h" ])

Software version and dependencies
.................................

The CHANGELOG contains information about the current and previous versions.
For a list of direct dependencies, look for DEPENDENT_MODULES in test_support/module_build_info.




