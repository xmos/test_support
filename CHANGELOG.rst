test_support Change Log
=======================

3.0.0
-----

  * ADDED:     Pyxrun.run(echo=False) suppresses stdout replay without changing
    capture or comparison, so benchmarks need no custom quiet-execution wrapper
  * ADDED:     Pyxrun package to run or flash an application on a board, with output
    captured while it runs, deadlines, retained logs and safe teardown. Pyxrun.run()
    runs an executable and checks its output, to exit or until a given line;
    Pyxrun.Session is for multi-step tests. Based on hardware_test_tools' XcoreApp
  * ADDED:     Pyxsim.run() runs an already-built executable, matching Pyxrun.run()
  * ADDED:     Pyxsim.build() and Pyxrun.build() build the one target of an executable
    in a configured CMake build directory, for tests that build what they are about
    to run
  * ADDED:     AssertiveComparisonChecker's suppress_multidrive_messages support/param to
    ComparisonChecker
  * ADDED:     BusWire resolved-wire model for Python testbenches, including pull-up
    handling and hard-clash detection
  * ADDED:     Methods in Xsi class for getting the xsim tick frequency
  * CHANGED:   Turned into a plain python package instead of a lib
  * CHANGED:   Pyxsim CMake build uses XCommon CMake
  * CHANGED:   The way time is incremented by time_step for better floating point precision
  * CHANGED:   ComparisonChecker only prints expected output when verbosity is 2 or higher (i.e.
    -vv)
  * CHANGED:   Pyxsim prints captured simulator output when verbosity is enabled while still
    preserving output capture for tester comparisons
  * CHANGED:   ComparisonChecker verbose output uses colour to highlight expected and missing
    output
  * CHANGED:   ComparisonChecker filters suppressed output from verbose Pyxsim logs and reports
    colourised suppression counts for multidrive and ignored lines
  * DEPRECATED: Pyxsim.run_on_simulator_(); use Pyxsim.run(). The build-and-run
    Pyxsim.run_on_simulator() is unchanged
  * FIXED:     Pyxsim appargs are passed to the application; the simulator previously
    failed to start when any were given
  * FIXED:     Resolved issues with stdout/stderr capture in Pyxsim
  * FIXED:     Subprocess exit code checking in Pyxsim to properly report errors from
    failed commands
  * FIXED:     Pyxsim now joins and terminates simulator/subprocess workers on timeout to avoid
    leaking child processes
  * FIXED:     Pyxsim checks the xsim exit result after the simulation ends, so an
    application that asserts or exits non-zero is reported as a failure

2.0.0
-----

  * ADDED:     Support for basic VCD tracing
  * ADDED:     NOCOVERSTART and NOCOVEREND for adding coverage exclusions
  * ADDED:     AssertiveComparisonTester, which asserts on errors rather than
    printing
  * ADDED:     Initial CMake support
  * FIXED:     Use of 32bit ports in Pyxsim

1.0.0
-----

  * Initial release
