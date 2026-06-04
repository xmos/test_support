test_support Change Log
=======================

UNRELEASED
----------

  * ADDED:     AssertiveComparisonChecker's suppress_multidrive_messages support/param to
    ComparisonChecker
  * ADDED:     Methods in Xsi class for getting the xsim tick frequency
  * ADDED:     Reusable testplan pytest plugin documentation under doc/rst, including
    central parametrization, automatic pytest marker discovery, generated RST
    results, and optional executable sequence rendering
  * ADDED:     testplan generated RST can include optional sequence tables from pure
    sequence builder functions
  * ADDED:     testplan generated RST includes requirement coverage and result
    summaries based on authored verifies links
  * ADDED:     testplan requirement coverage supports unsupported requirements as
    deliberate exclusions from coverage gaps
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
  * FIXED:     Resolved issues with stdout/stderr capture in Pyxsim
  * FIXED:     Subprocess exit code checking in Pyxsim to properly report errors from
    failed commands
  * FIXED:     Pyxsim now joins and terminates simulator/subprocess workers on timeout to avoid
    leaking child processes

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
