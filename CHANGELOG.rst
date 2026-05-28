test_support Change Log
=======================

UNRELEASED
----------

  * ADDED:     AssertiveComparisonChecker's suppress_multidrive_messages support/param to
    ComparisonChecker
  * ADDED:     Methods in Xsi class for getting the xsim tick frequency
  * CHANGED:   Pyxsim CMake build uses XCommon CMake
  * CHANGED:   The way time is incremented by time_step for better floating point precision
  * CHANGED:   ComparisonChecker only prints expected output when verbosity is 2 or higher (i.e.
    -vv)
  * FIXED:     Resolved issues with stdout/stderr capture in Pyxsim
  * FIXED:     Subprocess exit code checking in Pyxsim to properly report errors from
    failed commands

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

