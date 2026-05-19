test_support Change Log
=======================

UNRELEASED
----------

  * ADDED:     AssertiveComparisonChecker’s suppress_multidrive_messages support/param to
    ComparisonChecker
  * ADDED:     Methods in Xsi class for getting the xsim tick frequency
  * CHANGED:   Pyxsim CMake build uses XCommon CMake
  * CHANGED:   The way time is incremented by time_step for better floating point precision
  * FIXED:     Resolved issues with stdout/stderr capture in Pyxsim

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

