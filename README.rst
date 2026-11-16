:orphan:

#####################################
test_support: XMOS test support tools
#####################################

:vendor: XMOS
:scope: General use
:description: Python helpers for testing XMOS XCORE applications and libraries
:category: Core & system
:keywords: testing
:devices: xcore-200, xcore.ai

*******
Summary
*******

``test_support`` provides shared Python infrastructure for XMOS simulation,
hardware execution and testbench code. It includes helpers for running xsim from
pytest, interacting with simulated ports and pins, comparing simulator output,
reading XE metadata, and modelling resolved bus wires in Python testbenches.

********
Features
********

* Python wrapper for the xCORE simulator XSI interface.
* Pytest-oriented simulator runners and output comparison helpers.
* Matching ``Pyxsim.run()`` and ``Pyxrun.run()`` entry points for already-built
  executables, using the same output comparison checkers.
* Simulator thread support for Python-driven testbench activity.
* Resolved wire model for buses with multiple named drivers.
* Python access helpers for XE files.
* Python code coverage support for xsim traces.
* Observation-based completion through ``Pyxrun.run(until=...)`` for applications
  that keep running, using the same lifecycle as finite tests.
* ``Pyxrun.Session`` for interactive execution or flashing, with captured output,
  deadlines, retained logs and safe teardown.

************
Known issues
************

* The XTC Tools environment must be activated and its XSI library available even
  when importing helpers that do not themselves use the simulator, such as output
  checkers, bus models and Pyxrun. Package imports currently load XSI eagerly.

****************
Development repo
****************

* `test_support <https://www.github.com/xmos/test_support>`_ (https://www.github.com/xmos/test_support)

**************
Required tools
**************

* Python 3.12
* XMOS XTC Tools 15.3.1

*********************************
Required libraries (dependencies)
*********************************

* None

*******
Support
*******

This package is supported by XMOS Ltd. Issues can be raised against the software
at `www.xmos.com/support <https://www.xmos.com/support>`_ or using GitHub
`issues <https://github.com/xmos/test_support/issues>`_.
