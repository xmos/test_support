:orphan:

####################################
test_support: XMOS test support tools
####################################

:vendor: XMOS
:scope: General Use
:description: Python helpers for testing XMOS xCORE applications and libraries
:category: Testing
:keywords: test, xsim, pyxsim, pytest, coverage
:devices: xcore-200, xcore.ai

*******
Summary
*******

``test_support`` provides shared Python infrastructure for XMOS simulation and
testbench code. It includes helpers for running xsim from pytest, interacting
with simulated ports and pins, comparing simulator output, reading XE metadata,
and modelling resolved bus wires in Python testbenches.

********
Features
********

* Python wrapper for the xCORE simulator XSI interface.
* Pytest-oriented simulator runners and output comparison helpers.
* Simulator thread support for Python-driven testbench activity.
* Resolved wire model for buses with multiple named drivers.
* Python access helpers for XE files.
* Python code coverage support for xsim traces.

************
Known issues
************

* None

****************
Development repo
****************

* `test_support <https://www.github.com/xmos/test_support>`_ (https://www.github.com/xmos/test_support)

**************
Required tools
**************

* Python 3.12
* XMOS XTC Tools

*********************************
Required libraries (dependencies)
*********************************

* ``colorama``

********
Examples
********

* ``examples/pyxsim`` demonstrates a simulator thread interacting with an xCORE application.
* ``examples/code_coverage`` demonstrates xsim trace based coverage processing.

*******
Support
*******

This package is supported by XMOS Ltd. Issues can be raised against the software
at `www.xmos.com/support <https://www.xmos.com/support>`_ or using GitHub
`issues <https://github.com/xmos/test_support/issues>`_.
