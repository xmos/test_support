:orphan:

#########################################
test_support: XMOS test support helpers
#########################################

:vendor: XMOS
:version: 2.0.0
:scope: General Use
:description: Reusable pytest, simulator, coverage, and test-plan helpers for XMOS software repositories
:category: Test
:keywords: pytest, xsim, pyxsim, xcoverage, testplan
:devices: xcore-200, xcore.ai

*******
Summary
*******

``test_support`` provides reusable Python helpers for testing XMOS xCORE
applications. It includes wrappers for running tests on the xCORE simulator,
code coverage processing utilities, and pytest helpers for generating structured
test-plan result documentation.

********
Features
********

* Python wrapper for the xCORE simulator, ``xsim``.
* Python access functions for XE files.
* Python code coverage measurement helpers for pytest.
* Reusable pytest test-plan generation helpers for central parametrization,
  generated result summaries, and optional executable sequence tables.

************
Known issues
************

* None

****************
Development repo
****************

* ``test_support`` is maintained as part of XMOS software infrastructure.

**************
Required tools
**************

* XMOS XTC Tools
* Python 3
* pytest

*********************************
Required libraries (dependencies)
*********************************

* ``colorama``
* ``PyYAML``

*******
Support
*******

This package is supported by XMOS Ltd. Issues can be raised against the software at
`www.xmos.com/support <https://www.xmos.com/support>`_.
