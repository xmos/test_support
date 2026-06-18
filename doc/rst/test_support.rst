#########################################
test_support: XMOS test support helpers
#########################################

************
Introduction
************

``test_support`` contains reusable helpers for testing XMOS xCORE software from
pytest. The package is intended to be installed into consuming repositories and
used by their local test suites.

The package includes simulator wrappers, coverage processing helpers, and a
generic pytest test-plan plugin that can generate documentation-ready result
includes for projects using ``sphinx-needs``.

************
Installation
************

Consuming repositories commonly install ``test_support`` as an editable Python
dependency from their development environment:

.. code-block:: bash

   pip install -e ../test_support

The exact path depends on the repository layout used by the project under test.

********
Contents
********

.. toctree::
   :maxdepth: 2

   code_coverage
   testplan

******
Pyxsim
******

``Pyxsim`` provides Python helpers for running xCORE simulator based tests from
pytest. Tests can execute XE files under ``xsim`` and compare simulator output
using the provided tester classes.

For examples, see ``examples/pyxsim`` in this package.

*********
Changelog
*********

Release notes are recorded in ``CHANGELOG.rst`` at the package root.
