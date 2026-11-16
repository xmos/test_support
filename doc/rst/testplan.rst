#######################
Test Plan Traceability
#######################

The ``testplan`` package provides a small pytest plugin that adds requirement
traceability to standard JUnit XML reports. The reports can be rendered by
``xmosdoc`` using ``sphinx-test-reports`` and ``sphinx-needs``.

The plugin does not own project parametrization or generate documentation
directly. Tests remain parametrized by the consuming project's pytest hooks and
the standard ``--junitxml`` option writes their results.

*******************
Registering pytest
*******************

Enable the plugin from the consuming repository's ``conftest.py``:

.. code-block:: python

   pytest_plugins = ["testplan.pytest_plugin"]

Mark each test with the authored test specification it executes:

.. code-block:: python

   import pytest


   @pytest.mark.testplan("DEMO_TC_TRANSFER")
   def test_demo():
       pass

The plugin writes a ``verifies`` property identifying the authored test
specification to each test case in the JUnit report. The authored ``test-spec``
need owns the ``specifies`` links to requirements, so requirement traceability is
defined once in the test plan rather than repeated in Python markers.

***********************
Generating JUnit output
***********************

Configure pytest to use the xUnit1 JUnit format so testcase properties and
source locations are retained:

.. code-block:: ini

   [pytest]
   junit_family = xunit1

Generate the report with pytest's standard option:

.. code-block:: console

   pytest tests --junitxml=doc/rst/test_report/pytest_results.xml

The test plan marker does not select or parametrize tests. Project-specific
fixtures, markers and ``pytest_generate_tests`` hooks continue to control the
executed variants.

*******************
xmosdoc integration
*******************

Reference the generated report from the authored test-plan document:

.. code-block:: rst

   .. test-file:: Demo test results
      :file: doc/rst/test_report/pytest_results.xml
      :id: TF_DEMO
      :auto_suites:
      :auto_cases:

``xmosdoc`` configures ``verifies`` as a link from each generated test-case
need to the authored test specification. Requirements show their authored
specifications through ``specifies_back``, while a specification shows its
generated test variants through ``verifies_back``.
