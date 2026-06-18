####################
Test Plan Generation
####################

The ``testplan`` package provides a reusable pytest plugin for projects that
maintain authored test plans in RST and want generated pytest result summaries in
their documentation.

The intended flow is:

* author planned and implemented tests in an RST test plan, usually using
  ``sphinx-needs`` directives;
* keep test parameters and optional sequence builders in ``tests/testplan.yml``;
* mark implemented pytest tests with ``@pytest.mark.testplan("ID")``;
* optionally reference pure sequence-builder functions for executable sequence
  tables;
* generate an RST include with the latest pytest metadata, results, parameter
  variants, feature summaries, and executable sequence tables.

*******************
Registering pytest
*******************

Enable the plugin from the consuming repository's ``conftest.py``:

.. code-block:: python

   pytest_plugins = ["testplan.pytest_plugin"]

Implemented tests link to authored test-plan IDs with a pytest marker:

.. code-block:: python

   import pytest


   @pytest.mark.testplan("DEMO_TC_001")
   def test_demo(bus_speed_khz, target_arch):
       assert bus_speed_khz > 0

**********************
Central configuration
**********************

The plugin reads ``tests/testplan.yml`` from the pytest root by default, with a
root-level ``testplan.yml`` retained as a compatibility fallback. A different
file can be selected with ``--testplan-config``.

Example configuration:

.. code-block:: yaml

   parameters:
     target_arch:
       values:
         - xs3
     bus_speed_khz:
       values:
         - 80
         - 200
     transport:
       values:
         - direct-xsi

   tests:
     DEMO_TC_001:
       sequence: tests.test_demo::build_demo_session
       parameters:
         target_arch:
           - xs3
         bus_speed_khz:
           - 80
           - 200
         transport:
           - direct-xsi

``parameters`` defines named test parameters. Parameter names are used unchanged
as pytest fixture names and generated RST metadata field names. ``tests``
contains one entry per authored test-plan ID.

Every authored ``.. test::`` case must have a matching ``tests.<id>`` entry in
``tests/testplan.yml``. Extra YAML test entries that are not authored in the RST
test plan are also reported as errors. This keeps the authored plan and central
test configuration synchronized without a separate sync command.

The ``pytest`` field records the collected pytest node without parameter values.
It is generated automatically from collected tests marked with
``@pytest.mark.testplan("ID")`` and is not stored in ``tests/testplan.yml``.

Test case implementation status is also generated from collection. A test case
with a collected pytest marker is reported as ``implemented``; an authored test
case with no collected pytest marker is reported as ``planned``. Projects should
normally omit ``:status:`` from authored ``.. test::`` blocks.

The ``sequence`` field is optional. It points to a pure Python builder function
using ``module::function`` notation. Planned tests may omit ``sequence`` and may
also have no pytest implementation.

***************************
Central parametrization
***************************

For marked tests, the plugin uses ``tests.<id>.parameters`` to parametrize pytest
fixtures with matching names. If a configured parameter is not present in the
test function signature it is not passed to pytest, but it is still available as
documentation metadata.

For example, this configuration:

.. code-block:: yaml

   tests:
     DEMO_TC_001:
       parameters:
         bus_speed_khz:
           - 80
           - 200

parametrizes this test over both bus speeds:

.. code-block:: python

   @pytest.mark.testplan("DEMO_TC_001")
   def test_demo(bus_speed_khz):
       assert bus_speed_khz in [80, 200]

**********************
Generated RST includes
**********************

Generate the documentation report include with:

.. code-block:: bash

   pytest tests --testplan-report-rst doc/rst/generated/test_report.rst

For metadata-only output without running tests, use pytest collection mode:

.. code-block:: bash

   pytest tests --collect-only --testplan-report-rst doc/rst/generated/test_report.rst

The generated report contains:

* ``needextend`` directives that apply configured metadata, automatically
  discovered pytest mappings, and latest result fields to authored needs;
* a requirement coverage summary based on authored ``:verifies:`` links from
  test cases to requirements, with linked requirement IDs and split outcome
  count columns;
* a per-test result rollup table with split outcome count columns;
* a separate per-test timing summary;
* a parameter variant result table showing each executed parameter combination,
  its result, and duration;
* a feature summary based on tags in the authored test plan, with split outcome
  count columns;
* executable sequence tables for tests with a configured ``sequence`` builder.

*********************
Executable sequences
*********************

Executable sequence tables are generated from pure builder functions. A builder
must not require pytest fixtures and must not run the simulator. It should return
an object that exposes ``_execution_table_rows()``.

Example:

.. code-block:: python

   def build_demo_session(bus_speed_khz, table_mode=None):
       session = DemoSession(bus_speed_khz=bus_speed_khz, table_mode=table_mode)
       session.add_transaction(...)
       return session

The corresponding configuration is:

.. code-block:: yaml

   tests:
     DEMO_TC_001:
       sequence: tests.test_demo::build_demo_session

For parameterized tests, the generated documentation renders one representative
variant by default. The representative variant is the first configured parameter
combination for that test.

*******************
xmosdoc integration
*******************

Projects using ``xmosdoc`` and ``sphinx-needs`` can include the generated report
in their authored test-plan page:

.. code-block:: rst

   .. include:: generated/test_report.rst

The generated result badges use CSS shipped in the ``testplan`` package. A
project can opt in with ``package:testplan.resources``:

.. code-block:: yaml

   documentation:
     extra_extensions:
       - sphinx_needs
     html_static_paths:
       - package:testplan.resources
     html_css_files:
       - testplan.css
     sphinx_config_includes:
       - package:testplan.resources/sphinx_config.yml
     sphinx_config:
       needs_fields:
         target_arch:
           description: Target architecture
           schema:
             type: string
           nullable: true

The shared ``sphinx_config.yml`` supplies generic test-plan needs types, the
``verifies`` link type, and generated metadata fields such as ``level``,
``pytest``, and ``result``. Projects must still define project-specific needs
fields referenced by generated result metadata, such as target architecture or
bus speed.

Requirement coverage is generated from semantic ``:verifies:`` links in the
authored test plan. A test case linked to a requirement contributes its configured
parameter variants and latest pytest result to that requirement's coverage and
result rollup.

Requirements with ``:status: unsupported`` document deliberate exclusions from
product scope. They are excluded from requirement coverage summaries and are not
treated as uncovered test gaps.
