# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.

from xml.etree import ElementTree


pytest_plugins = ["pytester"]


def test_testplan_marker_writes_verifies_property(pytester):
    pytester.makeconftest('pytest_plugins = ["testplan.pytest_plugin"]')
    pytester.makeini("[pytest]\njunit_family = xunit1")
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.testplan("TEST_SPEC_ONE")
        def test_example():
            pass
        """
    )
    report = pytester.path / "report.xml"

    result = pytester.runpytest("-q", f"--junitxml={report}")

    result.assert_outcomes(passed=1)
    properties = ElementTree.parse(report).findall(".//testcase/properties/property")
    assert [(prop.get("name"), prop.get("value")) for prop in properties] == [
        ("verifies", "TEST_SPEC_ONE"),
    ]


def test_testplan_marker_rejects_missing_requirement_ids(pytester):
    pytester.makeconftest('pytest_plugins = ["testplan.pytest_plugin"]')
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.testplan()
        def test_example():
            pass
        """
    )

    result = pytester.runpytest("-q")

    assert result.ret == 4
    result.stderr.fnmatch_lines(
        ["*testplan marker requires exactly one specification ID*"]
    )
