# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Link pytest JUnit tests to authored test specifications."""

from __future__ import annotations

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "testplan(specification_id): link a test result to an authored test specification",
    )


def pytest_collection_modifyitems(items):
    errors = []

    for item in items:
        marker = item.get_closest_marker("testplan")
        if marker is None:
            continue

        if marker.kwargs:
            errors.append(
                f"{item.nodeid}: testplan marker accepts one specification ID "
                "as a positional argument"
            )
            continue

        if len(marker.args) != 1:
            errors.append(
                f"{item.nodeid}: testplan marker requires exactly one specification ID"
            )
            continue

        specification_id = marker.args[0]
        if not isinstance(specification_id, str) or not specification_id.strip():
            errors.append(
                f"{item.nodeid}: testplan specification ID must be a non-empty string"
            )
            continue

        item.user_properties.append(("verifies", specification_id.strip()))

    if errors:
        raise pytest.UsageError("\n".join(errors))
