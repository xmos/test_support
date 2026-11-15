# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""How application arguments are placed on the simulator's command line."""
import os

import pytest

if "XCC_EXEC_PREFIX" not in os.environ:
    pytest.skip("Pyxsim.pyxsim needs XTC Tools", allow_module_level=True)

from Pyxsim.pyxsim import _simulator_arguments  # noqa: E402


def test_no_application_arguments():
    """Calls without application arguments retain the original simulator command layout."""
    assert _simulator_arguments(["--max-cycles", "10"], "a.xe", []) == ["--max-cycles", "10", "a.xe"]


def test_application_arguments_follow_the_args_flag():
    """Application arguments require --args immediately before the executable."""
    assert _simulator_arguments(["--max-cycles", "10"], "a.xe", ["1", "x"]) == [
        "--max-cycles", "10", "--args", "a.xe", "1", "x"]
    assert _simulator_arguments([], "a.xe", ["1"]) == ["--args", "a.xe", "1"]


def test_args_flag_supplied_by_the_caller_is_not_repeated():
    """An existing trailing --args flag is reused rather than duplicated."""
    assert _simulator_arguments(["--args"], "a.xe", ["1"]) == ["--args", "a.xe", "1"]


def test_inputs_are_not_modified():
    """Building the final command does not mutate the caller's simulator argument list."""
    simargs = ["--max-cycles", "10"]
    _simulator_arguments(simargs, "a.xe", ["1"])
    assert simargs == ["--max-cycles", "10"]
