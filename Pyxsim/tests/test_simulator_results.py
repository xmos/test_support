"""Keep upstream result handling alongside the legacy and run-only APIs."""
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

if "XCC_EXEC_PREFIX" not in os.environ:
    pytest.skip("Pyxsim.pyxsim needs XTC Tools", allow_module_level=True)

from Pyxsim import pyxsim
from Pyxsim.testers import TestError as SimulatorError


def simulator(status, result):
    xsi = pyxsim.XsiBase.__new__(pyxsim.XsiBase)
    xsi._simthreads = []
    xsi._plugins = []
    xsi._time = 0
    xsi._time_step = 1
    xsi._terminated_by_simthread = False
    xsi._clock = lambda: status
    xsi.get_result = Mock(return_value=result)
    return xsi


@pytest.mark.parametrize("result", [0, 1, 7])
def test_natural_completion_checks_the_application_result(result):
    """Natural completion passes only for a zero application result."""
    xsi = simulator(pyxsim.XsiStatus.DONE, result)
    if result:
        with pytest.raises(SimulatorError, match=f"non-zero result: {result}"):
            xsi.run()
    else:
        assert xsi.run() is None
    xsi.get_result.assert_called_once_with()


@pytest.mark.parametrize("status", ["OK", "DONE"])
def test_python_termination_does_not_hide_a_naturally_completed_failure(status):
    """Intentional Python stops pass, but cannot hide a simultaneous application failure."""
    xsi = simulator(getattr(pyxsim.XsiStatus, status), 7)
    xsi._simthreads = [SimpleNamespace(
        start=lambda: None,
        resume_condition=lambda xsi: True,
        resume_event=SimpleNamespace(set=lambda: None),
        terminate_flag=True,
    )]
    xsi.wait_for_simthread = lambda thread: None
    if status == "OK":
        assert xsi.run() is None
        xsi.get_result.assert_not_called()
    else:
        with pytest.raises(SimulatorError, match="non-zero result: 7"):
            xsi.run()
        xsi.get_result.assert_called_once_with()


def test_older_xtc_without_result_api_remains_supported(monkeypatch):
    """Older XTC libraries lacking xsi_get_result retain the zero-result fallback."""
    monkeypatch.setattr(pyxsim, "xsi_lib", SimpleNamespace())
    xsi = pyxsim.Xsi.__new__(pyxsim.Xsi)
    assert xsi.get_result() == 0


def test_backend_without_result_api_keeps_base_fallback():
    """Backends without result-query support inherit the successful base fallback."""
    xsi = pyxsim.XsiBase.__new__(pyxsim.XsiBase)
    assert xsi.get_result() == 0
