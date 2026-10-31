import os
import signal
import sys
import tempfile
import time
from pathlib import Path

import pytest

import Pyxsim
from Pyxsim.xe import Xe


def test_close_removes_temporary_directory(tmp_path):
    tempdir = tmp_path / "xe"
    tempdir.mkdir()
    (tempdir / "config.xml").touch()

    xe = Xe.__new__(Xe)
    xe._tempdir = str(tempdir)

    xe.close()
    xe.close()

    assert not tempdir.exists()


def test_init_failure_removes_temporary_directory(tmp_path, monkeypatch):
    def raise_xobjdump_error(_xe):
        raise RuntimeError("xobjdump failed")

    binary = tmp_path / "test.xe"
    binary.touch()
    tempdir = tmp_path / "xe"
    tempdir.mkdir()

    monkeypatch.setattr("Pyxsim.xe.tempfile.mkdtemp", lambda **_kwargs: str(tempdir))
    monkeypatch.setattr(Xe, "_get_platform_info", raise_xobjdump_error)

    with pytest.raises(RuntimeError, match="xobjdump failed"):
        Xe(Path(binary))

    assert not tempdir.exists()

class _FakeXsi:
    def __init__(self, xe_path, simargs, appargs, **kwargs):
        self.xe = Xe(xe_path, **kwargs)

    def register_simthread(self, _simthread):
        pass

    def terminate(self):
        self.xe.close()


class _HangingXsi(_FakeXsi):
    def run(self):
        time.sleep(60)


class _CrashingXsi(_FakeXsi):
    def run(self):
        os.kill(os.getpid(), signal.SIGKILL)


@pytest.mark.skipif(sys.platform == "win32", reason="relies on fork start method")
@pytest.mark.parametrize("xsi_class", [_HangingXsi, _CrashingXsi])
def test_run_with_pyxsim_removes_worker_temp_files(tmp_path, monkeypatch, xsi_class):
    binary = tmp_path / "test.xe"
    binary.touch()
    system_tmp = tmp_path / "tmp"
    system_tmp.mkdir()

    monkeypatch.setattr(tempfile, "tempdir", str(system_tmp))
    monkeypatch.setattr(Xe, "_get_platform_info", lambda _xe: None)
    monkeypatch.setattr(Xe, "_get_symtab", lambda _xe: None)
    monkeypatch.setattr(Pyxsim.pyxsim, "Xsi", xsi_class)

    assert not Pyxsim.run_with_pyxsim(str(binary), [], simargs=[], timeout=1)

    assert list(system_tmp.iterdir()) == []
