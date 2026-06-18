# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
import pytest

from Pyxsim.bus import BusWire, BusMode, BusWire, BusWireHardClash, DriveMode


def test_bus_wire_all_released_resolves_to_released_value():
    line = BusWire("sda", released_value=1)
    line.release("controller")
    line.release("target")

    snapshot = line.snapshot()

    assert snapshot.resolved == 1
    assert snapshot.hard_clash is False
    assert snapshot.drivers_high_z == ("controller", "target")


def test_bus_wire_hard_low_beats_released():
    line = BusWire("sda")
    line.drive_low("controller")
    line.release("target")

    snapshot = line.snapshot()

    assert snapshot.resolved == 0
    assert snapshot.hard_clash is False
    assert snapshot.drivers_low == ("controller",)


def test_bus_wire_hard_high_beats_released():
    line = BusWire("sda")
    line.drive_high("controller")
    line.release("target")

    snapshot = line.snapshot()
    assert snapshot.resolved == 1
    assert snapshot.hard_clash is False
    assert snapshot.drivers_high == ("controller",)


def test_bus_wire_multiple_low_drivers_do_not_clash():
    line = BusWire("sda")
    line.drive_low("controller")
    line.drive_low("target")

    snapshot = line.snapshot()
    assert snapshot.resolved == 0
    assert snapshot.hard_clash is False
    assert snapshot.drivers_low == ("controller", "target")


def test_bus_wire_low_and_high_drivers_clash():
    line = BusWire("sda")
    line.drive_low("controller")

    with pytest.raises(BusWireHardClash) as exc_info:
        line.drive_high("target")

    snapshot = exc_info.value.snapshot
    assert snapshot.resolved == 0
    assert snapshot.hard_clash is True
    assert snapshot.drivers_low == ("controller",)
    assert snapshot.drivers_high == ("target",)


def test_bus_wire_accepts_drive_mode_values():
    line = BusWire("sda")
    line.set_driver("controller", DriveMode.DRIVE_HIGH.value)

    assert line.driver_mode("controller") == DriveMode.DRIVE_HIGH
    assert line.resolved_value() == 1


def test_bus_wire_release_with_pullup_resolves_high():
    wire = BusWire("sda", mode=BusMode.OPEN_DRAIN, pullup_enabled=True)
    wire.release("controller")
    wire.release("target")

    snapshot = wire.snapshot()
    assert snapshot.resolved == 1
    assert snapshot.mode == BusMode.OPEN_DRAIN
    assert snapshot.pullup_enabled is True


def test_bus_wire_release_without_pullup_uses_released_value():
    wire = BusWire("sda", pullup_enabled=False, released_value=0)
    wire.release("controller")

    assert wire.resolved_value() == 0


def test_bus_wire_configures_mode_and_pullup():
    wire = BusWire("sda")

    wire.configure(mode=BusMode.PUSH_PULL, pullup_enabled=False)

    snapshot = wire.snapshot()
    assert snapshot.mode == BusMode.PUSH_PULL
    assert snapshot.pullup_enabled is False


def test_bus_wire_drive_value_sets_hard_drive_mode():
    wire = BusWire("sda")

    wire.drive("controller", 1)

    assert wire.driver_mode("controller") == DriveMode.DRIVE_HIGH


@pytest.mark.parametrize("value", [-1, 2, 3])
def test_bus_wire_drive_rejects_non_single_wire_values(value):
    wire = BusWire("sda")

    with pytest.raises(ValueError, match="0 or 1"):
        wire.drive("controller", value)
