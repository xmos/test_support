# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
import pytest
from Pyxsim.bus import Bus, BusDriver, BusWire, BusMode, BusWireHardClash, DriveMode


def test_bus_wire_all_released_resolves_to_released_value():
    sda = BusWire("sda", released_value=1)
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])

    controller.sda.release()
    target.sda.release()

    snapshot = sda.snapshot()

    assert snapshot.resolved == 1
    assert snapshot.hard_clash is False
    assert snapshot.drivers_high_z == ("controller", "target")


def test_bus_wire_hard_low_beats_released():
    sda = BusWire("sda")
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])

    controller.sda.drive(0)
    target.sda.release()

    snapshot = sda.snapshot()

    assert snapshot.resolved == 0
    assert snapshot.hard_clash is False
    assert snapshot.drivers_low == ("controller",)


def test_bus_wire_hard_high_beats_released():
    sda = BusWire("sda")
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])

    controller.sda.drive(1)
    target.sda.release()

    snapshot = sda.snapshot()
    assert snapshot.resolved == 1
    assert snapshot.hard_clash is False
    assert snapshot.drivers_high == ("controller",)


def test_bus_wire_multiple_low_drivers_do_not_clash():
    sda = BusWire("sda")
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])

    controller.sda.drive(0)
    target.sda.drive(0)

    snapshot = sda.snapshot()
    assert snapshot.resolved == 0
    assert snapshot.hard_clash is False
    assert snapshot.drivers_low == ("controller", "target")


def test_bus_wire_low_and_high_drivers_clash():
    sda = BusWire("sda")
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])

    controller.sda.drive(0)

    with pytest.raises(BusWireHardClash) as exc_info:
        target.sda.drive(1)

    snapshot = exc_info.value.snapshot
    assert snapshot.resolved == 0
    assert snapshot.hard_clash is True
    assert snapshot.drivers_low == ("controller",)
    assert snapshot.drivers_high == ("target",)


def test_bus_wire_release_with_pullup_resolves_high():
    sda = BusWire("sda", mode=BusMode.OPEN_DRAIN, pullup_enabled=True)
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])

    controller.sda.release()
    target.sda.release()

    snapshot = sda.snapshot()
    assert snapshot.resolved == 1
    assert snapshot.mode == BusMode.OPEN_DRAIN
    assert snapshot.pullup_enabled is True


def test_bus_wire_release_without_pullup_uses_released_value():
    sda = BusWire("sda", pullup_enabled=False, released_value=0)
    controller = BusDriver("controller")
    Bus([sda], [controller])

    controller.sda.release()

    assert sda.resolved_value() == 0


def test_bus_wire_warns_once_when_floating_without_pullup_or_released_value(capsys):
    sda = BusWire("sda", pullup_enabled=False)
    controller = BusDriver("controller")
    Bus([sda], [controller])

    controller.sda.release()

    assert sda.resolved_value() is None
    assert sda.resolved_value() is None

    captured = capsys.readouterr()
    assert captured.out.count("Bus wire sda is floating") == 1


def test_bus_wire_configures_mode_and_pullup():
    sda = BusWire("sda", released_value=0)
    controller = BusDriver("controller")
    Bus([sda], [controller])

    sda.configure(mode=BusMode.PUSH_PULL, pullup_enabled=False)

    snapshot = sda.snapshot()
    assert snapshot.mode == BusMode.PUSH_PULL
    assert snapshot.pullup_enabled is False


def test_bus_wire_drive_value_sets_hard_drive_mode():
    sda = BusWire("sda")
    controller = BusDriver("controller")
    Bus([sda], [controller])

    controller.sda.drive(1)

    assert controller.sda.mode() == DriveMode.DRIVE_HIGH


@pytest.mark.parametrize("value", [-1, 2, 3])
def test_bus_wire_drive_rejects_non_single_wire_values(value):
    sda = BusWire("sda")
    controller = BusDriver("controller")
    Bus([sda], [controller])

    with pytest.raises(ValueError, match="0 or 1"):
        controller.sda.drive(value)


# New OO API-specific tests

def test_bus_binds_drivers_to_multiple_wires():
    """Test that Bus binds all drivers to all wires."""
    scl = BusWire("scl", pullup_enabled=False)
    sda = BusWire("sda", pullup_enabled=True)
    controller = BusDriver("controller")
    target = BusDriver("target")
    
    Bus([scl, sda], [controller, target])
    
    # All drivers should be bound to all wires
    controller.scl.drive(1)
    controller.sda.drive(0)
    target.scl.release()
    target.sda.release()
    
    assert scl.resolved_value() == 1
    assert sda.resolved_value() == 0


def test_bus_rejects_duplicate_wire_names():
    """Test that Bus raises on duplicate wire names."""
    sda1 = BusWire("sda")
    sda2 = BusWire("sda")
    controller = BusDriver("controller")
    
    with pytest.raises(ValueError, match="Duplicate wire names"):
        Bus([sda1, sda2], [controller])


def test_bus_rejects_duplicate_driver_names():
    """Test that Bus raises on duplicate driver names."""
    sda = BusWire("sda")
    controller1 = BusDriver("controller")
    controller2 = BusDriver("controller")
    
    with pytest.raises(ValueError, match="Duplicate driver names"):
        Bus([sda], [controller1, controller2])


def test_bus_enforces_global_uniqueness():
    """Test that wire and driver names must be globally unique."""
    sda = BusWire("sda")
    sda_driver = BusDriver("sda")  # Same name as wire
    
    with pytest.raises(ValueError, match="globally unique"):
        Bus([sda], [sda_driver])


def test_driver_attribute_access_for_unbound_wire_raises():
    """Test that accessing unbound wire raises AttributeError."""
    sda = BusWire("sda")
    controller = BusDriver("controller")
    Bus([sda], [controller])
    
    with pytest.raises(AttributeError, match="'BusDriver' object has no attribute 'scl'"):
        controller.scl.drive(0)


def test_bus_wire_driver_mode_queries():
    """Test that BusWireDriver.mode() returns correct DriveMode."""
    sda = BusWire("sda")
    controller = BusDriver("controller")
    Bus([sda], [controller])
    
    # Initially high-Z
    assert controller.sda.mode() == DriveMode.HIGH_Z
    
    # After driving low
    controller.sda.drive(0)
    assert controller.sda.mode() == DriveMode.DRIVE_LOW
    
    # After driving high
    controller.sda.drive(1)
    assert controller.sda.mode() == DriveMode.DRIVE_HIGH
    
    # After release
    controller.sda.release()
    assert controller.sda.mode() == DriveMode.HIGH_Z


def test_driver_release_only_affects_that_driver():
    """Test that releasing one driver doesn't affect other drivers."""
    sda = BusWire("sda")
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])
    
    controller.sda.drive(0)
    target.sda.drive(0)
    
    # Both driving low
    assert sda.resolved_value() == 0
    assert controller.sda.mode() == DriveMode.DRIVE_LOW
    assert target.sda.mode() == DriveMode.DRIVE_LOW
    
    # Release controller only
    controller.sda.release()
    
    # Controller released, target still driving
    assert sda.resolved_value() == 0
    assert controller.sda.mode() == DriveMode.HIGH_Z
    assert target.sda.mode() == DriveMode.DRIVE_LOW


def test_hard_clash_still_detected_with_oo_api():
    """Test that BusWireHardClash is still raised with OO API."""
    sda = BusWire("sda")
    controller = BusDriver("controller")
    target = BusDriver("target")
    Bus([sda], [controller, target])
    
    controller.sda.drive(1)
    
    with pytest.raises(BusWireHardClash) as exc_info:
        target.sda.drive(0)
    
    assert exc_info.value.snapshot.hard_clash is True


def test_bus_rejects_invalid_wire_name():
    """Test that Bus rejects wire names that are not valid Python identifiers."""
    sda_invalid = BusWire("sda-line")  # Hyphen not allowed in identifiers
    controller = BusDriver("controller")
    
    with pytest.raises(ValueError, match="must be a valid Python identifier"):
        Bus([sda_invalid], [controller])


def test_bus_rejects_wire_name_conflicting_with_driver_attribute():
    """Test that Bus rejects wire names that conflict with BusDriver attributes."""
    name_wire = BusWire("name")  # Conflicts with BusDriver.name
    controller = BusDriver("controller")
    
    with pytest.raises(ValueError, match="conflicts with BusDriver attribute"):
        Bus([name_wire], [controller])


def test_driver_bound_wires_are_real_attributes():
    """Test that bound wires are real attributes, not __getattr__ magic."""
    scl = BusWire("scl")
    sda = BusWire("sda")
    controller = BusDriver("controller")
    Bus([scl, sda], [controller])
    
    # Attributes should be in __dict__
    assert "scl" in controller.__dict__
    assert "sda" in controller.__dict__
    
    # Should be able to use hasattr
    assert hasattr(controller, "scl")
    assert hasattr(controller, "sda")
    assert not hasattr(controller, "nonexistent")
    
    # Should be able to use getattr with default
    assert getattr(controller, "scl") is not None
    assert getattr(controller, "nonexistent", "default") == "default"
