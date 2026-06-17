# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Generic resolved-wire model for Python testbenches."""

from dataclasses import dataclass
from enum import Enum


class DriveMode(Enum):
    """Hard-drive state for one named driver on a resolved bus wire."""

    HIGH_Z = "high_z"
    DRIVE_LOW = "drive_low"
    DRIVE_HIGH = "drive_high"


class BusMode(Enum):
    """Protocol mode hint for callers that map logical bits to drive modes."""

    OPEN_DRAIN = "open_drain"
    PUSH_PULL = "push_pull"


class BusWireHardClash(RuntimeError):
    """Raised when resolved bus-wire drivers hard-drive opposite values."""

    def __init__(self, snapshot, driver=None, mode=None, context=None):
        self.snapshot = snapshot
        self.driver = driver
        self.mode = mode
        self.context = context
        detail = (
            f"Bus wire hard clash on {snapshot.name}: "
            f"resolved={snapshot.resolved}, "
            f"low_drivers={snapshot.drivers_low}, "
            f"high_drivers={snapshot.drivers_high}"
        )
        if driver is not None:
            detail += f", driver={driver}"
        if mode is not None:
            detail += f", mode={mode}"
        if context is not None:
            detail += f", context={context}"
        super().__init__(detail)


@dataclass(frozen=True)
class ResolvedLineState:
    """Snapshot of a bus wire after resolving all named drivers."""

    name: str
    resolved: int | None
    hard_clash: bool
    drivers_low: tuple[str, ...]
    drivers_high: tuple[str, ...]
    drivers_high_z: tuple[str, ...]
    mode: BusMode
    pullup_enabled: bool


class BusWire:
    """Resolved digital bus wire with named hard drivers and simple bias.

    The model intentionally distinguishes hard-drive high from high-Z release.
    Pull-up modelling is deliberately simple: when all drivers are released and
    pull-up is enabled, the wire resolves high. This preserves enough driver
    intent to detect hard-drive clashes while still providing a concrete value
    for simulators that only support hard drives.
    """

    def __init__(self, name, mode=BusMode.OPEN_DRAIN, pullup_enabled=True, released_value=None):
        if not isinstance(mode, BusMode):
            mode = BusMode(mode)
        if released_value is not None and released_value not in (0, 1):
            raise ValueError("released_value must be 0 or 1")
        self.name = name
        self.mode = mode
        self.pullup_enabled = bool(pullup_enabled)
        self.released_value = released_value
        self._drivers = {}

    def configure(self, mode=None, pullup_enabled=None):
        """Configure protocol mode and pull-up state."""
        if mode is not None:
            self.set_mode(mode)
        if pullup_enabled is not None:
            if pullup_enabled:
                self.enable_pullup()
            else:
                self.disable_pullup()

    def set_mode(self, mode):
        """Set the protocol mode hint for this wire."""
        if not isinstance(mode, BusMode):
            mode = BusMode(mode)
        self.mode = mode

    def enable_pullup(self):
        """Enable the modeled pull-up bias."""
        self.pullup_enabled = True

    def disable_pullup(self):
        """Disable the modeled pull-up bias."""
        self.pullup_enabled = False

    def set_driver(self, driver, mode, context=None):
        """Set a named driver's hard-drive mode."""
        if not isinstance(mode, DriveMode):
            mode = DriveMode(mode)
        driver = self._key(driver)
        self._drivers[driver] = mode
        if mode != DriveMode.HIGH_Z:
            self.assert_no_hard_clash(driver=driver, mode=mode, context=context)

    def release(self, driver):
        """Set a named driver to high-Z."""
        self.set_driver(driver, DriveMode.HIGH_Z)

    def drive(self, driver, value, context=None):
        """Set a named driver to hard-drive low or high."""
        if value & 0x1:
            self.drive_high(driver, context=context)
        else:
            self.drive_low(driver, context=context)

    def drive_low(self, driver, context=None):
        """Set a named driver to hard-drive low."""
        self.set_driver(driver, DriveMode.DRIVE_LOW, context=context)

    def drive_high(self, driver, context=None):
        """Set a named driver to hard-drive high."""
        self.set_driver(driver, DriveMode.DRIVE_HIGH, context=context)

    def driver_mode(self, driver):
        """Return a named driver's mode, defaulting to high-Z."""
        return self._drivers.get(self._key(driver), DriveMode.HIGH_Z)

    def snapshot(self, exclude=None):
        """Resolve all drivers and return a stable debug snapshot."""
        exclude = self._key(exclude) if exclude is not None else None
        drivers_low = tuple(sorted(
            driver for driver, mode in self._drivers.items()
            if driver != exclude and mode == DriveMode.DRIVE_LOW
        ))
        drivers_high = tuple(sorted(
            driver for driver, mode in self._drivers.items()
            if driver != exclude and mode == DriveMode.DRIVE_HIGH
        ))
        drivers_high_z = tuple(sorted(
            driver for driver, mode in self._drivers.items()
            if driver != exclude and mode == DriveMode.HIGH_Z
        ))

        hard_clash = bool(drivers_low and drivers_high)
        if drivers_low:
            resolved = 0
        elif drivers_high:
            resolved = 1
        elif self.pullup_enabled:
            resolved = 1
        else:
            resolved = self.released_value

        return ResolvedLineState(
            name=self.name,
            resolved=resolved,
            hard_clash=hard_clash,
            drivers_low=drivers_low,
            drivers_high=drivers_high,
            drivers_high_z=drivers_high_z,
            mode=self.mode,
            pullup_enabled=self.pullup_enabled,
        )

    def resolved_value(self, exclude=None):
        """Return the resolved digital value for this line."""
        return self.snapshot(exclude=exclude).resolved

    def has_hard_clash(self):
        """Return true if at least one hard-low and one hard-high driver exist."""
        return self.snapshot().hard_clash

    def assert_no_hard_clash(self, driver=None, mode=None, context=None):
        """Raise if any hard-low and hard-high drivers are active."""
        snapshot = self.snapshot()
        if not snapshot.hard_clash:
            return
        raise BusWireHardClash(
            snapshot,
            driver=self._key(driver) if driver is not None else None,
            mode=self._key(mode) if mode is not None else None,
            context=self._key(context) if context is not None else None,
        )

    def _key(self, value):
        return value.value if isinstance(value, Enum) else value

