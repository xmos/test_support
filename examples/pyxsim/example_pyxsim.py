# Copyright 2025-2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
import os
from pathlib import Path

import Pyxsim


class ExampleSimThread(Pyxsim.SimThread):
    def __init__(self) -> None:
        self._port0 = "tile[0]:XS1_PORT_1G"
        self._port1 = "tile[0]:XS1_PORT_1H"

    def run(self) -> None:
        self.wait_for_port_pins_change([self._port0])
        print("[simthread] Transition seen on p0")

        val = self.xsi.sample_port_pins(self._port1)
        print("[simthread] Change value on p1")
        self.xsi.drive_port_pins(self._port1, 1 - val)


def main() -> None:
    XE_OVERRIDE = os.environ.get("XE_FILE_OVERRIDE")
    if XE_OVERRIDE:
        xe = Path(XE_OVERRIDE)
    else:
        xe = Path(__file__).parent / "bin" / "example_pyxsim.xe"
    assert xe.exists()

    Pyxsim.run_with_pyxsim(
        xe,
        [ExampleSimThread()],
        simargs=["--max-cycles", "10000"],
        instTracing=True,
        vcdTracing=True,
    )


if __name__ == "__main__":
    main()
