# Copyright 2026 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
"""Build one target of a configured CMake project. Shared by Pyxsim and Pyxrun."""
import math
import subprocess
from pathlib import Path
from Pyxsim._process import run_command


class BuildError(Exception):
    """build() could not build the executable; the message includes the build output."""


def build(xe, *, build_dir=None, timeout=600):
    """Build the one target that produces ``xe`` in an already-configured CMake build.

    Available as Pyxsim.build() and Pyxrun.build(), which are the same function.
    Call it before run() when a test must build on demand:
    one configuration out of many, or an application whose generated header the
    test has just rewritten. It does not configure, so the variants themselves are
    declared in CMakeLists.txt. The target is the executable's name without ``.xe``,
    as XCommon CMake names it.

    ``build_dir`` defaults to the nearest ``build`` directory above the executable
    that holds a CMake cache; pass it for any other layout. Raises BuildError if
    there is no such directory, or the build fails or exceeds ``timeout`` seconds.
    On timeout or interruption, stop the tool process tree before returning.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    xe = Path(xe).resolve()
    if build_dir is None:
        for parent in xe.parents:
            if (parent / "build" / "CMakeCache.txt").is_file():
                build_dir = parent / "build"
                break
        else:
            raise BuildError(f"No configured CMake build directory found above {xe}; "
                             "run cmake first or pass build_dir")
    build_dir = Path(build_dir).resolve()
    if not (build_dir / "CMakeCache.txt").is_file():
        raise BuildError(f"{build_dir} is not a configured CMake build directory; run cmake first")
    command = ["cmake", "--build", str(build_dir), "--target", xe.stem]
    try:
        result = run_command(command, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        raise BuildError(f"Building {xe.stem} exceeded {timeout} seconds\n{output}") from None
    if result.returncode != 0:
        raise BuildError(f"Building {xe.stem} failed with status {result.returncode}\n{result.stdout}")
    if not xe.is_file():
        raise BuildError(f"Building {xe.stem} succeeded but did not produce {xe}\n{result.stdout}")
