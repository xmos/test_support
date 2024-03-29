# Copyright 2016-2022 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
from math import gcd
from xml.dom.minidom import parse
import os
import re
import tempfile

from Pyxsim.xmostest_subprocess import call, call_get_output
from Pyxsim.testers import TestError


def lcm(a, b):
    return (a * b) // gcd(a, b)


class Xe:
    def _get_platform_info(self):
        call(["xobjdump", "--split", self.path], silent=True, cwd=self._tempdir)
        xn = parse("%s/platform_def.xn" % self._tempdir)
        self._tile_map = {}
        self.tiles = []
        lcm_freq = 1
        for node in xn.getElementsByTagName("Node"):
            freq = node.getAttribute("SystemFrequency")
            if freq:
                freq = int(freq.replace("MHz", ""))
                lcm_freq = lcm(lcm_freq, freq)
                node_type = node.getAttribute("Type")
            for tile in node.getElementsByTagName("Tile"):
                self._tile_map[
                    node.getAttribute("Id"), tile.getAttribute("Number")
                ] = tile.getAttribute("Reference")
                self.tiles.append(tile.getAttribute("Reference"))
        self.freq = lcm_freq
        self.node_type = node_type

        config = parse("%s/config.xml" % self._tempdir)
        self._port_map = {}
        for pin_node in config.getElementsByTagName("Pin"):
            name = pin_node.getAttribute("name")
            (package, pin) = name.split(":")
            for port_node in pin_node.getElementsByTagName("Port"):
                port = "tile[%s]:%s" % (
                    port_node.getAttribute("core"),
                    port_node.getAttribute("name"),
                )
                bitnum = int(port_node.getAttribute("bitNum"))
                if port not in self._port_map:
                    self._port_map[port] = []
                self._port_map[port].append((package, pin, bitnum))

    def get_port_pins(self, port):
        m = re.match(r"([^\.]*)\.(\d*)", port)
        if m:
            port = m.groups(0)[0]
            bit = int(m.groups(0)[1])
            pins = self._port_map[port]
            for (package, pin, bitnum) in pins:
                if bitnum == bit:
                    return [(package, pin, bitnum)]
            raise TestError("Cannot find port pins")
        return self._port_map[port]

    def _get_symtab(self):
        stdout, _stderr = call_get_output(["xobjdump", "-t", self.path])
        call_get_output(["xobjdump", "-t", self.path])
        current_tile = None
        symtab = {}
        for line in stdout:
            line = str(line, "utf8")
            m = re.match(r"Loadable.*for (.*) \(node \"(\d*)\", tile (\d*)", line)
            if m:
                current_tile = m.groups(0)[0]
            m = re.match(r"(0x[0-9a-fA-F]*).....([^ ]*) *(0x[0-9a-fA-F]*) (.*)$", line)
            if m and current_tile is not None:
                (address, section, _size, name) = m.groups(0)
                if section != "*ABS*":
                    address = int(address, 0)
                    symtab[current_tile, name] = address
        self.symtab = symtab

    def __init__(self, path):
        if not os.path.isfile(path):
            raise IOError("Cannot find file: %s" % path)
        self.path = os.path.abspath(path)
        self._symtab = {}
        self._tempdir = tempfile.mkdtemp()
        self._get_platform_info()
        self._get_symtab()

    def __del__(self):
        if self._tempdir is not None:
            for root, dirs, files in os.walk(self._tempdir, topdown=False):
                for f in files:
                    p = os.path.join(root, f)
                    os.remove(p)
                for d in dirs:
                    p = os.path.join(root, d)
                    os.rmdir(p)
            os.rmdir(self._tempdir)
