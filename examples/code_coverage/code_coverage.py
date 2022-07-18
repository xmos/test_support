# Copyright 2022 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
from xcoverage.xcov import *
import subprocess as ps
import pytest
import sys
import os

def build_xe(xe, clean=False):
    build_config = xe
    cmd = "xmake "
    if clean:
        cmd += "clean "
    cmd += "CONFIG=%s " % build_config
    ps.run(cmd, shell=True, check=True)

def code_coverage():

    #define xcov_combine and combine_proccess
    xcov_comb = xcov_combine()
    combine_test = combine_process(os.path.dirname(os.path.abspath(__file__)))

    testname = os.path.basename(__file__).split(".")[0]
    xe_bin = testname + "_demo"
    binary = f"bin/demo/{xe_bin}.xe"
    split_dir = f"bin/demo"
    disasm = f"bin/demo/{xe_bin}.dump"
    tracefile = f"bin/demo/trace.txt"

    #build xe and generate disassembly file
    build_xe("demo", clean=False)
    print(binary)
    print(split_dir)
    print(disasm)
    generate_elf_disasm(binary, split_dir, disasm)

    #run xsim
    ps.run("xsim --trace-to %s %s" % (tracefile, binary), shell=True)

    #run code coverage calculation
    coverage = xcov_process(disasm, tracefile, split_dir)
    #run coverage result combine for each source file
    xcov_comb.run_combine(split_dir)
    #merge cobined result over different process
    coverage = combine_test.do_combine_test()
    combine_test.generate_merge_src()
    # teardowm - remove tmp file
    combine_test.remove_tmp_testresult(combine_test.tpath)

if __name__ == "__main__":
    code_coverage()
