
Test Support
============

This repo contains helpers for testing XMOS xCORE applictions and includes the following:

- Python wrapper for the xCORE simulator (xsim)
- Python access functions for XE files
- Python code coverage measurement (xcov) for pytest 

Basic usage: xcoverage
----------------------

This only suit for xsim.

It requires disassembly and elf file which dumped from binary file (.xe file) by:

 * xobjdump --split [.xe].
 * xobjdump -S [.xe] -o [output_file_name.dump].
 * run the above 2 step by youself or run method from xcov: generate_elf_disasm("/path_to/(name-of-xe).xe", "/path_where_store_elf_and_disasm", "/path_to/(name-of-disasm).dump")

.xe must make with -g flag to enable the gdb bugger otherwise xcoverage won't work!.

It also needs a tracing file from xsim by running:

 * xsim --trace-to [output_file_name.txt] [.xe].

``xcov_process``
.......................

This is the main function to be called in your test.
It returns the average coverage and save the data in .xcov file in xcov dir.
.xcov file is necessary for the below "xcov_combine" function.

xcov_process(disasm, trace, xcov_dir).

 * @param disam: path to disasm file.
 * @param trace: path to trace file.
 * @param xcov_dir : path where xcov directory locates.
 * @return average coverage of all src file.
 * @output generate xcov file for xcov_combine and save in xcov dir.

``xcov_combine``
.......................

see example in test/test_xcoverage

``combine_process``
.......................

see example in test/test_xcoverage

``Mark the source code as not expected to be hit``
........................................................

Add a comment "//NE" beside you source code. It wouldn't be counted in coverage.

see example in test/test_xcoverage

Software version and dependencies
.................................

The CHANGELOG contains information about the current and previous versions.
For a list of direct dependencies, look for DEPENDENT_MODULES in test_support/module_build_info.








