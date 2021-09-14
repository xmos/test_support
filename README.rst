
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
xobjdump --split [.xe]
xobjdump -S [.xe] -o [output_file_name.dump]
(The .xe must made with -g flag to enable the gdb bugger otherwise xcoverage won't work!)

It also needs a tracing file from xsim by running:
xsim --trace-to [output_file_name.txt] [.xe]

"xcov_process"
..............

This is the main function to be called in your test, then it will return back the result
It returns the average coverage and save the data in .xcov file in xcov dir.
.xcov file is necessary for the below "xcov_combine" function.

xcov_process(disasm, trace, xcov_dir)
@param disam: path to disasm file
@param trace: path to trace file
@param xcov_dir : path where xcov directory located
@return average coverage of all src file
@output generate xcov file for xcov_combine and save in xcov dir

"xcov_combine"
..............

This function read data (.xcov file) from xcov dir and create .rtf files which show the details of executed source code.

xcov_combine(xcov_dir)
@param xcov_dir: path where xcov directory located
@output .coverage and .rtf files





