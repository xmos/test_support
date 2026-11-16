#############
Code Coverage
#############

``test_support`` includes Python code coverage measurement helpers for pytest
tests that run on ``xsim``.

************
Requirements
************

Coverage processing requires a disassembly file and ELF file extracted from the
``.xe`` binary:

.. code-block:: bash

   xobjdump --split app.xe
   xobjdump -S app.xe -o app.dump

The same files can be generated from Python by calling
``generate_elf_disasm(xe_path, output_dir, dump_path)``.

The ``.xe`` file must be built with debug information enabled using ``-g`` so
that coverage can be mapped back to source lines.

Coverage also requires a trace file from ``xsim``:

.. code-block:: bash

   xsim --trace-to trace.txt app.xe

************
xcov_process
************

``xcov_process(disasm, trace, xcov_dir)`` processes a disassembly file and xsim
trace, returns the average source coverage, and writes an ``.xcov`` file under
``xcov_dir``. The generated ``.xcov`` file is used by the combine helpers.

Arguments:

* ``disasm``: path to the disassembly file.
* ``trace``: path to the xsim trace file.
* ``xcov_dir``: directory where ``.xcov`` files are stored.

************
xcov_combine
************

``xcov_combine`` combines coverage data from multiple ``.xcov`` files. See
``examples/code_coverage`` for example usage.

***************
combine_process
***************

``combine_process`` provides a higher-level combine flow. See
``examples/code_coverage`` for example usage.

*******************
Coverage Exclusions
*******************

Add ``//NOCOVER`` beside a source line to exclude it from coverage. Use
``//NOCOVERSTART`` and ``//NOCOVEREND`` to exclude a block.

An excluded file list can also be passed to ``xcov_process``:

.. code-block:: python

   xcov_process(
       disasm,
       trace,
       xcov_dir,
       excluded_file=["/tests/shared/test_main.xc", "/tests/shared/shared.h"],
   )
