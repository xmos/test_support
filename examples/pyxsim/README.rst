##############
Pyxsim example
##############

************
Introduction
************

This example demonstrates a simple use of a simthread to interact with
the simulated xcore application, with the following sequence:

* xcore app enables two 1-bit ports on tile 0, with a trigger on the
  second port changing value

* simthread waits for the value on the first port to change

* xcore app changes the value on the first port

* simthread sees the first port change value and then changes the
  value on the second port

* xcore app wakes up from waiting for the second port to change

*************
Build and run
*************

.. code-block:: console

   cmake -G "Unix Makefiles" -B build
   xmake -C build

Install the test_support package using pip, and then run:

.. code-block:: console

   python example_pyxsim.py

The expected output is:

.. code-block:: console

   [xcore] Change value on p0
   [simthread] Transition seen on p0
   [simthread] Change value on p1
   [xcore] Transition seen on p1

***********************
VCD/instruction tracing
***********************

VCD and instruction tracing are enabled by default in ``example_pyxsim.py``.
The data is captured in the ``logs`` directory, and can be viewed with
a waveform viewer such as ``gtkwave``.
