// Copyright 2026 XMOS LIMITED.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.
#include <stdio.h>
#include <xcore/port.h>
#include <xcore/hwtimer.h>
#include <xcore/assert.h>

/*
 * Firmware for Pyxsim/tests/test_app_assert.py.
 *
 * Prints "1 In main", waits 10000 timer ticks and then fails xassert(0).
 * The build defines LIBXCORE_XASSERT_IS_ASSERT, so the failure ends the
 * simulation with a non-zero result. "2 In main" must never be printed.
 * The Python test checks that Pyxsim reports this run as a failure.
 */

int main()
{
    hwtimer_t timer = hwtimer_alloc();
    printf("1 In main\n");
    hwtimer_delay(timer, 10000);
    xassert(0);
    printf("2 In main\n");

    return 0;
}
