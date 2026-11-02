// Copyright 2026 XMOS LIMITED.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.
#include <stdio.h>
#include <xcore/port.h>
#include <xcore/hwtimer.h>
#include <xcore/assert.h>


int main()
{
    hwtimer_t timer = hwtimer_alloc();
    printf("1 In main\n");
    hwtimer_delay(timer, 10000);
    xassert(0);
    printf("2 In main\n");

    return 0;
}
