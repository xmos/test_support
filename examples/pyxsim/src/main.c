// Copyright 2025 XMOS LIMITED.
// This Software is subject to the terms of the XMOS Public Licence: Version 1.
#include <print.h>
#include <xcore/port.h>
#include <xcore/select.h>

int main() {
    port_t p1 = XS1_PORT_1H;
    port_enable(p1);

    unsigned p1_state = port_in(p1);
    port_set_trigger_in_not_equal(p1, p1_state);
    printstrln("[xcore] Change value on p0");

    port_t p0 = XS1_PORT_1G;
    port_enable(p0);

    unsigned p0_state = port_in(p0);
    port_out(p0, 1 - p0_state);

    SELECT_RES(
        CASE_THEN(p1, on_port_change)
    )
    {
        on_port_change: {
            printstrln("[xcore] Transition seen on p1");
            break;
        }
    }

    port_disable(p0);
    port_disable(p1);

    return 0;
}
