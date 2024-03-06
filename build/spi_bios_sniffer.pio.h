// -------------------------------------------------- //
// This file is autogenerated by pioasm; do not edit! //
// -------------------------------------------------- //

#pragma once

#if !PICO_NO_HARDWARE
#include "hardware/pio.h"
#endif

// ---------------- //
// spi_bios_sniffer //
// ---------------- //

#define spi_bios_sniffer_wrap_target 2
#define spi_bios_sniffer_wrap 6

static const uint16_t spi_bios_sniffer_program_instructions[] = {
    0x2023, //  0: wait   0 pin, 3                   
    0x20a3, //  1: wait   1 pin, 3                   
            //     .wrap_target
    0x2022, //  2: wait   0 pin, 2                   
    0x20a2, //  3: wait   1 pin, 2                   
    0x00c6, //  4: jmp    pin, 6                     
    0x0002, //  5: jmp    2                          
    0x4002, //  6: in     pins, 2                    
            //     .wrap
};

#if !PICO_NO_HARDWARE
static const struct pio_program spi_bios_sniffer_program = {
    .instructions = spi_bios_sniffer_program_instructions,
    .length = 7,
    .origin = -1,
};

static inline pio_sm_config spi_bios_sniffer_program_get_default_config(uint offset) {
    pio_sm_config c = pio_get_default_sm_config();
    sm_config_set_wrap(&c, offset + spi_bios_sniffer_wrap_target, offset + spi_bios_sniffer_wrap);
    return c;
}

static inline void spi_bios_sniffer_program_init(PIO pio, uint sm, uint offset, uint base_pin, uint jmp_pin) {
    pio_sm_config c = spi_bios_sniffer_program_get_default_config(offset);
    // initialize 4 input pins DO, DI, CLK, SELECT
    for(int i=0; i < 4; i++) {
        pio_gpio_init(pio, base_pin + i);
    }
    //gpio_pull_down(base_pin + 3); // set inner pull up resistor for SELET pin
    // initialize JUMP PIN (Here this is actually not necessary)
    // pio_gpio_init(pio, jmp_pin);
    // Set all pins to input (false = input)
    pio_sm_set_consecutive_pindirs(pio, sm, base_pin, 4, false);
    sm_config_set_in_pins(&c, base_pin);
    sm_config_set_jmp_pin(&c, jmp_pin);
    // set autopush at threshold 16 bit
    // we are reading DO and DI at the same time
    sm_config_set_in_shift (&c, false, true, 16);
    // Chain FIFOs together as we will *only* receive.
    // This will ensure we will not block.
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_RX);
    // run at max clockrate
    float div = 1.f ; //(float)clock_get_hz(clk_sys) / 135000000.0;
    sm_config_set_clkdiv(&c, div);
    // Load our configuration, and jump to the start of the program
    pio_sm_init(pio, sm, offset, &c);
    // Set the state machine running
    pio_sm_set_enabled(pio, sm, true);
}

#endif

