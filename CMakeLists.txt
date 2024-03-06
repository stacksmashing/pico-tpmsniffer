cmake_minimum_required(VERSION 3.13)
# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(tpm_sniffer)
 
pico_sdk_init()

add_executable(tpm_sniffer)

pico_generate_pio_header(tpm_sniffer ${CMAKE_CURRENT_LIST_DIR}/lpc_sniffer.pio)
#pico_generate_pio_header(tpm_sniffer ${CMAKE_CURRENT_LIST_DIR}/spi_sniffer.pio)
pico_generate_pio_header(tpm_sniffer ${CMAKE_CURRENT_LIST_DIR}/spi_bios_sniffer.pio)
target_sources(tpm_sniffer PRIVATE main.c)

target_link_libraries(tpm_sniffer PRIVATE
        pico_stdlib
        hardware_pio
        hardware_flash
        pico_multicore
        )
pico_enable_stdio_usb(tpm_sniffer 1)
pico_add_extra_outputs(tpm_sniffer)
