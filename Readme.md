# Pico TPMSniffer

> This is experimental software and hardware. It's not ready to use for professional or production use.

The board (in /hardware/) is compatible with the "Debug Card" connector found on some Lenovo laptops only for LPC. 

The firmare supports LPC and SPI TPMs. Where for the later sniffing is performed on the BIOS Chip (typically Winbond 25Qxxx) SPI lines are shared with the TPM Chip.

! The hardware is currently not compatible with the SPI / SPI-BIOS ! Currently you need to use either a 
testclip, probe pins, solder to the pins or other means to connect to the  TPM / BIOS pins sniffing SPI.

## Building

```
export PICO_SDK_PATH=path to your Pico-SDK
mkdir build
cd build
cmake ..
make
```

## Hardware

The board files are in `hardware/`, the Pogo pins used are of the type: P50-B1-16mm

## Usage

### LPC

Just connect to the serial port, boot your machine, and push against the card connector!

### SPI / SPI-BIOS

Connect (BIOS Chip) DI, DO, CLK, SELECT and GND according to this 
* GPIO 2 -----> DI
* GPIO 3 -----> DO
* GPIO 4 -----> CLK
* GPIO 5 -----> SELECT
* GND Pico ---> GND Bios/Tpm

Start the laptop before the 5seconds countdown is finished. Otherwise the sniffer might not capture
the TPM key. The sniffer still seems to have an issue with the first 1 second of the boot sequence. 