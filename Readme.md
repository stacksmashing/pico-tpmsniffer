# Pico TPMSniffer

> This is experimental software and hardware. It's not ready to use for professional or production use.

The board (in /hardware/) is compatible with the "Debug Card" connector found on some Lenovo laptops only for LPC. 

The firmare supports LPC and SPI TPMs. Where for the later there are options to either sniff on the TPM
directly or if Buslines are shared with BIOS (typically Winbond 25Qxxx) SPI can also be sniffed there.

! The hardware is currently not compatible with the SPI / SPI-BIOS ! Currently you need to use either a 
testclip, probe pins, solder to the pins or other means to connect to the  TPM / BIOS pins.

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

Connect DI, DO, CLK, SELECT and GND according to this 
* GPIO 2 -----> DI
* GPIO 3 -----> DO
* GPIO 4 -----> CLK
* GPIO 5 -----> SELECT
* GND Pico ---> GND Bios/Tpm
