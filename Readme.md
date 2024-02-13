# Pico TPMSniffer

> This is experimental software and hardware. It's not ready to use for professional or production use.

The board (in /hardware/) is compatible with the "Debug Card" connector found on some Lenovo laptops. The firmware currently only supports LPC, not SPI TPMs.

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

Just connect to the serial port, boot your machine, and push against the card connector!
