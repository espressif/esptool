# esptool

A cute Python utility to communicate with the ROM bootloader in Espressif ESP8266.
It is intended to be a simple, platform independent, open source replacement for XTCOM.

[![Build Status](https://travis-ci.org/themadinventor/esptool.svg?branch=master)](https://travis-ci.org/themadinventor/esptool)

## Installation / dependencies

esptool depends on [pySerial](https://github.com/pyserial/pyserial#readme) for serial communication
with the target device.

If you choose to install esptool system-wide by running `python setup.py install`, then
this will be taken care of automatically.

If not using `setup.py`, then you'll have to install pySerial manually
by running something like `pip install pyserial`, `easy_install pyserial` or `apt-get install python-serial`,
depending on your platform. (The official pySerial installation instructions are
[here](https://pyserial.readthedocs.org/en/latest/pyserial.html#installation)).

## Usage

This utility actually have a user interface! It uses [Argparse](https://docs.python.org/dev/library/argparse.html)
and is rather self-documenting. Try running `esptool -h`, `esptool write_flash -h`, etc.
Or hack the script to your hearts content.

### Ports

The serial port is selected using the `-p` option, like `-p /dev/ttyUSB0` (on unixen like Linux and OSX) or `-p COM1`
(on Windows). The perhaps not so obvious corner case here is when you run esptool in Cygwin on Windows, where you have to convert the Windows-style name into an Unix-style path (`COM1` -> `/dev/ttyS0`, and so on).

The baudrate may be set using `-b 921600` (or another baudrate of your choice) to speed up large transfers.

### Examples
Typical usage:

Converting an ELF file to the two binary blobs to be flashed:
```
./esptool.py elf2image my_app.elf
```
This creates `my_app.elf-0x00000.bin` and `my_app.elf-0x40000.bin`.

Writing those binaries to flash:
```
./esptool.py write_flash 0x00000 my_app.elf-0x00000.bin 0x40000 my_app.elf-0x40000.bin
```

You can also create a bootable application image from binary blobs:
```
./esptool.py make_image -f app.text.bin -a 0x40100000 -f app.data.bin -a 0x3ffe8000 -f app.rodata.bin -a 0x3ffe8c00 app.flash.bin
```

Dumping the ROM (64 KiB) from the chip:
```
./esptool.py dump_mem 0x40000000 65536 iram0.bin
```

Reading the MAC Address:
```
./esptool.py read_mac
```

Reading the SPI Flash ID:
```
./esptool.py flash_id
```

Refer to [flashrom source code](http://code.coreboot.org/p/flashrom/source/tree/HEAD/trunk/flashchips.h) for flash chip manufacturer name and part number.

Verifying flash that was already written
```
./esptool.py verify_flash 0x40000 my_app.elf-0x40000.bin
```

NOTE: esptool.py may update the first 16 bytes (offset 0) of the ESP8266 flash when writing, to reflect the provided flash mode and flash size parameters. If this happens then the verify may fail on these bytes.

For more information and options, view the built-in usage message (`esptool -h`).

## Entering the Bootloader

If GPIO0 and GPIO15 is pulled down and GPIO2 is pulled high when the module leaves reset,
then the bootloader will enter the UART download mode. The ROM auto-bauds, that is, it will
automagically detect which baud rate you are using. esptool defaults to 115200.

esptool.py uses the RTS and DTR modem status lines to automatically enter the bootloader.
Connect RTS to CH_PD (which is used as active-low reset) and DTR to GPIO0.

## Internal Technical Documentation

The [repository wiki](https://github.com/themadinventor/esptool/wiki) contains some technical documentation regarding the protocol and file formats used by the ROM bootloader. This may be useful if you're developing `esptool.py`:

* [Firmware Image Format](https://github.com/themadinventor/esptool/wiki/Firmware-Image-Format)
* [Serial Protocol](https://github.com/themadinventor/esptool/wiki/Serial-Protocol)


## Boot log
The boot rom writes a log to the UART when booting. The timing is a little bit unusual: 74880 baud

```
ets Jan  8 2014,rst cause 1, boot mode:(3,7)

load 0x40100000, len 24236, room 16 
tail 12
chksum 0xb7
ho 0 tail 12 room 4
load 0x3ffe8000, len 3008, room 12 
tail 4
chksum 0x2c
load 0x3ffe8bc0, len 4816, room 4
tail 12
chksum 0x46
csum 0x46
```

## About

esptool was initially created by Fredrik Ahlberg (themadinventor, kongo), but has since received improvements from several members of the ESP8266 community, including pfalcon, tommie, 0ff and george-hopkins.

This document and the attached source code is released under GPLv2.

