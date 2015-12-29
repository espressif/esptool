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

Note that this document may be out of date. Use the built-in usage (`esptool -h`) when in doubt.

## Protocol

If GPIO0 and GPIO15 is pulled down and GPIO2 is pulled high when the module leaves reset,
then the bootloader will enter the UART download mode. The ROM auto-bauds, that is, it will
automagically detect which baud rate you are using. esptool defaults to 115200.

esptool uses the RTS and DTR modem status lines to automatically enter the bootloader.
Connect RTS to CH_PD (which is used as active-low reset) and DTR to GPIO0.

The bootloader protocol uses [SLIP](http://en.wikipedia.org/wiki/SLIP) framing.
Each packet begin and end with `0xC0`, all occurrences of `0xC0` and `0xDB` inside the packet
are replaced with `0xDB 0xDC` and `0xDB 0xDD`, respectively.

Inside the frame, the packet consists of a header and a variable-length body.
All multi-byte fields are little-endian.

### Request

Byte   | Name		| Comment
-------|----------------|-------------------------------
0      | Direction	| Always `0x00` for requests
1      | Command	| Requested operation, according to separate table
2-3    | Size		| Size of body
4-7    | Checksum	| XOR checksum of payload, only used in block transfer packets
8..n   | Body		| Depends on operation

### Response

Byte   | Name		| Comment
-------|----------------|-------------------------------
0      | Direction	| Always `0x01` for responses
1      | Command	| Same value as in the request packet that trigged the response
2-3    | Size		| Size of body, normally 2
4-7    | Value		| Response data for some operations
8..n   | Body		| Depends on operation
8      | Status		| Status flag, success (`0`) or failure (`1`)
9      | Error		| Last error code, not reset on success

### Opcodes

Byte   | Name			| Input		| Output
-------|------------------------|---------------|------------------------
`0x02` | Flash Download Start	| total size, number of blocks, block size, offset	|
`0x03` | Flash Download Data	| size, sequence number, data. checksum in value field. |
`0x04` | Flash Download Finish	| reboot flag? |
`0x05` | RAM Download Start	| total size, packet size, number of packets, memory offset |
`0x06` | RAM Download Finish	| execute flag, entry point |
`0x07` | RAM Download Data	| size, sequence numer, data. checksum in dedicated field. |
`0x08` | Sync Frame		| `0x07 0x07 0x12 0x20`, `0x55` 32 times |
`0x09` | Write register		| Four 32-bit words: address, value, mask and delay (in microseconds) | Body is `0x00 0x00` if successful
`0x0a` | Read register		| Address as 32-bit word | Read data as 32-bit word in `value` field
`0x0b` | Configure SPI params	| 24 bytes of unidentified SPI parameters |

### Checksum
Each byte in the payload is XOR'ed together, as well as the magic number `0xEF`.
The result is stored as a zero-padded byte in the 32-bit checksum field in the header.

## Firmware image format
The firmware file consists of a header, a variable number of data segments and a footer.
Multi-byte fields are little-endian.

### File header

Byte	| Description
--------|-----------------------
0	| Always `0xE9`
1	| Number of segments
2	| SPI Flash Interface (`0` = QIO, `1` = QOUT, `2` = DIO, `0x3` = DOUT)
3	| High four bits: `0` = 512K, `1` = 256K, `2` = 1M, `3` = 2M, `4` = 4M, Low four bits: `0` = 40MHz, `1`= 26MHz, `2` = 20MHz, `0xf` = 80MHz
4-7	| Entry point
8-n	| Segments

esptool overrides the 2nd and 3rd (start from 0) bytes according to the SPI flash info provided through command line option, regardless of corresponding bytes from the input .bin file that will be written to address 0x00000. So you must provide SPI flash info when running `esptool write_flash` command. For example `esptool write_flash -ff 80m -fm qio -fs 8m 0x00000 boot.bin 0x01000 user1.bin`

### Segment

Byte	| Description
--------|-----------------------
0-3	| Memory offset
4-7	| Segment size
8...n	| Data

### Footer
The file is padded with zeros until its size is one byte less than a multiple of 16 bytes. A last byte (thus making the file size a multiple of 16) is the checksum of the data of all segments. The checksum is defined as the xor-sum of all bytes and the byte `0xEF`.

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

