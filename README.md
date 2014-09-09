# esptool

A cute Python utility to communicate with the ROM bootloader in Espressif ESP8266.
It is intended to be a simple, platform independent, open source replacement for XTCOM.

This is a work in progress; it is usable but expect some rough edges.

## Usage

This utility actually have a user interface! It uses [Argparse](https://docs.python.org/dev/library/argparse.html)
and is rather self-documenting. Try running `esptool -h`.
Or hack the script to your hearts content.

### Examples
The probably most useful command; writing an application to flash:
```
./esptool.py write_flash 0x000000 wi07c.rom
```

Creating an application image:
```
./esptool.py make_image -f app.text.bin -a 0x40100000 -f app.data.bin -a 0x3ffe8000 -f app.rodata.bin -a 0x3ffe8c00 app.flash.bin
```

Dumping the ROM:
```
./esptool.py dump_mem 0x40000000 65536 iram0.bin
```

## Protocol

If GPIO0 and GPIO15 is pulled down and GPIO2 is pulled high when the module leaves reset,
then the bootloader will enter the UART download mode. It communicates over 115200 8N1.

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
2-3    | Size		| Size of body
4-7    | Value		| Response data for some operations
8..n   | Body		| Depends on operation

### Opcodes

Byte   | Name			| Input		| Output
-------|------------------------|---------------|------------------------
`0x02` | Flash Download Start	| total size, 0x200, block size, offset	|
`0x03` | Flash Download Data	| size, sequence number, data. checksum in dedicated field. |
`0x04` | Flash Download Finish	| reboot flag? |
`0x05` | RAM Download Start	| total size, packet size, number of packets, memory offset |
`0x06` | RAM Download Finish	| execute flag, entry point |
`0x07` | RAM Download Data	| size, sequence numer, data. checksum in dedicated field. |
`0x08` | Sync Frame		| `0x07 0x07 0x12 0x20`, `0x55` 32 times |
`0x09` | Write register		| Four 32-bit words: address, value, mask and delay (in microseconds) | Body is `0x00 0x00` if successful
`0x0a` | Read register		| Address as 32-bit word | Read data as 32-bit word in `value` field

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
2-3	| Padding/unused
4-7	| Entry point
8-n	| Segments

### Segment

Byte	| Description
--------|-----------------------
0-3	| Memory offset
4-7	| Segment size
8...n	| Data

### Footer
The footer is 16 bytes, function unknown but probably some kind of checksum.

## Boot log
The boot rom writes a log to the UART when booting. The timing is a little bit unusual: 75000 baud (at least on my modules, when doing a cold boot)

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

This information is collected through research by Fredrik Ahlberg.
Feel free to contact me on [GitHub](https://github.com/themadinventor) or through fredrik at z80 dot se.

This document and the attached source code is released under GPLv2.

