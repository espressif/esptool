# esptool

A cute Python utility to communicate with the ROM bootloader in Espressif ESP8266.
It is intended to be a simple, platform independent, open source replacement for XTCOM.

This is a work in progress; batteries are not yet included.

## Usage

This utility does not have a user interface yet. Hack it, like real hackers! ;)

## Protocol

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
`0x02` | Flash Download Start	|		|
`0x03` | Flash Download Data	|		|
`0x04` | Flash Download Finish	|		|
`0x05` | RAM Download Start	|		|
`0x06` | RAM Download Finish	|		|
`0x07` | RAM Download Data	|		|
`0x08` | Sync Frame		|		|
`0x09` | Write register		| Four 32-bit words: address, value, mask and delay (in microseconds) | Body is `0x00 0x00` if successful
`0x0a` | Read register		| Address as 32-bit word | Read data as 32-bit word in `value` field

### Checksum
Each byte in the payload is XOR'ed together, as well as the magic number `0xEF`.
The result is stored as a zero-padded byte in the 32-bit checksum field in the header.

## Flash image format
The flash file consists of a header, a variable number of data segments and a footer.
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

