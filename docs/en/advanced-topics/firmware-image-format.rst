Firmware Image Format
=====================

This is technical documentation for the firmware image format used by the ROM bootloader. These are the images created by ``esptool.py elf2image``.

The firmware file consists of a header, a variable number of data segments and a footer. Multi-byte fields are little-endian.

File Header
-----------

+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Byte   | Description                                                                                                                                                    |
+========+================================================================================================================================================================+
| 0      | Always ``0xE9``                                                                                                                                                |
+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1      | Number of segments                                                                                                                                             |
+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 2      | SPI Flash Interface (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``0x3`` = DOUT)                                                                                   |
+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 3      | High four bits: ``0`` = 512K, ``1`` = 256K, ``2`` = 1M, ``3`` = 2M, ``4`` = 4M, Low four bits: ``0`` = 40MHz, ``1``\ = 26MHz, ``2`` = 20MHz, ``0xf`` = 80MHz   |
+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 4-7    | Entry point                                                                                                                                                    |
+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 8-n    | Segments                                                                                                                                                       |
+--------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+

esptool overrides the 2nd and 3rd (start from 0) bytes according to the SPI flash info provided through command line option, regardless of corresponding bytes from the input .bin file that will be written to address 0x00000.
So you must provide SPI flash info when running ``esptool write_flash`` command. For example ``esptool write_flash -ff 80m -fm qio -fs 8m 0x00000 boot.bin 0x01000 user1.bin``

Segment
-------

+---------+-----------------+
| Byte    | Description     |
+=========+=================+
| 0-3     | Memory offset   |
+---------+-----------------+
| 4-7     | Segment size    |
+---------+-----------------+
| 8...n   | Data            |
+---------+-----------------+

Footer
------

The file is padded with zeros until its size is one byte less than a multiple of 16 bytes. A last byte (thus making the file size a multiple of 16) is the checksum of the data of all segments. The checksum is defined as the xor-sum of all bytes and the byte ``0xEF``.
