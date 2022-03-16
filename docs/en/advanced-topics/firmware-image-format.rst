Firmware Image Format
=====================

This is technical documentation for the firmware image format used by the ROM bootloader. These are the images created by ``esptool.py elf2image``.

.. only:: esp8266

    The firmware file consists of a header, a variable number of data segments and a footer. Multi-byte fields are little-endian.

.. only:: not esp8266

    The firmware file consists of a header, an extended header, a variable number of data segments and a footer. Multi-byte fields are little-endian.

File Header
-----------

The image header is 8 bytes long:

.. only:: esp8266

    +--------+--------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                      |
    +========+==================================================================================================+
    | 0      | Magic number (always ``0xE9``)                                                                   |
    +--------+--------------------------------------------------------------------------------------------------+
    | 1      | Number of segments                                                                               |
    +--------+--------------------------------------------------------------------------------------------------+
    | 2      | SPI Flash Mode (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``3`` = DOUT)                            |
    +--------+--------------------------------------------------------------------------------------------------+
    | 3      | High four bits - Flash size (``0`` = 512KB, ``1`` = 256KB, ``2`` = 1MB, ``3`` = 2MB, ``4`` = 4MB,|
    |        | ``5`` = 2MB-c1, ``6`` = 4MB-c1, ``8`` = 8MB, ``9`` = 16MB)                                       |
    |        |                                                                                                  |
    |        | Low four bits - Flash frequency (``0`` = 40MHz, ``1`` = 26MHz, ``2`` = 20MHz, ``0xf`` = 80MHz)   |
    +--------+--------------------------------------------------------------------------------------------------+
    | 4-7    | Entry point address                                                                              |
    +--------+--------------------------------------------------------------------------------------------------+

.. only:: not esp8266

    +--------+--------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                      |
    +========+==================================================================================================+
    | 0      | Magic number (always ``0xE9``)                                                                   |
    +--------+--------------------------------------------------------------------------------------------------+
    | 1      | Number of segments                                                                               |
    +--------+--------------------------------------------------------------------------------------------------+
    | 2      | SPI Flash Mode (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``3`` = DOUT)                            |
    +--------+--------------------------------------------------------------------------------------------------+
    | 3      | High four bits - Flash size (``0`` = 1MB, ``1`` = 2MB, ``2`` = 4MB, ``3`` = 8MB, ``4`` = 16MB)   |
    |        |                                                                                                  |
    |        | Low four bits - Flash frequency (``0`` = 40MHz, ``1`` = 26MHz, ``2`` = 20MHz, ``0xf`` = 80MHz)   |
    +--------+--------------------------------------------------------------------------------------------------+
    | 4-7    | Entry point address                                                                              |
    +--------+--------------------------------------------------------------------------------------------------+

.. only:: esp32c2 or esp32h2

    .. fail_when_new_target_added::

        TODO: Update flash frequency lists to be esp32c2 or esp32h2 specific

esptool.py overrides the 2nd and 3rd (start from 0) bytes according to the SPI flash info provided through command line option, regardless of corresponding bytes from the input .bin file that will be written to address 0x00000.
So you must provide SPI flash info when running ``esptool.py write_flash`` command. For example: ``esptool.py write_flash -ff 80m -fm qio -fs 1MB 0x00000 boot.bin 0x01000 user1.bin``

.. only:: not esp8266

    Please note that the appended SHA256 hash becomes incorrect when esptool.py overrides these SPI flash info bytes in a bootloader image, which leads to an error if Secure Boot is enabled.

.. only:: esp8266

    Individual segments come right after this header.

.. only:: not esp8266

    Extended File Header
    --------------------

    The 16-byte long extended header comes right after the image header, individual segments come right after it:

    +--------+---------------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                             |
    +========+=========================================================================================================+
    | 0      | WP pin when SPI pins set via efuse (read by ROM bootloader)                                             |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 1-3    | Drive settings for the SPI flash pins (read by ROM bootloader)                                          |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 4-5    | Chip ID (which ESP device is this image for)                                                            |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 6      | Minimum chip revision supported by the image                                                            |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 7-14   | Reserved bytes in additional header space, currently unused                                             |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 15     | Hash appended (If 1, SHA256 digest is appended after the checksum)                                      |
    +--------+---------------------------------------------------------------------------------------------------------+

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

.. only:: not esp8266

    If ``hash appended`` in the extended file header is ``0x01``, a SHA256 digest “simple hash” (of the entire image) is appended after the checksum. This digest is separate to secure boot and only used for detecting corruption.

    If secure boot is enabled, a signature is also appended (and the simple hash is included in the signed data). This image signature is `Secure Boot V1 <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v1.html#image-signing-algorithm>`_ and `Secure Boot V2 <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html#signature-block-format>`_ specific.


.. only:: not esp8266

    Analyzing the Binary Image Format
    ---------------------------------

    A great tool to inspect and parse the binary image format is the `Kaitai Struct online IDE <https://ide.kaitai.io/>`_. It allows the user to describe types and structures, import a real binary image and watch how these get parsed in real-time.

    Kaitai Struct description of the binary structure used by Espressif chips can `be found here. <https://gist.github.com/igrr/ab899cef9b121134785a82eaee50ed89>`_
