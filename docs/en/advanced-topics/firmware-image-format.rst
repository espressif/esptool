{IDF_TARGET_FLASH_FREQ_F:default="80", esp32c2="60", esp32h2="48"}

{IDF_TARGET_FLASH_FREQ_0:default="40", esp32c2="30", esp32h2="24"}

{IDF_TARGET_FLASH_FREQ_1:default="26", esp32c2="20", esp32h2="16"}

{IDF_TARGET_FLASH_FREQ_2:default="20", esp32c2="15", esp32h2="12"}

{IDF_TARGET_BOOTLOADER_OFFSET:default="0x0", esp32="0x1000", esp32s2="0x1000", esp32p4="0x2000"}


.. _image-format:

Firmware Image Format
=====================

This is technical documentation for the firmware image format used by the ROM bootloader. These are the images created by ``esptool.py elf2image``.

.. only:: esp8266

    .. packetdiag:: diag/firmware_image_format_esp8266.diag
        :caption: Firmware image format
        :align: center

    The firmware file consists of a header, a variable number of data segments and a footer. Multi-byte fields are little-endian.

.. only:: not esp8266

    .. packetdiag:: diag/firmware_image_format.diag
        :caption: Firmware image format
        :align: center

    The firmware file consists of a header, an extended header, a variable number of data segments and a footer. Multi-byte fields are little-endian.

File Header
-----------

.. packetdiag:: diag/firmware_image_header_format.diag
    :caption: Firmware image header
    :align: center

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


.. only:: esp32s2 or esp32s3 or esp32p4

    +--------+------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                    |
    +========+================================================================================================+
    | 0      | Magic number (always ``0xE9``)                                                                 |
    +--------+------------------------------------------------------------------------------------------------+
    | 1      | Number of segments                                                                             |
    +--------+------------------------------------------------------------------------------------------------+
    | 2      | SPI Flash Mode (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``3`` = DOUT)                          |
    +--------+------------------------------------------------------------------------------------------------+
    | 3      | High four bits - Flash size (``0`` = 1MB, ``1`` = 2MB, ``2`` = 4MB, ``3`` = 8MB, ``4`` = 16MB, |
    |        | ``5`` = 32MB, ``6`` = 64MB, ``7`` = 128MB")                                                    |
    |        |                                                                                                |
    |        | Low four bits - Flash frequency (``0`` = {IDF_TARGET_FLASH_FREQ_0}MHz, ``1`` = {IDF_TARGET_FLASH_FREQ_1}MHz, ``2`` = {IDF_TARGET_FLASH_FREQ_2}MHz, ``0xf`` = {IDF_TARGET_FLASH_FREQ_F}MHz) |
    +--------+------------------------------------------------------------------------------------------------+
    | 4-7    | Entry point address                                                                            |
    +--------+------------------------------------------------------------------------------------------------+


.. only:: esp32c6

    +--------+------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                    |
    +========+================================================================================================+
    | 0      | Magic number (always ``0xE9``)                                                                 |
    +--------+------------------------------------------------------------------------------------------------+
    | 1      | Number of segments                                                                             |
    +--------+------------------------------------------------------------------------------------------------+
    | 2      | SPI Flash Mode (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``3`` = DOUT)                          |
    +--------+------------------------------------------------------------------------------------------------+
    | 3      | High four bits - Flash size (``0`` = 1MB, ``1`` = 2MB, ``2`` = 4MB, ``3`` = 8MB, ``4`` = 16MB) |
    |        |                                                                                                |
    |        | Low four bits - Flash frequency (``0`` = 80MHz, ``0`` = 40MHz, ``2`` = 20MHz)                  |
    +--------+------------------------------------------------------------------------------------------------+
    | 4-7    | Entry point address                                                                            |
    +--------+------------------------------------------------------------------------------------------------+

    .. note::
        Flash frequency with value ``0`` can mean either 80MHz or 40MHz based on MSPI clock source mode.


.. only:: esp32c5 or esp32c61

    +--------+------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                    |
    +========+================================================================================================+
    | 0      | Magic number (always ``0xE9``)                                                                 |
    +--------+------------------------------------------------------------------------------------------------+
    | 1      | Number of segments                                                                             |
    +--------+------------------------------------------------------------------------------------------------+
    | 2      | SPI Flash Mode (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``3`` = DOUT)                          |
    +--------+------------------------------------------------------------------------------------------------+
    | 3      | High four bits - Flash size (``0`` = 1MB, ``1`` = 2MB, ``2`` = 4MB, ``3`` = 8MB, ``4`` = 16MB) |
    |        |                                                                                                |
    |        | Low four bits - Flash frequency (``0xf`` = {IDF_TARGET_FLASH_FREQ_F}MHz, ``0`` = {IDF_TARGET_FLASH_FREQ_0}MHz, ``2`` = {IDF_TARGET_FLASH_FREQ_2}MHz)                |
    +--------+------------------------------------------------------------------------------------------------+
    | 4-7    | Entry point address                                                                            |
    +--------+------------------------------------------------------------------------------------------------+

.. only:: not (esp8266 or esp32c6 or esp32s3 or esp32s2 or esp32p4 or esp32c5 or esp32c61)

    +--------+------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                    |
    +========+================================================================================================+
    | 0      | Magic number (always ``0xE9``)                                                                 |
    +--------+------------------------------------------------------------------------------------------------+
    | 1      | Number of segments                                                                             |
    +--------+------------------------------------------------------------------------------------------------+
    | 2      | SPI Flash Mode (``0`` = QIO, ``1`` = QOUT, ``2`` = DIO, ``3`` = DOUT)                          |
    +--------+------------------------------------------------------------------------------------------------+
    | 3      | High four bits - Flash size (``0`` = 1MB, ``1`` = 2MB, ``2`` = 4MB, ``3`` = 8MB, ``4`` = 16MB) |
    |        |                                                                                                |
    |        | Low four bits - Flash frequency (``0`` = {IDF_TARGET_FLASH_FREQ_0}MHz, ``1`` = {IDF_TARGET_FLASH_FREQ_1}MHz, ``2`` = {IDF_TARGET_FLASH_FREQ_2}MHz, ``0xf`` = {IDF_TARGET_FLASH_FREQ_F}MHz) |
    +--------+------------------------------------------------------------------------------------------------+
    | 4-7    | Entry point address                                                                            |
    +--------+------------------------------------------------------------------------------------------------+


``esptool.py`` overrides the 2nd and 3rd (counted from 0) bytes according to the SPI flash info provided through the command line options (see :ref:`flash-modes`).
These bytes are only overridden if this is a bootloader image (an image written to a correct bootloader offset of {IDF_TARGET_BOOTLOADER_OFFSET}).
In this case, the appended SHA256 digest, which is a cryptographic hash used to verify the integrity of the image, is also updated to reflect the header changes.
Generating images without SHA256 digest can be achieved by running ``esptool.py elf2image`` with the ``--dont-append-digest`` argument.

.. only:: esp8266

    Individual segments come right after this header.

.. only:: not esp8266

    Extended File Header
    --------------------

    .. packetdiag:: diag/firmware_image_ext_header_format.diag
        :caption: Extended File Header
        :align: center

    +--------+---------------------------------------------------------------------------------------------------------+
    | Byte   | Description                                                                                             |
    +========+=========================================================================================================+
    | 0      | WP pin when SPI pins set via eFuse (read by ROM bootloader)                                             |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 1-3    | Drive settings for the SPI flash pins (read by ROM bootloader)                                          |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 4-5    | Chip ID (which ESP device is this image for)                                                            |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 6      | Minimal chip revision supported by the image (deprecated, use the following field)                      |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 7-8    | Minimal chip revision supported by the image (in format: major * 100 + minor)                           |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 9-10   | Maximal chip revision supported by the image (in format: major * 100 + minor)                           |
    +--------+---------------------------------------------------------------------------------------------------------+
    | 11-14  | Reserved bytes in additional header space, currently unused                                             |
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

    If ``hash appended`` in the extended file header is ``0x01``, a SHA256 digest “simple hash” (of the entire image) is appended after the checksum. This digest is separate to secure boot and only used for detecting corruption. The SPI flash info cannot be changed during flashing if hash is appended after the image.

    If secure boot is enabled, a signature is also appended (and the simple hash is included in the signed data). This image signature is `Secure Boot V1 <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v1.html#image-signing-algorithm>`_ and `Secure Boot V2 <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html#signature-block-format>`_ specific.


Analyzing a Binary Image
------------------------

To analyze a binary image and get a complete summary of its headers and segments, use the :ref:`image_info <image-info>` command.
