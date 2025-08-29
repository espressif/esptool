{IDF_TARGET_BOOTLOADER_OFFSET:default="0x0", esp32="0x1000", esp32s2="0x1000", esp32p4="0x2000", esp32c5="0x2000", esp32h2="0x0", esp32h21="0x0", esp32h4="0x2000"}

{IDF_TARGET_FLASH_FREQ_F:default="80", esp32c2="60", esp32h2="48", esp32h21="48", esp32h4="48"}

{IDF_TARGET_FLASH_FREQ_0:default="40", esp32c2="30", esp32h2="24", esp32h21="24", esp32h4="24"}

{IDF_TARGET_FLASH_FREQ:default="``40m``, ``26m``, ``20m``, ``80m``", esp32c2="``30m``, ``20m``, ``15m``, ``60m``", esp32h2="``24m``, ``16m``, ``12m``, ``48m``", esp32c6="``40m``, ``20m``, ``80m``, esp32c5="``40m``, ``20m``, ``80m``, esp32c61="``40m``, ``20m``, ``80m``", esp32h21="``24m``, ``16m``, ``12m``, ``48m``", esp32h4="``24m``, ``16m``, ``12m``, ``48m``"}


.. _flash-modes:

Flash Modes
===========

``write-flash`` and some other commands accept command line arguments to set bootloader flash mode, flash size and flash clock frequency. The chip needs correct mode, frequency and size settings in order to run correctly - although there is some flexibility.
A header at the beginning of a bootable image contains these values.

To override these values, the options ``--flash-mode``, ``--flash-size`` and/or ``--flash-freq`` must appear after ``write-flash`` on the command line, for example:

::

    esptool --port /dev/ttyUSB1 write-flash --flash-mode dio --flash-size 4MB 0x0 bootloader.bin

These options are only consulted when flashing a bootable image to an {IDF_TARGET_NAME} at offset {IDF_TARGET_BOOTLOADER_OFFSET}. These are addresses used by the ROM bootloader to load from flash. When flashing at all other offsets, these arguments are not used.

Flash Mode: ``--flash-mode``, ``-fm``
-------------------------------------

These set Quad Flash I/O or Dual Flash I/O modes. Valid values are ``keep``, ``qio``, ``qout``, ``dio``, ``dout``. The default is ``keep``, which keeps whatever value is already in the image file. This parameter can also be specified using the environment variable ``ESPTOOL_FM``.

.. only:: esp8266

    Most boards use ``qio`` mode. Some ESP8266 modules, including the ESP-12E modules on some (not all) NodeMCU boards, are dual I/O and the firmware will only boot when flashed with ``--flash-mode dio``.

.. only:: not esp8266

    Most {IDF_TARGET_NAME} modules use ``qio``, but are also dual I/O.

In ``qio`` mode, two additional GPIOs are used for SPI flash communications. If flash mode is set to ``dio`` then these pins are available for other purposes. Search for ``SPIWP`` and ``SPIHD`` pins in the `{IDF_TARGET_NAME} Technical Reference Manual <{IDF_TARGET_TRM_EN_URL}>`__ to learn more.

For a full explanation of these modes, see the :ref:`SPI Flash Modes page <spi-flash-modes>`.

Flash Frequency: ``--flash-freq``, ``-ff``
------------------------------------------

Clock frequency for SPI flash interactions. Valid values are ``keep``, {IDF_TARGET_FLASH_FREQ} (MHz). The default is ``keep``, which keeps whatever value is already in the image file. This parameter can also be specified using the environment variable ``ESPTOOL_FF``.

The flash chip connected to most chips works with {IDF_TARGET_FLASH_FREQ_0}MHz clock speeds, but you can try lower values if the device won't boot. The highest {IDF_TARGET_FLASH_FREQ_F}MHz flash clock speed will give the best performance, but may cause crashing if the flash or board design is not capable of this speed.

Flash Size: ``--flash-size``, ``-fs``
-------------------------------------

Size of the SPI flash, given in megabytes.

.. only:: esp8266

    Valid values are: ``keep``, ``detect``, ``256KB``, ``512KB``, ``1MB``, ``2MB``, ``4MB``, ``2MB-c1``, ``4MB-c1``, ``8MB``, ``16MB``

.. only:: esp32 or esp32c3 or esp32c6 or esp32c2 or esp32h2 or esp32c5 or esp32c61 or esp32h21 or esp32h4

    Valid values are: ``keep``, ``detect``, ``1MB``, ``2MB``, ``4MB``, ``8MB``, ``16MB``

.. only:: esp32s2 or esp32s3 or esp32p4

    Valid values are: ``keep``, ``detect``, ``1MB``, ``2MB``, ``4MB``, ``8MB``, ``16MB``, ``32MB``, ``64MB``, ``128MB``

.. note::

    Esptool uses power of two units, so in IEC units the size arguments are Mebibytes, although Espressif's technical documentation doesn't use the Mebi- prefix. This is due to compatibility reasons and to keep consistent with flash manufacturers.

.. only:: esp8266

    For ESP8266, some :ref:`additional sizes & layouts for OTA "firmware slots" are available <esp8266-and-flash-size>`.

The default ``--flash-size`` parameter is ``keep``. This means that if no ``--flash-size`` argument is passed when flashing a bootloader, the value in the bootloader .bin file header is kept instead of detecting the actual flash size and updating the header.

To enable automatic flash size detection based on SPI flash ID, add the argument ``esptool [...] write-flash [...] -fs detect``. If detection fails, a warning is printed and a default value of of ``4MB`` (4 megabytes) is used.

If flash size is not successfully detected, you can find the flash size by using the ``flash-id`` command and then looking up the ID from the output (see :ref:`Read SPI flash id <read-spi-flash-id>`).
Alternatively, read off the silkscreen labelling of the flash chip and search for its datasheet.

The default ``--flash-size`` parameter can also be overridden using the environment variable ``ESPTOOL_FS``.

.. only:: esp8266

    The ESP8266 SDK stores WiFi configuration at the "end" of flash, and it finds the end using this size. However there is no downside to specifying a smaller flash size than you really have, as long as you don't need to write an image larger than this size.

    ESP-12, ESP-12E and ESP-12F modules (and boards that use them such as NodeMCU, HUZZAH, etc.) usually have at least 4 megabyte / ``4MB`` (sometimes labelled 32 megabit) flash.

    .. _esp8266-and-flash-size:

    If using OTA, some additional sizes & layouts for OTA "firmware slots" are available. If not using OTA updates then you can ignore these extra sizes:

    +-------------------+-----------------------+-----------------+-----------------+
    | flash size arg    | Number of OTA slots   | OTA Slot Size   | Non-OTA Space   |
    +===================+=======================+=================+=================+
    | 256KB             | 1 (no OTA)            | 256KB           | N/A             |
    +-------------------+-----------------------+-----------------+-----------------+
    | 512KB             | 1 (no OTA)            | 512KB           | N/A             |
    +-------------------+-----------------------+-----------------+-----------------+
    | 1MB               | 2                     | 512KB           | 0KB             |
    +-------------------+-----------------------+-----------------+-----------------+
    | 2MB               | 2                     | 512KB           | 1024KB          |
    +-------------------+-----------------------+-----------------+-----------------+
    | 4MB               | 2                     | 512KB           | 3072KB          |
    +-------------------+-----------------------+-----------------+-----------------+
    | 2MB-c1            | 2                     | 1024KB          | 0KB             |
    +-------------------+-----------------------+-----------------+-----------------+
    | 4MB-c1            | 2                     | 1024KB          | 2048KB          |
    +-------------------+-----------------------+-----------------+-----------------+
    | 8MB [^]           | 2                     | 1024KB          | 6144KB          |
    +-------------------+-----------------------+-----------------+-----------------+
    | 16MB [^]          | 2                     | 1024KB          | 14336KB         |
    +-------------------+-----------------------+-----------------+-----------------+

    -  [^] Support for 8MB & 16MB flash size is not present in all ESP8266 SDKs. If your SDK doesn't support these flash sizes, use ``--flash-size 4MB``.

.. only:: not esp8266

    The ESP-IDF flashes a partition table to the flash at offset 0x8000. All of the partitions in this table must fit inside the configured flash size, otherwise the {IDF_TARGET_NAME} will not work correctly.
