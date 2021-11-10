.. _flash-modes:

Flash Modes
===========

``write_flash`` and some other commands accept command line arguments to set bootloader flash mode, flash size and flash clock frequency. The chip needs correct mode, frequency and size settings in order to run correctly - although there is some flexibility.
A header at the beginning of a bootable image contains these values.

To override these values, the options ``--flash_mode``, ``--flash_size`` and/or ``--flash_freq`` must appear after ``write_flash`` on the command line, for example:

::

    esptool.py --port /dev/ttyUSB1 write_flash --flash_mode dio --flash_size 4MB 0x0 bootloader.bin

These options are only consulted when flashing a bootable image to an ESP8266 at offset 0x0, or an ESP32 at offset 0x1000. These are addresses used by the ROM bootloader to load from flash. When flashing at all other offsets, these arguments are not used.

Flash Mode (--flash\_mode, -fm)
-------------------------------

These set Quad Flash I/O or Dual Flash I/O modes. Valid values are ``keep``, ``qio``, ``qout``, ``dio``, ``dout``. The default is ``keep``, which keeps whatever value is already in the image file. This parameter can also be specified using the environment variable ``ESPTOOL_FM``.

Most boards use ``qio`` mode. Some ESP8266 modules, including the ESP-12E modules on some (not all) NodeMCU boards, are dual I/O and the firmware will only boot when flashed with ``--flash_mode dio``. Most ESP32 modules are also dual I/O.

In ``qio`` mode, two additional GPIOs (9 and 10) are used for SPI flash communications. If flash mode is set to ``dio`` then these pins are available for other purposes.

For a full explanation of these modes, see the :ref:`SPI Flash Modes page <spi-flash-modes>`.

Flash Frequency (--flash\_freq, -ff)
------------------------------------

Clock frequency for SPI flash interactions. Valid values are ``keep``, ``40m``, ``26m``, ``20m``, ``80m`` (MHz). The default is ``keep``, which keeps whatever value is already in the image file. This parameter can also be specified using the environment variable ``ESPTOOL_FF``.

The flash chip connected to most chips works with 40MHz clock speeds, but you can try lower values if the device won't boot. The highest 80MHz flash clock speed will give the best performance, but may cause crashing if the flash or board design is not capable of this speed.

Flash Size (--flash\_size, -fs)
-------------------------------

Size of the SPI flash, given in megabytes. Valid values vary by chip type:

+------------------+--------------------------------------------------------------------------------------------------------------------+
| Chip             | flash\_size values                                                                                                 |
+==================+====================================================================================================================+
| ESP32 and later  | ``keep``, ``detect``, ``1MB``, ``2MB``, ``4MB``, ``8MB``, ``16MB``                                                 |
+------------------+--------------------------------------------------------------------------------------------------------------------+
| ESP8266          | ``keep``, ``detect``, ``256KB``, ``512KB``, ``1MB``, ``2MB``, ``4MB``, ``2MB-c1``, ``4MB-c1``, ``8MB``, ``16MB``   |
+------------------+--------------------------------------------------------------------------------------------------------------------+

For ESP8266, some `additional sizes & layouts for OTA "firmware slots" are available <#esp8266-and-flash-size>`_.

The default ``--flash_size`` parameter is ``keep``. This means that if no ``--flash_size`` argument is passed when flashing a bootloader, the value in the bootloader .bin file header is kept instead of detecting the actual flash size and updating the header.

To enable automatic flash size detection based on SPI flash ID, add the argument ``esptool.py [...] write_flash [...] -fs detect``. If detection fails, a warning is printed and a default value of of ``4MB`` (4 megabytes) is used.

If flash size is not successfully detected, you can find the flash size by using the ``flash_id`` command and then looking up the ID from the output (see :ref:`Read SPI flash id <read-spi-flash-id>`).
Alternatively, read off the silkscreen labelling of the flash chip and search for its datasheet.

The default ``flash_size`` parameter can also be overridden using the environment variable ``ESPTOOL_FS``.

ESP8266 and Flash Size
^^^^^^^^^^^^^^^^^^^^^^

The ESP8266 SDK stores WiFi configuration at the "end" of flash, and it finds the end using this size. However there is no downside to specifying a smaller flash size than you really have, as long as you don't need to write an image larger than this size.

ESP-12, ESP-12E and ESP-12F modules (and boards that use them such as NodeMCU, HUZZAH, etc.) usually have at least 4 megabyte / ``4MB`` (sometimes labelled 32 megabit) flash.

If using OTA, some additional sizes & layouts for OTA "firmware slots" are available. If not using OTA updates then you can ignore these extra sizes:

+-------------------+-----------------------+-----------------+-----------------+
| flash_size arg    | Number of OTA slots   | OTA Slot Size   | Non-OTA Space   |
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

-  [^] Support for 8MB & 16MB flash size is not present in all ESP8266 SDKs. If your SDK doesn't support these flash sizes, use ``--flash_size 4MB``.

ESP32 and Flash Size
^^^^^^^^^^^^^^^^^^^^

The ESP-IDF flashes a partition table to the flash at offset 0x8000. All of the partitions in this table must fit inside the configured flash size, otherwise the ESP32 will not work correctly.
