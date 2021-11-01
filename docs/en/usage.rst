Usage
=====

Use ``esptool.py -h`` to see a summary of all available commands and
command line options.

To see all options for a particular command, append ``-h`` to the
command name. ie ``esptool.py write_flash -h``.

Common Options
--------------

Serial Port
~~~~~~~~~~~

*  The serial port is selected using the ``-p`` option, like
   ``-p /dev/ttyUSB0`` (Linux and macOS) or ``-p COM1`` (Windows).
*  A default serial port can be specified by setting the
   ``ESPTOOL_PORT`` environment variable.
*  If no ``-p`` option or ``ESPTOOL_PORT`` value is specified,
   ``esptool.py`` will enumerate all connected serial ports and try each
   one until it finds an Espressif device connected (new behaviour in
   v2.4.0).

Note: Windows and macOS may require drivers to be installed for a
particular USB/serial adapter, before a serial port is available.
Consult the documentation for your particular device. On macOS, you can
also consult `System
Information <https://support.apple.com/en-us/HT203001>`__'s list of USB
devices to identify the manufacturer or device ID when the adapter is
plugged in. On Windows, you can use `Windows Update or Device
Manager <https://support.microsoft.com/en-us/help/15048/windows-7-update-driver-hardware-not-working-properly>`__
to find a driver.

If using Cygwin or WSL on Windows, you have to convert the Windows-style
name into a Unix-style path (``COM1`` -> ``/dev/ttyS0``, and so on).
(This is not necessary if using ESP-IDF for ESP32 with the supplied
Windows MSYS2 environment, this environment uses a native Windows Python
which accepts COM ports as-is.)

In Linux, the current user may not have access to serial ports and a
"Permission Denied" error will appear. On most Linux distributions, the
solution is to add the user to the ``dialout`` group with a command like
``sudo usermod -a -G dialout <USERNAME>``. Check your Linux
distribution's documentation for more information.

Baud rate
~~~~~~~~~

The default esptool.py baud rate is 115200bps. Different rates may be
set using ``-b 921600`` (or another baud rate of your choice). A default
baud rate can also be specified using the ``ESPTOOL_BAUD`` environment
variable. This can speed up ``write_flash`` and ``read_flash``
operations.

The baud rate is limited to 115200 when esptool.py establishes the
initial connection, higher speeds are only used for data transfers.

Most hardware configurations will work with ``-b 230400``, some with
``-b 460800``, ``-b 921600`` and/or ``-b 1500000`` or higher.

If you have connectivity problems then you can also set baud rates below
115200. You can also choose 74880, which is the usual baud rate used by
the ESP8266 to output `boot
log <https://github.com/espressif/esptool/wiki/ESP8266-Boot-ROM-Log>`__
information.

Commands
--------

Write binary data to flash: write\_flash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Binary data can be written to the ESP's flash chip via the serial
``write_flash`` command:

::

    esptool.py --port COM4 write_flash 0x1000 my_app-0x01000.bin

Multiple flash addresses and file names can be given on the same command
line:

::

    esptool.py --port COM4 write_flash 0x00000 my_app.elf-0x00000.bin 0x40000 my_app.elf-0x40000.bin

The ``--chip`` argument is optional when writing to flash, esptool will
detect the type of chip when it connects to the serial port.

The ``--port`` argument is documented under `Serial
Port <#serial-port>`__.

The next arguments to write\_flash are one or more pairs of offset
(address) and file name. When generating ESP8266 "version 1" images, the
file names created by ``elf2image`` include the flash offsets as part of
the file name. For other types of images, consult your SDK documentation
to determine the files to flash at which offsets.

Numeric values passed to write\_flash (and other commands) can be
specified either in hex (ie 0x1000), or in decimal (ie 4096).

See the `Troubleshooting <#troubleshooting>`__ section if the
write\_flash command is failing, or the flashed module fails to boot.

Setting flash mode and size
^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may also need to specify arguments for `flash mode and flash
size <#flash-modes>`__, if you wish to override the defaults. For
example:

::

    esptool.py --port /dev/ttyUSB0 write_flash --flash_mode qio --flash_size 32m 0x0 bootloader.bin 0x1000 my_app.bin

Since esptool v2.0, these options are not often needed as the default is
to keep the flash mode and size from the ``.bin`` image file. See the
`Flash Modes <#flash-modes>`__ section for more details.

Compression
^^^^^^^^^^^

By default, the serial transfer data is compressed for better
performance. The ``-u/--no-compress`` option disables this behaviour.

Erasing flash before write
^^^^^^^^^^^^^^^^^^^^^^^^^^

To successfully write data into flash, all 4096-byte memory sectors (the
smallest erasable unit) affected by the operation have to be erased
first. As a result, when the flashing offset address or the data are not
4096-byte aligned, more memory is erased than actually needed. Esptool
will display information about which flash memory sectors will be
erased.

Use the ``-e/--erase-all`` option to erase all flash sectors (not just
write areas) before programming.

Read Flash Contents: read\_flash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The read\_flash command allows reading back the contents of flash. The
arguments to the command are an address, a size, and a filename to dump
the output to. For example, to read a full 2MB of attached flash:

::

    esptool.py -p PORT -b 460800 read_flash 0 0x200000 flash_contents.bin

(Note that if ``write_flash`` updated the boot image's `flash mode and
flash size <#flash-modes>`__ during flashing then these bytes may be
different when read back.)

Erase Flash: erase\_flash & erase region
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To erase the entire flash chip (all data replaced with 0xFF bytes):

::

    esptool.py erase_flash

To erase a region of the flash, starting at address 0x20000 with length
0x4000 bytes (16KB):

::

    esptool.py erase_region 0x20000 0x4000

The address and length must both be multiples of the SPI flash erase
sector size. This is 0x1000 (4096) bytes for supported flash chips.

Read built-in MAC address: read\_mac
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    esptool.py read_mac

Read SPI flash id: flash\_id
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    esptool.py flash_id

Example output:

::

    Manufacturer: e0
    Device: 4016
    Detected flash size: 4MB

Refer to `flashrom source
code <https://review.coreboot.org/plugins/gitiles/flashrom/+/refs/heads/master/flashchips.h>`__
for flash chip manufacturer name and part number.

Convert ELF to Binary: elf2image
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``elf2image`` command converts an ELF file (from compiler/linker
output) into the binary executable images which can be flashed and then
booted into:

::

    esptool.py --chip esp8266 elf2image my_app.elf

This command does not require a serial connection.

``elf2image`` also accepts the `Flash Modes <#flash-modes>`__ arguments
``--flash_freq`` and ``--flash_mode``, which can be used to set the
default values in the image header. This is important when generating
any image which will be booted directly by the chip. These values can
also be overwritten via the ``write_flash`` command, see the
`write\_flash command <#write-binary-data-to-flash-write_flash>`__ for
details.

By default, ``elf2image`` uses the sections in the ELF file to generate
each segment in the binary executable. To use segments (PHDRs) instead,
pass the ``--use_segments`` option.

elf2image for ESP8266
^^^^^^^^^^^^^^^^^^^^^

The default command output is two binary files:
``my_app.elf-0x00000.bin`` and ``my_app.elf-0x40000.bin``. You can alter
the firmware file name prefix using the ``--output/-o`` option.

``elf2image`` can also produce a "version 2" image file suitable for use
with a software bootloader stub such as
`rboot <https://github.com/raburton/rboot>`__ or the Espressif
bootloader program. You can't flash a "version 2" image without also
flashing a suitable bootloader.

::

    esptool.py --chip esp8266 elf2image --version=2 -o my_app-ota.bin my_app.elf

elf2image for ESP32
^^^^^^^^^^^^^^^^^^^

For ESP32, elf2image produces a single output binary "image file". By
default this has the same name as the .elf file, with a .bin extension.
ie:

::

    esptool.py --chip esp32 elf2image my_esp32_app.elf

In the above example, the output image file would be called
``my_esp32_app.bin``.

Output .bin image details: image\_info
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``image_info`` command outputs some information (load addresses,
sizes, etc) about a ``.bin`` file created by ``elf2image``.

::

    esptool.py --chip esp32 image_info my_esp32_app.bin

Note that ``--chip esp32`` is required when reading ESP32 images.
Otherwise the default is ``--chip esp8266`` and the image will be
interpreted as an invalid ESP8266 image.

Advanced Commands
~~~~~~~~~~~~~~~~~

The following commands are less commonly used, or only of interest to
advanced users. They are documented on the wiki:

*  `verify\_flash <https://github.com/espressif/esptool/wiki/Advanced-Commands#verify_flash>`__
*  `dump\_mem <https://github.com/espressif/esptool/wiki/Advanced-Commands#dump_mem>`__
*  `load\_ram <https://github.com/espressif/esptool/wiki/Advanced-Commands#load_ram>`__
*  `read\_mem &
   write\_mem <https://github.com/espressif/esptool/wiki/Advanced-Commands#read_mem--write_mem>`__
*  `read\_flash\_status <https://github.com/espressif/esptool/wiki/Advanced-Commands#read_flash_status>`__
*  `write\_flash\_status <https://github.com/espressif/esptool/wiki/Advanced-Commands#write_flash_status>`__
*  `chip\_id <https://github.com/espressif/esptool/wiki/Advanced-Commands#chip_id>`__
*  `make\_image <https://github.com/espressif/esptool/wiki/Advanced-Commands#make_image>`__
*  `run <https://github.com/espressif/esptool/wiki/Advanced-Commands#run>`__

Additional ESP32 Tools
----------------------

The following tools for ESP32, bundled with esptool.py, are documented
on the wiki:

*  `espefuse.py - for reading/writing ESP32 efuse
   region <https://github.com/espressif/esptool/wiki/espefuse>`__
*  `espsecure.py - for working with ESP32 security
   features <https://github.com/espressif/esptool/wiki/espsecure>`__

Serial Connections
------------------

The ESP8266 & ESP32 ROM serial bootloader uses a 3.3V UART serial
connection. Many development boards make the serial connections for you
onboard.

However, if you are wiring the chip yourself to a USB/Serial adapter or
similar then the following connections must be made:

+---------------------+-------------------+
| ESP32/ESP8266 Pin   | Serial Port Pin   |
+=====================+===================+
| TX (aka GPIO1)      | RX (receive)      |
+---------------------+-------------------+
| RX (aka GPIO3)      | TX (transmit)     |
+---------------------+-------------------+
| Ground              | Ground            |
+---------------------+-------------------+

Note that TX (transmit) on the ESP8266 is connected to RX (receive) on
the serial port connection, and vice versa.

Do not connect the chip to 5V TTL serial adapters, and especially not to
"standard" RS-232 adapters! 3.3V serial only!

Entering the Bootloader
-----------------------

Both ESP8266 and ESP32 have to be reset in a certain way in order to
launch the serial bootloader.

On some development boards (including NodeMCU, WeMOS, HUZZAH Feather,
Core Board, ESP32-WROVER-KIT), esptool.py can automatically trigger a
reset into the serial bootloader - in which case you don't need to read
this section.

For everyone else, three things must happen to enter the serial
bootloader - a reset, required pins set correctly, and GPIO0 pulled low:

Boot Mode
~~~~~~~~~

Both ESP8266 and ESP32 choose the boot mode each time they reset. A
reset event can happen in one of several ways:

*  Power applied to chip.
*  The nRESET pin was low and is pulled high (on ESP8266 only).
*  The CH\_PD/EN pin ("enable") pin was low and is pulled high.

On ESP8266, both the nRESET and CH\_PD pins must be pulled high for the
chip to start operating.

For more details on selecting the boot mode, see the following Wiki
pages:

*  `ESP8266 Boot Mode
   Selection <https://github.com/espressif/esptool/wiki/ESP8266-Boot-Mode-Selection>`__
*  `ESP32 Boot Mode
   Selection <https://github.com/espressif/esptool/wiki/ESP32-Boot-Mode-Selection>`__

Flash Modes
-----------

``write_flash`` and some other commands accept command line arguments to
set bootloader flash mode, flash size and flash clock frequency. The
chip needs correct mode, frequency and size settings in order to run
correctly - although there is some flexibility. A header at the
beginning of a bootable image contains these values.

To override these values, the options ``--flash_mode``, ``--flash_size``
and/or ``--flash_freq`` must appear after ``write_flash`` on the command
line, for example:

::

    esptool.py --port /dev/ttyUSB1 write_flash --flash_mode dio --flash_size 4MB 0x0 bootloader.bin

These options are only consulted when flashing a bootable image to an
ESP8266 at offset 0x0, or an ESP32 at offset 0x1000. These are addresses
used by the ROM bootloader to load from flash. When flashing at all
other offsets, these arguments are not used.

Flash Mode (--flash\_mode, -fm)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These set Quad Flash I/O or Dual Flash I/O modes. Valid values are
``keep``, ``qio``, ``qout``, ``dio``, ``dout``. The default is ``keep``,
which keeps whatever value is already in the image file. This parameter
can also be specified using the environment variable ``ESPTOOL_FM``.

Most boards use ``qio`` mode. Some ESP8266 modules, including the
ESP-12E modules on some (not all) NodeMCU boards, are dual I/O and the
firmware will only boot when flashed with ``--flash_mode dio``. Most
ESP32 modules are also dual I/O.

In ``qio`` mode, two additional GPIOs (9 and 10) are used for SPI flash
communications. If flash mode is set to ``dio`` then these pins are
available for other purposes.

For a full explanation of these modes, see the `SPI Flash Modes wiki
page <https://github.com/espressif/esptool/wiki/SPI-Flash-Modes>`__.

Flash Frequency (--flash\_freq, -ff)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clock frequency for SPI flash interactions. Valid values are ``keep``,
``40m``, ``26m``, ``20m``, ``80m`` (MHz). The default is ``keep``, which
keeps whatever value is already in the image file. This parameter can
also be specified using the environment variable ``ESPTOOL_FF``.

The flash chip connected to most chips works with 40MHz clock speeds,
but you can try lower values if the device won't boot. The highest 80MHz
flash clock speed will give the best performance, but may cause crashing
if the flash or board design is not capable of this speed.

Flash Size (--flash\_size, -fs)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Size of the SPI flash, given in megabytes. Valid values vary by chip
type:

+-----------+--------------------------------------------------------------------------------------------------------------------+
| Chip      | flash\_size values                                                                                                 |
+===========+====================================================================================================================+
| ESP32     | ``keep``, ``detect``, ``1MB``, ``2MB``, ``4MB``, ``8MB``, ``16MB``                                                 |
+-----------+--------------------------------------------------------------------------------------------------------------------+
| ESP8266   | ``keep``, ``detect``, ``256KB``, ``512KB``, ``1MB``, ``2MB``, ``4MB``, ``2MB-c1``, ``4MB-c1``, ``8MB``, ``16MB``   |
+-----------+--------------------------------------------------------------------------------------------------------------------+

For ESP8266, some `additional sizes & layouts for OTA "firmware slots"
are available <#esp8266-and-flash-size>`__.

The default ``--flash_size`` parameter is ``keep``. This means that if
no ``--flash_size`` argument is passed when flashing a bootloader, the
value in the bootloader .bin file header is kept instead of detecting
the actual flash size and updating the header.

To enable automatic flash size detection based on SPI flash ID, add the
argument ``esptool.py [...] write_flash [...] -fs detect``. If detection
fails, a warning is printed and a default value of of ``4MB`` (4
megabytes) is used.

If flash size is not successfully detected, you can find the flash size
by using the ``flash_id`` command and then looking up the ID from the
output (see `Read SPI flash id <#read-spi-flash-id-flash_id>`__).
Alternatively, read off the silkscreen labelling of the flash chip and
search for its datasheet.

The default ``flash_size`` parameter can also be overridden using the
environment variable ``ESPTOOL_FS``.

ESP8266 and Flash Size
^^^^^^^^^^^^^^^^^^^^^^

The ESP8266 SDK stores WiFi configuration at the "end" of flash, and it
finds the end using this size. However there is no downside to
specifying a smaller flash size than you really have, as long as you
don't need to write an image larger than this size.

ESP-12, ESP-12E and ESP-12F modules (and boards that use them such as
NodeMCU, HUZZAH, etc.) usually have at least 4 megabyte / ``4MB``
(sometimes labelled 32 megabit) flash.

If using OTA, some additional sizes & layouts for OTA "firmware slots"
are available. If not using OTA updates then you can ignore these extra
sizes:

+-------------------+-----------------------+-----------------+-----------------+
| flash\_size arg   | Number of OTA slots   | OTA Slot Size   | Non-OTA Space   |
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

-  [^] Support for 8MB & 16MB flash size is not present in all ESP8266
   SDKs. If your SDK doesn't support these flash sizes, use
   ``--flash_size 4MB``.

ESP32 and Flash Size
^^^^^^^^^^^^^^^^^^^^

The ESP-IDF flashes a partition table to the flash at offset 0x8000. All
of the partitions in this table must fit inside the configured flash
size, otherwise the ESP32 will not work correctly.

Merging binaries
----------------

The ``merge_bin`` command will merge multiple binary files (of any kind)
into a single file that can be flashed to a device later. Any gaps
between the input files are padded with 0xFF bytes (same as unwritten
flash contents).

For example:

::

    esptool.py --chip esp32 merge_bin -o merged-flash.bin --flash_mode dio --flash_size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin

Will create a file ``merged-flash.bin`` with the contents of the other 3
files. This file can be later be written to flash with
``esptool.py write_flash 0x0 merged-flash.bin``.

Note: Because gaps between the input files are padded with 0xFF bytes,
when the merged binary is written then any flash sectors between the
individual files will be erased. To avoid this, write the files
individually.

Options
~~~~~~~

-  The ``merge_bin`` command supports the same ``--flash_mode``,
   ``--flash_size`` and ``--flash_freq`` options as the ``write_flash``
   command to override the bootloader flash header (see above for
   details). These options are applied to the output file contents in
   the same way as when writing to flash. Make sure to pass the
   ``--chip`` parameter if using these options, as the supported values
   and the bootloader offset both depend on the chip.
-  The ``--target-offset 0xNNN`` option will create a merged binary that
   should be flashed at the specified offset, instead of at offset 0x0.
-  The ``--fill-flash-size SIZE`` option will pad the merged binary with
   0xFF bytes to the full flash specified size, for example
   ``--fill-flash-size 4MB`` will create a 4MB binary file.
-  It is possible to append options from a text file with ``@filename``.
   As an example, this can be conveniently used with the ESP-IDF build
   system, which produces a ``flash_args`` file in the build directory
   of a project:

.. code:: sh

    cd build    # The build directory of an ESP-IDF project
    esptool.py --chip esp32 merge_bin -o merged-flash.bin @flash_args

Advanced Options
----------------

See the `Advanced Options wiki
page <https://github.com/espressif/esptool/wiki/Advanced-Options>`__ for
some of the more unusual esptool.py command line options.

Remote Serial Ports
-------------------

It is possible to connect to any networked remote serial port that
supports `RFC2217 <http://www.ietf.org/rfc/rfc2217.txt>`__ (Telnet)
protocol, or a plain TCP socket. See the `Remote Serial Ports wiki
page <https://github.com/espressif/esptool/wiki/Remote-Serial-Ports>`__
for details.
