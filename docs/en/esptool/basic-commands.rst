.. _commands:

Basic Commands
==============

.. _write-flash:

Write Binary Data to Flash: ``write_flash``
-------------------------------------------

Binary data can be written to the ESP's flash chip via the serial ``write_flash`` command:

::

    esptool.py --port COM4 write_flash 0x1000 my_app-0x01000.bin

Multiple flash addresses and file names can be given on the same command line:

::

    esptool.py --port COM4 write_flash 0x00000 my_app.elf-0x00000.bin 0x40000 my_app.elf-0x40000.bin

The ``--chip`` argument is optional when writing to flash, esptool will detect the type of chip when it connects to the serial port.

The ``--port`` argument is documented under :ref:`serial-port`.

.. only:: esp8266

    The next arguments to ``write_flash`` are one or more pairs of offset (address) and file name. When generating ESP8266 "version 1" images, the file names created by ``elf2image`` include the flash offsets as part of the file name.
    For other types of images, consult your SDK documentation to determine the files to flash at which offsets.

.. only:: not esp8266

    The next arguments to ``write_flash`` are one or more pairs of offset (address) and file name. Consult your SDK documentation to determine the files to flash at which offsets.

Numeric values passed to write_flash (and other commands) can be specified either in hex (ie 0x1000), or in decimal (ie 4096).

See the :ref:`troubleshooting` section if the ``write_flash`` command is failing, or the flashed module fails to boot.

Setting Flash Mode and Size
^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may also need to specify arguments for :ref:`flash mode and flash size <flash-modes>`, if you wish to override the defaults. For example:

::

    esptool.py --port /dev/ttyUSB0 write_flash --flash_mode qio --flash_size 32m 0x0 bootloader.bin 0x1000 my_app.bin

Since esptool v2.0, these options are not often needed as the default is to keep the flash mode and size from the ``.bin`` image file. See the :ref:`flash-modes` section for more details.

Compression
^^^^^^^^^^^

By default, the serial transfer data is compressed for better performance. The ``-u/--no-compress`` option disables this behaviour.

Erasing Flash Before Write
^^^^^^^^^^^^^^^^^^^^^^^^^^

To successfully write data into flash, all 4096-byte memory sectors (the smallest erasable unit) affected by the operation have to be erased first. As a result, when the flashing offset address or the data are not 4096-byte aligned, more memory is erased than actually needed.
Esptool will display information about which flash memory sectors will be erased.

Use the ``-e/--erase-all`` option to erase all flash sectors (not just the write areas) before programming.

.. only:: not esp8266

    Bootloader Protection
    ^^^^^^^^^^^^^^^^^^^^^

    Flashing into the bootloader region (``0x0`` -> ``0x8000``) is disabled by default if active `Secure Boot <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/secure-boot-v2.html>`_ is detected.
    This is a safety measure to prevent accidentally overwriting the secure bootloader, which **can ultimately lead to bricking the device**.

    This behavior can be overridden with the ``--force`` option. **Use this only at your own risk and only if you know what you are doing!**


    Encrypted Flash Protection
    ^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. only:: esp32

        Overwriting the encrypted firmware (bootloader, application, etc.) without the ``--encrypt`` option is disabled, if `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ is enabled and Encrypted Download being disabled (eFuse bit ``EFUSE_DISABLE_DL_ENCRYPT`` is set).

    .. only:: not esp32

        Overwriting the encrypted firmware (bootloader, application, etc.) without the ``--encrypt`` option is disabled, if:

        *  `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ and Secure Download Mode are enabled or
        *  `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ is enabled but Encrypted Download is disabled (eFuse bit ``EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT`` is set).

    This is a safety measure to prevent accidentally overwriting the encrypted firmware with a plaintext binary, which **can ultimately lead to bricking the device**.

    This behavior can be overridden with the ``--force`` option. **Use this option provided that the flash encryption key is generated external to the device and you could perform the encryption on the host machine.**

    Flashing an Incompatible Image
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ``esptool.py`` checks every binary before flashing. If a valid firmware image is detected, the ``Chip ID`` and ``Minimum chip revision`` fields in its :ref:`header <image-format>` are compared against the actually connected chip.
    If the image turns out to be incompatible with the chip in use or requires a newer chip revision, flashing is stopped.

    This behavior can be overridden with the ``--force`` option.

Read Flash Contents: ``read_flash``
-----------------------------------

The read_flash command allows reading back the contents of flash. The arguments to the command are an address, a size, and a file path to output to. For example, to read a full 2MB of attached flash:

::

    esptool.py -p PORT -b 460800 read_flash 0 0x200000 flash_contents.bin


It is also possible to autodetect flash size by using ``ALL`` as size. The above example with autodetection would look like this:

::

    esptool.py -p PORT -b 460800 read_flash 0 ALL flash_contents.bin


.. note::

    When using the ``read_flash`` command in combination with the ``--no-stub`` argument, it may be necessary to also set the ``--flash_size`` argument to ensure proper reading of the flash contents by the ROM.


.. note::

    If ``write_flash`` updated the boot image's :ref:`flash mode and flash size <flash-modes>` during flashing then these bytes may be different when read back.

.. _erase_flash:

Erase Flash: ``erase_flash`` & ``erase_region``
-----------------------------------------------

To erase the entire flash chip (all data replaced with 0xFF bytes):

::

    esptool.py erase_flash

To erase a region of the flash, starting at address 0x20000 with length 0x4000 bytes (16KB):

::

    esptool.py erase_region 0x20000 0x4000

The address and length must both be multiples of the SPI flash erase sector size. This is 0x1000 (4096) bytes for supported flash chips.

.. only:: not esp8266

    Flash Protection
    ^^^^^^^^^^^^^^^^

    Erasing the flash chip is disabled by default if either active `Secure Boot <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/secure-boot-v2.html>`_ or
    `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ is detected.
    This is a safety measure to prevent accidentally deleting the secure bootloader or encrypted data, which **can ultimately lead to bricking the device**.

    This behavior can be overridden with the ``--force`` option. **Use this only at your own risk and only if you know what you are doing!**

Read Built-in MAC Address: ``read_mac``
---------------------------------------

::

    esptool.py read_mac

.. _read-spi-flash-id:

Read SPI Flash ID: ``flash_id``
-------------------------------

::

    esptool.py flash_id

Example output:

::

    Manufacturer: e0
    Device: 4016
    Detected flash size: 4MB

Refer to `flashrom source code <https://github.com/flashrom/flashrom/blob/master/include/flashchips.h>`__ for flash chip manufacturer name and part number.

.. _elf-2-image:

Convert ELF to Binary: ``elf2image``
------------------------------------

The ``elf2image`` command converts an ELF file (from compiler/linker output) into the binary executable images which can be flashed and then booted into:

::

    esptool.py --chip {IDF_TARGET_NAME} elf2image my_app.elf

This command does not require a serial connection.

``elf2image`` also accepts the `Flash Modes <#flash-modes>`__ arguments ``--flash_freq`` and ``--flash_mode``, which can be used to set the default values in the image header. This is important when generating any image which will be booted directly by the chip.
These values can also be overwritten via the ``write_flash`` command, see the `write_flash command <#write-binary-data-to-flash-write-flash>`__ for details. Overwriting these values via the ``write_flash`` command will produce an image with a recalculated SHA256 digest, otherwise, the image SHA256 digest would be invalidated by rewriting the image header. There is an option to skip appending a SHA256 digest after the image with ``--dont-append-digest`` argument of the ``elf2image`` command.

By default, ``elf2image`` uses the sections in the ELF file to generate each segment in the binary executable. To use segments (PHDRs) instead, pass the ``--use_segments`` option.

.. only:: esp8266

    The default command output for {IDF_TARGET_NAME} is two binary files: ``my_app.elf-0x00000.bin`` and ``my_app.elf-0x40000.bin``. You can alter the firmware file name prefix using the ``--output/-o`` option.

    ``elf2image`` can also produce a "version 2" image file suitable for use with a software bootloader stub such as `rboot <https://github.com/raburton/rboot>`__ or the Espressif bootloader program. You can't flash a "version 2" image without also flashing a suitable bootloader.

    ::

        esptool.py --chip {IDF_TARGET_NAME} elf2image --version=2 -o my_app-ota.bin my_app.elf

.. only:: not esp8266

    For {IDF_TARGET_NAME}, elf2image produces a single output binary "image file". By default this has the same name as the .elf file, with a .bin extension. For example:

    ::

        esptool.py --chip {IDF_TARGET_NAME} elf2image my_esp_app.elf

    In the above example, the output image file would be called ``my_esp_app.bin``.

    The ``--ram-only-header`` configuration is mainly applicable for use within the Espressif's SIMPLE_BOOT option from 3rd party OSes such as ZephyrOS and NuttX OS.
    This option makes only the RAM segments visible to the ROM bootloader placing them at the beginning of the file and altering the segment count from the image header with the quantity of these segments, and also writing only their checksum. This segment placement may result in a more fragmented binary because of flash alignment constraints.
    It is strongly recommended to use this configuration with care, because the image built must then handle the basic hardware initialization and the flash mapping for code execution after ROM bootloader boot it.

.. _image-info:

Output .bin Image Details: ``image_info``
-----------------------------------------

The ``image_info`` command outputs some information (load addresses, segment sizes, set flash size, frequency, and mode, extended header information, etc) about a ``.bin`` file created by ``elf2image``. Command also supports ``.hex`` file created by ``merge_bin`` command from supported ``.bin`` files.

This information corresponds to the headers described in :ref:`image-format`.

::

    esptool.py image_info my_esp_app.bin

.. only:: not esp8266

    If the given binary file is an application with a valid `ESP-IDF application header <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/app_image_format.html#application-description>`__
    or a bootloader with a valid `ESP-IDF bootloader header <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/bootloader_image_format.html#bootloader-description>`__
    detected in the image, specific fields describing the application or bootloader are also displayed.

.. _merge-bin:

Merge Binaries for Flashing: ``merge_bin``
------------------------------------------
The ``merge_bin`` command will merge multiple binary files (of any kind) into a single file that can be flashed to a device later. Any gaps between the input files are padded based on the selected output format.

For example:

::

    esptool.py --chip {IDF_TARGET_NAME} merge_bin -o merged-flash.bin --flash_mode dio --flash_size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin

Will create a file ``merged-flash.bin`` with the contents of the other 3 files. This file can be later written to flash with ``esptool.py write_flash 0x0 merged-flash.bin``.


**Common options:**

*  The ``merge_bin`` command supports the same ``--flash_mode``, ``--flash_size`` and ``--flash_freq`` options as the ``write_flash`` command to override the bootloader flash header (see above for details).
   These options are applied to the output file contents in the same way as when writing to flash. Make sure to pass the ``--chip`` parameter if using these options, as the supported values and the bootloader offset both depend on the chip.
*  The ``--format`` option will change the format of the output file. For more information about formats see formats description below.
*  The input files can be in either ``bin`` or ``hex`` format and they will be automatically converted to type selected by ``--format`` argument.
*  It is possible to append options from a text file with ``@filename`` (see the advanced options page :ref:`Specifying Arguments via File <specify_arguments_via_file>` section for details). As an example, this can be conveniently used with the ESP-IDF build system, which produces a ``flash_args`` file in the build directory of a project:

.. code:: sh

    cd build    # The build directory of an ESP-IDF project
    esptool.py --chip {IDF_TARGET_NAME} merge_bin -o merged-flash.bin @flash_args


HEX Output Format
^^^^^^^^^^^^^^^^^

The output of the command will be in `Intel Hex format <https://www.intel.com/content/www/us/en/support/programmable/articles/000076770.html>`__. The gaps between the files won't be padded.

Intel Hex format offers distinct advantages when compared to the binary format, primarily in the following areas:

* **Transport**: Intel Hex files are represented in ASCII text format, significantly increasing the likelihood of flawless transfers across various mediums.
* **Size**: Data is carefully allocated to specific memory addresses eliminating the need for unnecessary padding. Binary images often lack detailed addressing information, leading to the inclusion of data for all memory locations from the file's initial address to its end.
* **Validity Checks**: Each line in an Intel Hex file has a checksum to help find errors and make sure data stays unchanged.

.. code:: sh

    esptool.py --chip {IDF_TARGET_NAME} merge_bin --format hex -o merged-flash.hex --flash_mode dio --flash_size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin

.. note::

    Please note that during the conversion to the `Intel Hex` format, the binary input file is treated as a black box. The conversion process does not consider the actual contents of the binary file. This means that the `Intel Hex` file will contain the same data as the binary file (including the padding), but the data will be represented in a different format.
    When merging multiple files, the `Intel Hex` format, unlike the binary format, does not include any padding between the input files.
    It is recommended to merge multiple files instead of converting one already merged to get smaller merged outputs.

RAW Output Format
^^^^^^^^^^^^^^^^^

The output of the command will be in ``raw`` format and gaps between individual files will be filled with `0xFF` bytes (same as unwritten flash contents).

.. note::

    Because gaps between the input files are padded with `0xFF` bytes, when the merged binary is written then any flash sectors between the individual files will be erased. To avoid this, write the files individually.


**RAW options:**

*  The ``--pad-to-size SIZE`` option will pad the merged binary with `0xFF` bytes to the full flash specified size, for example ``--pad-to-size 4MB`` will create a 4MB binary file.
*  The ``--target-offset 0xNNN`` option will create a merged binary that should be flashed at the specified offset, instead of at offset 0x0.


UF2 Output Format
^^^^^^^^^^^^^^^^^

This command will generate a UF2 (`USB Flashing Format <https://github.com/microsoft/uf2>`_) binary.
This UF2 file can be copied to a USB mass storage device exposed by another ESP running the `ESP USB Bridge <https://github.com/espressif/esp-usb-bridge>`_ project. The bridge MCU will use it to flash the target MCU. This is as simple copying (or "drag-and-dropping") the file to the exposed disk accessed by a file explorer in your machine.

Gaps between the files will be filled with `0x00` bytes.

**UF2 options:**

*  The ``--chunk-size`` option will set what portion of 512 byte block will be used for data. A common value is 256 bytes. By default, the largest possible value will be used.
*  The ``--md5-disable`` option will disable MD5 checksums at the end of each block. This can be useful for integration with e.g. `tinyuf2 <https://github.com/adafruit/tinyuf2>`__.

.. code:: sh

    esptool.py --chip {IDF_TARGET_NAME} merge_bin --format uf2 -o merged-flash.uf2 --flash_mode dio --flash_size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin


Advanced Commands
-----------------

The following commands are less commonly used, or only of interest to advanced users. They are documented in the :ref:`advanced-commands` section:

.. list::

    *  :ref:`verify-flash`
    *  :ref:`dump-mem`
    *  :ref:`load-ram`
    *  :ref:`read-mem-write-mem`
    *  :ref:`read-flash-status`
    *  :ref:`write-flash-status`
    *  :ref:`read-flash-sfdp`
    :esp8266: *  :ref:`chip-id`
    :esp8266: *  :ref:`run`
