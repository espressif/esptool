.. _commands:

Basic Commands
==============

Write Binary Data to Flash: write_flash
----------------------------------------

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

        Overwriting the encrypted firmware (bootloader, application, etc.) without the ``--encrypt`` option is disabled, if `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ is enabled and Encrypted Download being disabled (efuse bit ``EFUSE_DISABLE_DL_ENCRYPT`` is set).

    .. only:: not esp32

        Overwriting the encrypted firmware (bootloader, application, etc.) without the ``--encrypt`` option is disabled, if:

        *  `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ and Secure Download Mode are enabled or
        *  `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ is enabled but Encrypted Download is disabled (efuse bit ``EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT`` is set).

    This is a safety measure to prevent accidentally overwriting the encrypted firmware with a plaintext binary, which **can ultimately lead to bricking the device**.

    This behavior can be overridden with the ``--force`` option. **Use this option provided that the flash encryption key is generated external to the device and you could perform the encryption on the host machine.**

    Flashing an Incompatible Image
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ``esptool.py`` checks every binary before flashing. If a valid firmware image is detected, the ``Chip ID`` and ``Minimum chip revision`` fields in its :ref:`header <image-format>` are compared against the actually connected chip.
    If the image turns out to be incompatible with the chip in use or requires a newer chip revision, flashing is stopped.

    This behavior can be overridden with the ``--force`` option.

Read Flash Contents: read_flash
--------------------------------

The read_flash command allows reading back the contents of flash. The arguments to the command are an address, a size, and a filename to dump the output to. For example, to read a full 2MB of attached flash:

::

    esptool.py -p PORT -b 460800 read_flash 0 0x200000 flash_contents.bin

.. note::

    If ``write_flash`` updated the boot image's :ref:`flash mode and flash size <flash-modes>` during flashing then these bytes may be different when read back.

.. _erase_flash:

Erase Flash: erase_flash & erase_region
---------------------------------------

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

Read Built-in MAC Address: read_mac
------------------------------------

::

    esptool.py read_mac

.. _read-spi-flash-id:

Read SPI Flash ID: flash_id
---------------------------

::

    esptool.py flash_id

Example output:

::

    Manufacturer: e0
    Device: 4016
    Detected flash size: 4MB

Refer to `flashrom source code <https://review.coreboot.org/plugins/gitiles/flashrom/+/refs/heads/master/flashchips.h>`__ for flash chip manufacturer name and part number.

.. _elf-2-image:

Convert ELF to Binary: elf2image
--------------------------------

The ``elf2image`` command converts an ELF file (from compiler/linker output) into the binary executable images which can be flashed and then booted into:

::

    esptool.py --chip {IDF_TARGET_NAME} elf2image my_app.elf

This command does not require a serial connection.

``elf2image`` also accepts the `Flash Modes <#flash-modes>`__ arguments ``--flash_freq`` and ``--flash_mode``, which can be used to set the default values in the image header. This is important when generating any image which will be booted directly by the chip.
These values can also be overwritten via the ``write_flash`` command, see the `write_flash command <#write-binary-data-to-flash-write-flash>`__ for details. However, if you want to overwrite these values via the ``write_flash`` command then use the ``--dont-append-digest`` argument of the ``elf2image`` command in order to skip appending a SHA256 digest after the image. The SHA256 digest would be invalidated by rewriting the image header, therefore, it is not allowed.

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

.. _image-info:

Output .bin Image Details: image_info
-------------------------------------

The ``image_info`` command outputs some information (load addresses, sizes, etc) about a ``.bin`` file created by ``elf2image``.

To view more information about the image, such as set flash size, frequency and mode, or extended header information, use the ``--version 2`` option. This extended output will become the default in a future major release.

This information corresponds to the headers described in :ref:`image-format`.

::

    esptool.py image_info --version 2 my_esp_app.bin

.. only:: not esp8266

    If a valid `ESP-IDF application header <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/app_image_format.html#application-description>`__ is detected in the image, specific fields describing the application are also displayed.

.. _merge-bin:

Merge Binaries for Flashing: merge_bin
--------------------------------------

The ``merge_bin`` command will merge multiple binary files (of any kind) into a single file that can be flashed to a device later. Any gaps between the input files are padded with 0xFF bytes (same as unwritten flash contents).

For example:

::

    esptool.py --chip {IDF_TARGET_NAME} merge_bin -o merged-flash.bin --flash_mode dio --flash_size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin

Will create a file ``merged-flash.bin`` with the contents of the other 3 files. This file can be later be written to flash with ``esptool.py write_flash 0x0 merged-flash.bin``.

.. note:

    Because gaps between the input files are padded with 0xFF bytes, when the merged binary is written then any flash sectors between the individual files will be erased. To avoid this, write the files individually.

**Options:**

*  The ``merge_bin`` command supports the same ``--flash_mode``, ``--flash_size`` and ``--flash_freq`` options as the ``write_flash`` command to override the bootloader flash header (see above for details).
   These options are applied to the output file contents in the same way as when writing to flash. Make sure to pass the ``--chip`` parameter if using these options, as the supported values and the bootloader offset both depend on the chip.
*  The ``--target-offset 0xNNN`` option will create a merged binary that should be flashed at the specified offset, instead of at offset 0x0.
*  The ``--fill-flash-size SIZE`` option will pad the merged binary with 0xFF bytes to the full flash specified size, for example ``--fill-flash-size 4MB`` will create a 4MB binary file.
*  It is possible to append options from a text file with ``@filename``. As an example, this can be conveniently used with the ESP-IDF build system, which produces a ``flash_args`` file in the build directory of a project:

.. code:: sh

    cd build    # The build directory of an ESP-IDF project
    esptool.py --chip {IDF_TARGET_NAME} merge_bin -o merged-flash.bin @flash_args

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
    :esp8266: *  :ref:`chip-id`
    :esp8266: *  :ref:`make-image`
    :esp8266: *  :ref:`run`
