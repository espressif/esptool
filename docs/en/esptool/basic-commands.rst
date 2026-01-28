.. _commands:

Basic Commands
==============

.. _write-flash:

Write Binary Data to Flash: ``write-flash``
-------------------------------------------

Binary data can be written to the ESP's flash chip via the serial ``write-flash`` command:

::

    esptool --port COM4 write-flash 0x1000 my_app-0x01000.bin

Multiple flash addresses and file names can be given on the same command line:

::

    esptool --port COM4 write-flash 0x00000 my_app.elf-0x00000.bin 0x40000 my_app.elf-0x40000.bin

The ``--chip`` argument is optional when writing to flash, esptool will detect the type of chip when it connects to the serial port.

The ``--port`` argument is documented under :ref:`serial-port`.

.. only:: esp8266

    The next arguments to ``write-flash`` are one or more pairs of offset (address) and file name. When generating ESP8266 "version 1" images, the file names created by ``elf2image`` include the flash offsets as part of the file name.
    For other types of images, consult your SDK documentation to determine the files to flash at which offsets.

.. only:: not esp8266

    The next arguments to ``write-flash`` are one or more pairs of offset (address) and file name. Consult your SDK documentation to determine the files to flash at which offsets.

Numeric values passed to write-flash (and other commands) can be specified either in hex (ie 0x1000), or in decimal (ie 4096).

See the :ref:`troubleshooting` section if the ``write-flash`` command is failing, or the flashed module fails to boot.

Setting Flash Mode and Size
^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may also need to specify arguments for :ref:`flash mode and flash size <flash-modes>`, if you wish to override the defaults. For example:

::

    esptool --port /dev/ttyUSB0 write-flash --flash-mode qio --flash-size 32m 0x0 bootloader.bin 0x1000 my_app.bin

Since esptool v2.0, these options are not often needed as the default is to keep the flash mode and size from the ``.bin`` image file. See the :ref:`flash-modes` section for more details.

Compression
^^^^^^^^^^^

By default, the serial transfer data is compressed for better performance. The ``-u/--no-compress`` option disables this behaviour.

Erasing Flash Before Write
^^^^^^^^^^^^^^^^^^^^^^^^^^

To successfully write data into flash, all 4096-byte memory sectors (the smallest erasable unit) affected by the operation have to be erased first. As a result, when the flashing offset address or the data are not 4096-byte aligned, more memory is erased than actually needed.
Esptool will display information about which flash memory sectors will be erased.

Use the ``-e/--erase-all`` option to erase all flash sectors (not just the write areas) before programming.

Skipping Unchanged Content
^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, esptool is set to erase the flash and try to flash the whole content of the provided binaries into flash. However, you can enable a check to skip flashing to save time if the new binary is already present in flash by using the ``--skip-flashed`` (or ``-s``) option. When enabled, esptool computes an MD5 checksum of the flash content and compares it with the new binary. If they match exactly, flashing is skipped entirely and a message is displayed indicating that the content is already in flash.

The ``--skip-flashed`` option is automatically enabled for each file that has a corresponding ``--diff-with`` pair (see `Fast Reflashing <#fast-reflashing>`__ below), as the MD5 check is already performed as part of the fast reflashing process.

.. note::

    The ``--skip-flashed`` and ``--no-diff-verify`` (see `No Diff Verification Mode <#no-diff-verification-mode>`__ below) options are mutually exclusive. You cannot use both at the same time.

For larger binaries, checksumming the flash content can take significant time. If you are certain the content needs to be rewritten (e.g., after a flash erase or when you know the content has changed), omit ``--skip-flashed`` to proceed directly to flashing without performing MD5 checks in order to save time.

Fast Reflashing
^^^^^^^^^^^^^^^

When repeatedly flashing similar firmware (e.g., during development), esptool can significantly speed up the flashing process by only rewriting changed flash sectors instead of the entire binary. This is called **fast reflashing** or **differential flashing**.

To enable fast reflashing, use the ``--diff-with`` option to provide the previously flashed binary file(s) for comparison, which will tell esptool that ``old_app.bin`` was previously written to address ``0x10000``, and now it should be compared with the new, updated binary `new_app.bin` and flash only those sectors of `new_app.bin` which are different from `old_app.bin`.:

::

    esptool write-flash 0x10000 new_app.bin --diff-with old_app.bin

When multiple files are being flashed, provide a corresponding ``--diff-with`` file for each one (or use ``skip`` to disable fast reflashing for a specific file). The diff files are matched sequentially to the files being flashed - the first ``--diff-with`` file corresponds to the first file being flashed, the second to the second, and so on.

.. note::

    You can simplify this process by using a single Intel HEX file (which can be created with the :ref:`merge-bin <merge-bin>` command) for ``--diff-with``. HEX files are automatically split into multiple binary files, which are then matched sequentially to the files being flashed.

The following example will fast reflash the changed sectors of ``bootloader.bin`` and ``assets.bin`` files, while flashing the ``app.bin`` by full erase and and re-flashing (notice the ``skip`` keyword being used as a diff pair for the ``app.bin`` file):

::

    esptool write-flash 0x1000 bootloader.bin 0x10000 app.bin 0x20000 assets.bin --diff-with old_boot.bin skip old_assets.bin

.. note::

    Because of the ``skip`` keyword, no file named ``skip`` can be used as a diff data source.

The following example will fast reflash only ``bootloader.bin``, while fully flashing the ``app.bin`` and ``assets.bin`` (notice only one ``--diff-with`` file is provided):

::

    esptool write-flash 0x1000 bootloader.bin 0x10000 app.bin 0x20000 assets.bin --diff-with old_boot.bin

How It Works
""""""""""""

1. Esptool compares the new binary with the previously flashed binary on a sector-by-sector basis (4KB sectors).
2. It verifies that the device flash still contains the previous binary by computing an MD5 checksum.
3. If the previous binary is still in flash, only the changed sectors are rewritten.
4. If the flash content has changed (e.g., from a previous manual flash), the entire new binary is flashed.

This can dramatically reduce flashing time when only small portions of the firmware have changed, as only the modified 4KB sectors need to be erased and rewritten.

When Fast Reflashing is Most Effective
"""""""""""""""""""""""""""""""""""""""

Fast reflashing provides the greatest time savings when there are large blocks of unchanged data between the old and new binaries. This is particularly effective during development when using build systems that organize linker sections to minimize changes between builds.

.. note::

    The concept of organizing linker sections involves grouping code from **mutable libraries** (code that changes frequently, such as your application logic) separately from **immutable libraries** (code that rarely changes, such as framework libraries, bootloaders, or third-party dependencies) in the generated linker script. This creates large, continuous blocks of unchanged data in the output binary, which remain consistent even between application recompilations and can be skipped during flashing.

    This is an advanced build system optimization technique. If your build system doesn't organize linker sections this way, fast reflashing will still work, but may provide less time savings if changes are scattered throughout the binary.

Another scenario where fast reflashing is highly effective is when reflashing large asset files (e.g., images, fonts, or other binary data) that have changed only slightly.

No Diff Verification Mode
"""""""""""""""""""""""""

For even faster reflashing in repeatable scenarios (e.g., when you are certain the flash state will match the ``--diff-with`` files), you can use ``--no-diff-verify`` to skip the MD5 verification (second step in `How It Works <#how-it-works>`__). This can save significant amounts of time with large binaries:

::

    esptool write-flash 0x10000 new_app.bin --diff-with old_app.bin --no-diff-verify

.. warning::

    ``--no-diff-verify`` assumes the device flash still contains the previous binary. If the flash has been modified (e.g., by another flashing operation or manual changes), the fast reflashing may produce incorrect results. Only use this option when you are certain the flash state matches the ``--diff-with`` file.

.. note::

    The ``--no-diff-verify`` option is mutually exclusive with ``--skip-flashed``. You cannot use both at the same time.

Limitations
"""""""""""

Fast reflashing is not available in the following scenarios:

.. list::

    * When ``--erase-all`` is used (entire flash is erased anyway)
    * When ``--encrypt`` or ``--encrypt-files`` is used (encrypted flashing)
    * When Secure Download Mode is active
    :esp8266: * On ESP8266 in ROM bootloader (active ``--no-stub``)

In these cases, esptool will automatically fall back to full re-flashing.

.. only:: esp32

    Bootloader Protection
    ^^^^^^^^^^^^^^^^^^^^^

    Flashing into the bootloader region (``0x0`` -> ``0x8000``) is disabled by default if active `Secure Boot V1 <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v1.html>`_ is detected.
    This is because Secure Boot V1 stores the signing key digest in eFuse, making the bootloader irreplaceable without the original key.
    This is a safety measure to prevent accidentally overwriting the secure bootloader, which **can ultimately lead to bricking the device**.

    `Secure Boot V2 <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html>`_ (available on ESP32 revision 3 and later) and all newer chips use a standardized scheme where the private signing key remains outside the chip, allowing safe bootloader updates.

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

    ``esptool`` checks every binary before flashing. If a valid firmware image is detected, the ``Chip ID`` and ``Minimum chip revision`` fields in its :ref:`header <image-format>` are compared against the actually connected chip.
    If the image turns out to be incompatible with the chip in use or requires a newer chip revision, flashing is stopped.

    This behavior can be overridden with the ``--force`` option.

Read Flash Contents: ``read-flash``
-----------------------------------

The read-flash command allows reading back the contents of flash. The arguments to the command are an address, a size, and a file path to output to. For example, to read a full 2MB of attached flash:

::

    esptool -p PORT -b 460800 read-flash 0 0x200000 flash_contents.bin


Size can be specified in bytes, or with suffixes like ``k`` and ``M``. So ``0x200000`` in example can be replaced with ``2M``.

It is also possible to autodetect flash size by using ``ALL`` as size. The above example with autodetection would look like this:

::

    esptool -p PORT -b 460800 read-flash 0 ALL flash_contents.bin


.. note::

    When using the ``read-flash`` command in combination with the ``--no-stub`` argument, it may be necessary to also set the ``--flash-size`` argument to ensure proper reading of the flash contents by the ROM.


.. note::

    If ``write-flash`` updated the boot image's :ref:`flash mode and flash size <flash-modes>` during flashing then these bytes may be different when read back.

.. _erase-flash:

Erase Flash: ``erase-flash`` & ``erase-region``
-----------------------------------------------

To erase the entire flash chip (all data replaced with 0xFF bytes):

::

    esptool erase-flash

To erase a region of the flash, starting at address 0x20000 with length 16 kB (0x4000 bytes):

::

    esptool erase-region 0x20000 16k

The address and length must both be multiples of the SPI flash erase sector size. This is 0x1000 (4096) bytes for supported flash chips.

.. only:: not esp8266

    Flash Protection
    ^^^^^^^^^^^^^^^^

    Erasing the flash chip is disabled by default if either active `Secure Boot <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/secure-boot-v2.html>`_ or
    `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_ is detected.
    This is a safety measure to prevent accidentally deleting the secure bootloader or encrypted data, which **can ultimately lead to bricking the device**.

    This behavior can be overridden with the ``--force`` option. **Use this only at your own risk and only if you know what you are doing!**

Read Built-in MAC Address: ``read-mac``
---------------------------------------

::

    esptool read-mac

.. _read-spi-flash-id:

Read SPI Flash ID: ``flash-id``
-------------------------------

::

    esptool flash-id

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

    esptool --chip {IDF_TARGET_NAME} elf2image my_app.elf

This command does not require a serial connection.

``elf2image`` also accepts the `Flash Modes <#flash-modes>`__ arguments ``--flash-freq`` and ``--flash-mode``, which can be used to set the default values in the image header. This is important when generating any image which will be booted directly by the chip.
These values can also be overwritten via the ``write-flash`` command, see the `write-flash command <#write-binary-data-to-flash-write-flash>`__ for details. Overwriting these values via the ``write-flash`` command will produce an image with a recalculated SHA256 digest, otherwise, the image SHA256 digest would be invalidated by rewriting the image header. There is an option to skip appending a SHA256 digest after the image with ``--dont-append-digest`` argument of the ``elf2image`` command.

By default, ``elf2image`` uses the sections in the ELF file to generate each segment in the binary executable. To use segments (PHDRs) instead, pass the ``--use-segments`` option.

.. only:: esp8266

    The default command output for {IDF_TARGET_NAME} is two binary files: ``my_app.elf-0x00000.bin`` and ``my_app.elf-0x40000.bin``. You can alter the firmware file name prefix using the ``--output/-o`` option.

    ``elf2image`` can also produce a "version 2" image file suitable for use with a software bootloader stub such as `rboot <https://github.com/raburton/rboot>`__ or the Espressif bootloader program. You can't flash a "version 2" image without also flashing a suitable bootloader.

    ::

        esptool --chip {IDF_TARGET_NAME} elf2image --version=2 -o my_app-ota.bin my_app.elf

.. only:: not esp8266

    For {IDF_TARGET_NAME}, elf2image produces a single output binary "image file". By default, this has the same name as the .elf file, with a .bin extension. For example:

    ::

        esptool --chip {IDF_TARGET_NAME} elf2image my_esp_app.elf

    In the above example, the output image file would be called ``my_esp_app.bin``.

    The ``--ram-only-header`` configuration is mainly applicable for use within the Espressif's SIMPLE_BOOT option from 3rd party OSes such as ZephyrOS and NuttX OS.
    For a detailed explanation of Simple Boot and how it works, see `Simple Boot explained <https://developer.espressif.com/blog/2025/06/simple-boot-explained/>`_.
    This option makes only the RAM segments visible to the ROM bootloader placing them at the beginning of the file and altering the segment count from the image header with the quantity of these segments, and also writing only their checksum. This segment placement may result in a more fragmented binary because of flash alignment constraints.
    It is strongly recommended to use this configuration with care, because the image built must then handle the basic hardware initialization and the flash mapping for code execution after ROM bootloader boot it.

.. _image-info:

Output .bin Image Details: ``image-info``
-----------------------------------------

The ``image-info`` command outputs some information (load addresses, segment sizes, set flash size, frequency, and mode, extended header information, etc) about a ``.bin`` file created by ``elf2image``. Command also supports ``.hex`` file created by ``merge-bin`` command from supported ``.bin`` files.

This information corresponds to the headers described in :ref:`image-format`.

::

    esptool image-info my_esp_app.bin

.. only:: not esp8266

    If the given binary file is an application with a valid `ESP-IDF application header <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/app_image_format.html#application-description>`__
    or a bootloader with a valid `ESP-IDF bootloader header <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/bootloader_image_format.html#bootloader-description>`__
    detected in the image, specific fields describing the application or bootloader are also displayed.

.. _merge-bin:

Merge Binaries for Flashing: ``merge-bin``
------------------------------------------
The ``merge-bin`` command will merge multiple binary files (of any kind) into a single file that can be flashed to a device later. Any gaps between the input files are padded based on the selected output format.

For example:

::

    esptool --chip {IDF_TARGET_NAME} merge-bin -o merged-flash.bin --flash-mode dio --flash-size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin

Will create a file ``merged-flash.bin`` with the contents of the other 3 files. This file can be later written to flash with ``esptool write-flash 0x0 merged-flash.bin``.


**Common options:**

*  The ``merge-bin`` command supports the same ``--flash-mode``, ``--flash-size`` and ``--flash-freq`` options as the ``write-flash`` command to override the bootloader flash header (see above for details).
   These options are applied to the output file contents in the same way as when writing to flash. Make sure to pass the ``--chip`` parameter if using these options, as the supported values and the bootloader offset both depend on the chip.
*  The ``--format`` option will change the format of the output file. For more information about formats see formats description below.
*  The input files can be in either ``bin`` or ``hex`` format and they will be automatically converted to type selected by ``--format`` argument.
*  It is possible to append options from a text file with ``@filename`` (see the advanced options page :ref:`Specifying Arguments via File <specify_arguments_via_file>` section for details). As an example, this can be conveniently used with the ESP-IDF build system, which produces a ``flash_args`` file in the build directory of a project:

.. code:: sh

    cd build    # The build directory of an ESP-IDF project
    esptool --chip {IDF_TARGET_NAME} merge-bin -o merged-flash.bin @flash_args


HEX Output Format
^^^^^^^^^^^^^^^^^

The output of the command will be in `Intel Hex format <https://www.intel.com/content/www/us/en/support/programmable/articles/000076770.html>`__. The gaps between the files won't be padded.

Intel Hex format offers distinct advantages when compared to the binary format, primarily in the following areas:

* **Transport**: Intel Hex files are represented in ASCII text format, significantly increasing the likelihood of flawless transfers across various mediums.
* **Size**: Data is carefully allocated to specific memory addresses eliminating the need for unnecessary padding. Binary images often lack detailed addressing information, leading to the inclusion of data for all memory locations from the file's initial address to its end.
* **Validity Checks**: Each line in an Intel Hex file has a checksum to help find errors and make sure data stays unchanged.

When using a merged Intel Hex file with the ``write-flash`` or ``image-info`` commands, the file is automatically split into temporary raw binary files at the gaps between input files.
This splitting process allows each section to be analyzed independently, producing output similar to running ``image-info`` on the original files before merging (with the only difference being the splitting based on gaps).

In contrast, analyzing a merged raw binary file only processes the header of the first file, providing less detailed information.

The splitting behavior of Intel Hex files offers an additional advantage during flashing: since no padding is used between sections, flash sectors between input files remain unerased. This can significantly improve flashing speed compared to using a merged raw binary file.

.. code:: sh

    esptool --chip {IDF_TARGET_NAME} merge-bin --format hex -o merged-flash.hex --flash-mode dio --flash-size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin

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

    esptool --chip {IDF_TARGET_NAME} merge-bin --format uf2 -o merged-flash.uf2 --flash-mode dio --flash-size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin


.. only:: not esp8266 and not esp32

    Commands Supported in Secure Download Mode
    ------------------------------------------

    When running a command against an SoC with active Secure Download Mode, only the following commands are supported:

    *  :ref:`write-flash`
    *  :ref:`erase-flash` (only ``erase-region``)
    *  :ref:`get-security-info`

    Running any other operation will result in an error. This is caused by the set of available serial protocol commands being restricted in Secure Download Mode, see :ref:`supported-in-sdm` for details.

    Binary image manipulation commands (``elf2image``, ``image-info``, ``merge-bin``) are not affected, because they do not require a serial connection with an SoC.

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
    :not esp8266 and not esp32: *  :ref:`get-security-info`
