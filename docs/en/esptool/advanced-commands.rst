{IDF_TARGET_BOOTLOADER_OFFSET:default="0x0", esp32="0x1000", esp32s2="0x1000", esp32p4="0x2000"}

.. _advanced-commands:

Advanced Commands
=================

The ``write_flash``, ``read_flash``, ``erase_flash``, ``erase_region``, ``read_mac``, ``flash_id``, ``elf2image``, ``image_info`` and ``merge_bin`` commands are all documented in the :ref:`commands` section.

The following less common commands are for more advanced users.

.. _verify-flash:

Verify Flash Data: verify_flash
-------------------------------

The ``verify_flash`` command allows you to verify that data in flash matches a local file.

The ``write_flash`` command always verifies the MD5 hash of data which is written to flash, so additional verification is not usually needed. However, if you wish to perform a byte-by-byte verification of the flash contents (and optionally print the differences to the console) then you can do so with this command:

::

    esptool.py verify_flash --diff yes 0x40000 my_app.elf-0x40000.bin


The ``--diff yes`` option specifies that if the files are different, the details should be printed to the console.

.. note::

    .. list::

        * If verifying a default boot image (offset {IDF_TARGET_BOOTLOADER_OFFSET} for {IDF_TARGET_NAME}) then any ``--flash_mode``, ``--flash_size`` and ``--flash_freq`` arguments which were passed to `write_flash` must also be passed to ``verify_flash``. Otherwise, ``verify_flash`` will detect mismatches in the header of the image file.
        * Another way to compare flash contents is to use the ``read_flash`` command, and then use binary diffing tools on the host.

.. _dump-mem:

Dump a Memory Region to File: dump_mem
--------------------------------------

The ``dump_mem`` command will dump a region from the chip's memory space to a file. For example, to dump the ROM (64 kB) from an ESP8266:

::

    esptool.py dump_mem 0x40000000 65536 iram0.bin

.. _load-ram:

Load a Binary to RAM: load_ram
------------------------------

The ``load_ram`` command allows the loading of an executable binary image (created with the ``elf2image`` or ``make_image`` commands) directly into RAM, and then immediately executes the program contained within it. Command also supports ``.hex`` file created by ``merge_bin`` command from supported ``.bin`` files.

::

    esptool.py --no-stub load_ram ./test/images/helloworld-esp8266.bin

.. note::

    * The binary image must only contain IRAM- and DRAM-resident segments. Any SPI flash mapped segments will not load correctly and the image will probably crash. The ``image_info`` command can be used to check the binary image contents.
    * Because the software loader is resident in IRAM and DRAM, this limits the region where a new program may be loaded. An error will be printed if the new program overlaps with the software loader in RAM. Older esptool versions may hang. Pass ``esptool.py --no-stub`` to avoid this problem.
    * Due to a limitation in the ROM loader, when using ``--no-stub`` any very early serial output from a program may be lost if the program resets or reconfigures the UART. To avoid this problem, a program can be compiled with ``ets_delay_us(1)`` as the very first statement after the entry point.

.. _read-mem-write-mem:

Read or Write RAM: read_mem / write_mem
---------------------------------------

The ``read_mem`` & ``write_mem`` commands allow reading and writing single words (4 bytes) of RAM. This can be used to "peek" and "poke" at registers.

::

    esptool.py write_mem 0x400C0000 0xabad1dea

::

    esptool.py read_mem 0x400C0000

.. _read-flash-status:

Read Flash Chip Registers: read_flash_status
--------------------------------------------

This command is intended for use when debugging hardware flash chip-related problems. It allows sending a ``RDSR``, ``RDSR2`` and/or ``RDSR3`` commands to the flash chip to read the status register contents. This can be used to check write protection status, for example:

::

    esptool.py read_flash_status --bytes 2

The ``--bytes`` argument determines how many status register bytes are read.

* ``--bytes 1`` sends the most common ``RDSR`` command (05h) and returns a single byte of status.
* ``--bytes 2`` sends both ``RDSR`` (05h) and ``RDSR2`` (35h), reads one byte of status from each, and returns a two byte status.
* ``--bytes 3`` sends ``RDSR`` (05h), ``RDSR2`` (35h), and ``RDSR3`` (15h), reads one byte of status from each, and returns a 3 byte status.

.. note::

    Not all flash chips support all of these comands. Consult the specific flash chip datasheet for details.

.. _write-flash-status:

Write Flash Chip Registers: write_flash_status
-----------------------------------------------

This command is intended for use when debugging hardware flash chip-related problems. It allows sending ``WRSR``, ``WRSR2`` and/or ``WRSR3`` commands to the flash chip to write the status register contents. This can be used to clear write protection bits, for example:

::

    esptool.py write_flash_status --bytes 2 --non-volatile 0

The ``--bytes`` option is similar to the corresponding option for ``read_flash_status`` and causes a mix of ``WRSR`` (01h), ``WRSR2`` (31h), and ``WRSR3`` (11h) commands to be sent to the chip. If ``--bytes 2`` is used then ``WRSR`` is sent first with a 16-bit argument and then with an 8-bit argument, as different flash chips use this command differently.
Otherwise, each command is accompanied by 8-bits of the new status register value.

A second option ``--non-volatile`` can be used in order to send a ``WREN`` (06h) command before writing the status. This may allow non-volatile status register bits to be set or cleared. If the ``--non-volatile`` option is not supplied, a ``WEVSR`` (50h) command is sent instead of ``WREN``.

.. note::

    Consult the specific flash chip datasheet for details about which commands are recognised by a particular chip.

.. warning::

    Setting status bits (particularly non-volatile ones) can have permanent side effects for some flash chips, so check carefully before using this command to set any bits!

.. only:: esp8266

    .. _chip-id:

    Read the Chip ID: chip_id
    -------------------------

    The ``chip_id`` command allows you to read a 4 byte ID which forms part of the MAC address. It is usually better to use ``read_mac`` to identify a chip.

    On {IDF_TARGET_NAME}, output is the same as the ``system_get_chip_id()`` SDK function. The chip ID is four bytes long, the lower three bytes are the final bytes of the MAC address. The upper byte is zero.

    ::

        esptool.py chip_id

    .. _make-image:

    Assemble a Firmware Image: make_image
    -------------------------------------

    ``make_image`` allows you to manually assemble a firmware image from binary segments (such as those extracted from objcopy). For example:

    ::

        esptool.py --chip esp8266 make_image -f app.text.bin -a 0x40100000 -f app.data.bin -a 0x3ffe8000 -f app.rodata.bin -a 0x3ffe8c00 app.flash.bin

    This command does not require a serial connection.

    .. note::

        In general, it is better to create an ELF image (including any binary data as part of the ELF, by using objcopy or other tools) and then use ``elf2image`` to generate the ``.bin`` file.

    .. _run:

    Boot Application Code: run
    --------------------------

    The ``run`` command immediately exits the bootloader and attempts to boot the normal application code.
