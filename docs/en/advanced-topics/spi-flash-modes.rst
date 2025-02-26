.. _spi-flash-modes:

SPI Flash Modes
===============

The ESP chips support four different SPI flash access modes: DIO, DOUT, QIO & QOUT. These can be set via the ``--flash-mode`` option of ``esptool.py write-flash``.

These options control how many I/O pins are used for communication with the attached SPI flash chip, and which SPI commands are used.

ESP chips use these commands when reading or executing code and data from the SPI flash chip. Data is read and then cached internally to the chip.

Summary
-------

In order of performance:

+------------+---------------+----------------------------------+-----------------------------------+
| Option     | Mode Name     | Pins Used                        | Speed (ESP device)                |
+============+===============+==================================+===================================+
| ``qio``    | Quad I/O      | 4 pins used for address & data   | Fastest.                          |
+------------+---------------+----------------------------------+-----------------------------------+
| ``qout``   | Quad Output   | 4 pins used for data.            | Approx 15% slower than ``qio``.   |
+------------+---------------+----------------------------------+-----------------------------------+
| ``dio``    | Dual I/O      | 2 pins used for address & data   | Approx 45% slower than ``qio``.   |
+------------+---------------+----------------------------------+-----------------------------------+
| ``dout``   | Dual Output   | 2 pins used for data.            | Approx 50% slower than ``qio``.   |
+------------+---------------+----------------------------------+-----------------------------------+

In general, choose the fastest option for ``--flash-mode`` that works with your device. Not all devices support all modes. See FAQ below for details.

Mode Descriptions
-----------------

Normal SPI
^^^^^^^^^^

A traditional "single" SPI (Serial Peripheral Interface) bus uses 4 pins for communication:

*  Clock (CLK)
*  Master Out Slave In (MOSI)
*  Master In Slave Out (MISO)
*  Chip Select (CS)

`Wikipedia has a fairly complete description <https://en.wikipedia.org/wiki/Serial_Peripheral_Interface_Bus>`__.

All of these signals are unidirectional. In single SPI mode, data is sent from the device to the host using the MISO pin and from the host to the device using the MOSI pin.

The maximum data rate for normal SPI is the clock rate in bits - so a 40MHz clock = 40Mbits/sec = 5Mbytes/sec.

Dual SPI
^^^^^^^^

To improve performance, SPI flash manufacturers introduced "Dual SPI". In Dual SPI modes, the MOSI & MISO pins are both used to read or write data simultaneously with two bits per clock cycle. This doubles the data rate for some commands, compared to single SPI.

In ``dout`` mode, the host uses the "Dual Output Fast Read" (3BH) command to read data. Each read command and the read address is sent from the host to the flash chip via normal SPI, but then the host reads the data via both the MOSI & MISO pins simultaneously with two bits per clock.
This doubles the data transfer rate compared to single SPI which only uses MISO to read data.

In ``dio`` mode, the host uses the "Dual I/O Fast Read" (BBH) command to read data. Each read command is sent from the host to the flash chip via normal SPI, but then the address is sent to the flash chip via both the MOSI & MISO pins with two bits per clock.
After this, the host reads the data bits with two bits per clock in the same way as "Dual Output Fast Read".

For ESP chips, 32 bytes is read per command and ``dio`` mode is approximately 5% faster than ``dout``.

Consult the datasheet for your particular SPI flash chip to determine if it supports either or both of these commands.

Quad SPI
^^^^^^^^

To further improve the performance of SPI flash data transfers, SPI flash manufacturers introduced "Quad SPI" mode. This mode added two additional pins (otherwise used for flash chip ``WP`` and ``HOLD`` signals) for data transfers. This allows double the data rate of dual SPI.

Not all flash chips support Quad SPI modes, and not all ESP chips have these pins wired up to the SPI flash chip. Some flash chips require special commands to enable quad modes (see below).

In ``qout`` mode, the host uses the "Quad Output Fast Read" (6BH) command to read data. This command is the same as "Dual Output Fast Read", only data is read on 4 pins instead of 2 with 4 bits per clock cycle. This makes the data transfer exactly twice as fast as "Dual Output Fast Read".

In ``qio`` mode, the host uses the "Quad I/O Fast Read" (EBH) command to read data. This command is the same as "Dual I/O Fast Read", only both address & data are transferred on 4 pins instead of 2 with 4 bits per clock cycle.
This makes both the address & data transfer exactly twice as fast as "Dual I/O Fast Read".

.. only:: esp32s3

  Octal SPI
  ^^^^^^^^^

  Some ESP chips additionally support Octal SPI mode. This mode uses 8 pins for communication with the SPI flash chip, and allows for even faster data transfers than Quad SPI. This mode added four additional pins (SPIIO4~7) compared to Quad SPI for data transfers.

  The 1st and 2nd bootloaders don't support ``opi`` mode. Because of that esptool doesn't use ``opi`` and ``dout`` is used instead. The bootloader retrieves the information from eFuse and effectively replaces the mode.

  .. note::

    Use the ``esptool.py flash-id`` command to check if your ESP is using Quad or Octal SPI mode. It prints information based on the eFuse settings.


Frequently Asked Questions
--------------------------

Why don't qio & qout modes work with my Espressif chip/module?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is usually one of the following reasons:

* The WP and HOLD pins of the SPI flash chip are not wired to the correct GPIOs of the Espressif chip. These pins must be connected correctly for quad modes to work, and not all boards/modules connect them at all.
* The SPI flash chip does not support quad modes. Look up the flash chip datasheet to see which modes it supports. You can identify the flash chip visually, or by using the :ref:`esptool.py flash-id <read-spi-flash-id>` command.
* Quad mode is not enabled correctly for this chip model. SPI flash is not a standard, so every manufacturer implements their chip differently. Most flash chips require certain commands to be sent in order to enable Quad SPI modes, and these commands vary.
  For Espressif chips, this often means that the chip first boots in a Dual SPI mode and then software detects the chip type and tries to enable Quad SPI mode.
  If the particular chip model is not supported by the software then it won't be able to enter quad mode.

Why does qout/dout mode work but qio/dio mode doesn't work?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some SPI flash chip models only support the "Dual Output Fast Read" and/or "Quad Output Fast Read" commands, not their Dual I/O & Quad I/O equivalents.

Will my code run half as fast in Dual SPI mode compared to Quad SPI?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

No. Espressif chips execute code directly from flash, however because reading from flash is slow the data is cached transparently in RAM. Flash read commands are only sent went a cache miss occurs.
However, refilling the cache with a Dual SPI read is approximately half as fast as its Quad SPI equivalent.

If you can't use the Quad SPI modes, make sure you are configuring the fastest SPI Flash clock rate that works reliably on your board/module. An 80MHz SPI clock in Dual I/O mode is faster than a 40MHz SPI clock in Quad I/O mode.

How is flash mode communicated to the Espressif chip?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The bootloader .bin file, flashed to the SPI flash, contains a header which has flash speed, flash mode, and some other metadata. The initial host mode is determined by ROM code when it reads this header after reset.
Passing the  ``--flash-mode`` argument to esptool will update this header when the file is being written to flash.

This only determines the mode which is used for the initial boot from reset. Software may then configure the flash mode differently as part of the boot process.

For example, on ESP32 if ESP-IDF is configured for qio/qout mode then the IDF software bootloader is actually flashed with a dio/dout mode.
When ROM code boots this bootloader from flash, the bootloader software checks the flash chip model and enables the correct Quad SPI mode for the rest of the boot process.
This is because of the multiple different ways to enable Quad SPI on different chip models.
