.. _advanced-options:

Advanced Options
================

The following advanced configuration options can be used for all esptool commands (they are placed before the command name on the command line).

For basic/fundamental configuration options, see the :ref:`options` page.

Reset Modes
-----------

By default, esptool tries to hard reset the chip into bootloader mode before it starts and hard resets the chip to run the normal program once it is complete. The ``--before`` and ``--after`` options allow this behavior to be changed:

Reset Before Operation
^^^^^^^^^^^^^^^^^^^^^^

The ``--before`` argument allows you to specify whether the chip needs resetting into bootloader mode before esptool talks to it.

.. list::

    * ``--before default_reset`` is the default, which uses DTR & RTS serial control lines (see :ref:`entering-the-bootloader`) to try to reset the chip into bootloader mode.
    * ``--before no_reset`` will skip DTR/RTS control signal assignments and just start sending a serial synchronisation command to the chip. This is useful if your chip doesn't have DTR/RTS, or for some serial interfaces (like Arduino board onboard serial) which behave differently when DTR/RTS are toggled.
    * ``--before no_reset_no_sync`` will skip DTR/RTS control signal assignments and skip also the serial synchronization command. This is useful if your chip is already running the :ref:`stub bootloader <stub>` and you want to avoid resetting the chip and uploading the stub again.
    :esp32c3 or esp32s3 or esp32c6 or esp32h2: * ``--before usb_reset`` will use custom reset sequence for USB-JTAG-Serial (used for example for ESP chips connected through the USB-JTAG-Serial peripheral). Usually, this option doesn't have to be used directly. Esptool should be able to detect connection through USB-JTAG-Serial.

Reset After Operation
^^^^^^^^^^^^^^^^^^^^^

The ``--after`` argument allows you to specify whether the chip should be reset after the esptool operation completes:

.. list::

    * ``--after hard_reset`` is the default. The DTR serial control line is used to reset the chip into a normal boot sequence.
    :esp8266:* ``--after soft_reset`` This runs the user firmware, but any subsequent reset will return to the serial bootloader. This was the reset behaviour in esptool v1.x.
    * ``--after no_reset`` leaves the chip in the serial bootloader, no reset is performed.
    * ``--after no_reset_stub`` leaves the chip in the stub bootloader, no reset is performed.

.. _disable_stub:

Disabling the Stub Loader
-------------------------

The ``--no-stub`` option disables uploading of a software "stub loader" that manages flash operations, and only talks directly to the loader in ROM.

Passing ``--no-stub`` will disable certain options, as not all options are implemented in every chip's ROM loader.

.. only:: not esp8266

    Overriding SPI Flash Connections
    --------------------------------

    The optional ``--spi-connection`` argument overrides the SPI flash connection configuration on ESP32. This means that the SPI flash can be connected to other pins, or esptool can be used to communicate with a different SPI flash chip to the default.

    Supply the ``--spi-connection`` argument after the ``esptool.py`` command, ie ``esptool.py flash_id --spi-connection HSPI``.

    Default Behavior
    ^^^^^^^^^^^^^^^^

    If the ``--spi-connection`` argument is not provided, the SPI flash is configured to use :ref:`pin numbers set in efuse <espefuse-spi-flash-pins>`. These are the same SPI flash pins that are used during a normal boot.

    The only exception to this is if the ``--no-stub`` option is also provided. In this case, efuse values are ignored and ``--spi-connection`` will default to ``--spi-connection SPI`` unless set to a different value.

    .. only:: esp32

        SPI Mode
        ^^^^^^^^

        ``--spi-connection SPI`` uses the default SPI pins:

        * CLK = GPIO 6
        * Q = GPIO 7
        * D = GPIO 8
        * HD = GPIO 9
        * CS = GPIO 11

        During normal booting, this configuration is selected if all SPI pin efuses are unset and GPIO1 (U0TXD) is not pulled low (default).

        This is the normal pin configuration for ESP32 chips that do not contain embedded flash.

        HSPI Mode
        ^^^^^^^^^

        ``--spi-connection HSPI`` uses the HSPI peripheral instead of the SPI peripheral for SPI flash communications, via the following HSPI pins:

        * CLK = GPIO 14
        * Q = GPIO 12
        * D = GPIO 13
        * HD = GPIO 4
        * CS = GPIO 15

        During normal booting, this configuration is selected if all SPI pin efuses are unset and GPIO1 (U0TXD) is pulled low on reset.

    Custom SPI Pin Configuration
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ``--spi-connection <CLK>,<Q>,<D>,<HD>,<CS>`` allows a custom list of pins to be configured for the SPI flash connection. This can be used to emulate the flash configuration equivalent to a particular set of SPI pin efuses being burned. The values supplied are GPIO numbers.

    .. only:: esp32

        For example, ``--spi-connection 6,17,8,11,16`` sets an identical configuration to the factory efuse configuration for ESP32s with embedded flash.

        When setting a custom pin configuration, the SPI peripheral (not HSPI) will be used unless the ``CLK`` pin value is set to 14 (HSPI CLK), in which case the HSPI peripheral will be used.

    .. note::

        Some GPIO pins might be shared with other peripherals. Therefore, some SPI pad pin configurations might not work reliably or at all. Use a different combination of pins if you encounter issues.

Specifying Arguments via File
-----------------------------
.. _specify_arguments_via_file:

Anywhere on the esptool command line, you can specify a file name as ``@filename.txt`` to read one or more arguments from text file ``filename.txt``. Arguments can be separated by newlines or spaces, quotes can be used to enclose arguments that span multiple words. Arguments read from the text file are expanded exactly as if they had appeared in that order on the esptool command line.

An example of this is available in the :ref:`merge_bin <merge-bin>` command description.

.. note:: PowerShell users

    Because of `splatting <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_splatting?view=powershell-7.3>`__ in PowerShell (method of passing a collection of parameter values to a command as a unit) there is a need to add quotes around @filename.txt ("@filename.txt") to be correctly resolved.
