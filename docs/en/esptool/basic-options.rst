.. _options:

Basic Options
=============

These are the basic/fundamental esptool options needed to define the communication with an ESP target. For advanced configuration options, see the :ref:`advanced-options` page.

Esptool has global and command-specific options. Global options have to be specified after ``esptool.py``. They are used to configure the serial port, baud rate, and chip type.
Command-specific options are specified after the command and are used to configure the command itself. For more information about commands and their options, see :ref:`commands` or see help in the command line.

.. _chip-type:

Chip Type: ``--chip``, ``-c``
-----------------------------

* The target chip type can be selected using the ``--chip``/ ``-c`` option, e.g. ``esptool.py --chip {IDF_TARGET_PATH_NAME} <command>``.
* A default chip type can be specified by setting the ``ESPTOOL_CHIP`` environment variable.
* If no ``-c`` option or ``ESPTOOL_CHIP`` value is specified, ``esptool.py`` automatically detects the chip type when connecting.
* Binary image generation commands, such as :ref:`elf2image <elf-2-image>` or :ref:`merge_bin <merge-bin>`, require the chip type to be specified.

.. _serial-port:

Serial Port: ``--port``, ``-p``
-------------------------------

*  The serial port is selected using the ``-p`` option, like ``-p /dev/ttyUSB0`` (Linux and macOS) or ``-p COM1`` (Windows).
*  A default serial port can be specified by setting the ``ESPTOOL_PORT`` environment variable.
*  If no ``-p`` option or ``ESPTOOL_PORT`` value is specified, ``esptool.py`` will enumerate all connected serial ports and try each one until it finds an Espressif device connected.

.. note::

    Windows and macOS may require drivers to be installed for a particular USB/serial adapter, before a serial port is available. Consult the documentation for your particular device.
    On macOS, you can also consult `System Information <https://support.apple.com/en-us/HT203001>`__'s list of USB devices to identify the manufacturer or device ID when the adapter is plugged in.
    On Windows, you can use `Windows Update or Device Manager <https://support.microsoft.com/en-us/help/15048/windows-7-update-driver-hardware-not-working-properly>`__ to find a driver.

If using Cygwin or WSL on Windows, you have to convert the Windows-style name into a Unix-style path (``COM1`` -> ``/dev/ttyS0``, and so on). (This is not necessary if using ESP-IDF with the supplied Windows MSYS2 environment,
this environment uses a native Windows Python which accepts COM ports as-is.)

In Linux, the current user may not have access to serial ports and a "Permission Denied" or "Port doesn't exist" errors may appear.
On most Linux distributions, the solution is to add the user to the ``dialout`` group (check e.g. ``ls -l /dev/ttyUSB0`` to find the group) with a command like ``sudo usermod -a -G dialout $USER``.
You can call ``su - $USER`` to enable read and write permissions for the serial port without having to log out and back in again.
Check your Linux distribution's documentation for more information.

Baud Rate: ``--baud``, ``-b``
-----------------------------

The default esptool baud rate is 115200bps. Different rates may be set using ``-b 921600`` (or another baud rate of your choice). A default baud rate can also be specified using the ``ESPTOOL_BAUD`` environment variable. This can speed up ``write_flash`` and ``read_flash`` operations.

The baud rate is limited to 115200 when esptool establishes the initial connection, higher speeds are only used for data transfers.

Most hardware configurations will work with ``-b 230400``, some with ``-b 460800``, ``-b 921600`` and/or ``-b 1500000`` or higher.

.. only:: esp8266

    If you have connectivity problems then you can also set baud rates below 115200. You can also choose 74880, which is the :ref:`usual baud rate used by the ESP8266 <serial-port-settings>` to output :ref:`boot-log-esp8266` information.

.. only:: not esp8266

    If you have connectivity problems then you can also set baud rates below 115200.
