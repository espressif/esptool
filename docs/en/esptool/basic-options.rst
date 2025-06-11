.. _options:

Basic Options
=============

These are the basic esptool options required to define communication with an ESP target. For advanced configuration, see :ref:`advanced-options`.

Esptool has both global and command-specific options. Global options must be specified after ``esptool.py`` and configure the serial port, baud rate, and chip type. Command-specific options are specified after the command and configure that command. For more information, see :ref:`commands` or use the command-line help.

.. _chip-type:

Chip Type: ``--chip``, ``-c``
-----------------------------

* Select the target chip type using ``--chip`` or ``-c``, e.g., ``esptool.py --chip {IDF_TARGET_PATH_NAME} <command>``.
* Set a default chip type with the ``ESPTOOL_CHIP`` environment variable.
* If neither ``-c`` nor ``ESPTOOL_CHIP`` is specified, esptool.py automatically detects the chip type when connecting.
* Some commands, such as :ref:`elf2image <elf-2-image>` or :ref:`merge-bin <merge-bin>`, require the chip type to be specified.

.. _serial-port:

Serial Port: ``--port``, ``-p``
-------------------------------

* Select the serial port using ``-p``, e.g., ``-p /dev/ttyUSB0`` (Linux/macOS) or ``-p COM1`` (Windows).
* Set a default serial port with the ``ESPTOOL_PORT`` environment variable.
* If neither ``-p`` nor ``ESPTOOL_PORT`` is specified, esptool.py enumerates all connected serial ports and tries each until it finds an Espressif device.

.. note::

    Windows and macOS may require drivers for your USB/serial adapter. Consult your device documentation.
    On macOS, use `System Information <https://support.apple.com/en-us/HT203001>`__ to identify the device. On Windows, use `Device Manager <https://support.microsoft.com/en-us/help/15048/windows-7-update-driver-hardware-not-working-properly>`__.

If using Cygwin or WSL on Windows, convert the Windows-style name to a Unix-style path (``COM1`` → ``/dev/ttyS0``). This is not necessary if using ESP-IDF with the MSYS2 environment, which accepts COM ports as-is.

On Linux, you may need to add your user to the ``dialout`` group to access serial ports (see ``ls -l /dev/ttyUSB0`` for the group). Use ``sudo usermod -a -G dialout $USER`` and ``su - $USER`` to enable permissions without logging out. Consult your distribution's documentation for details.

Baud Rate: ``--baud``, ``-b``
-----------------------------

The default esptool baud rate is 115200 bps. Set a different rate with ``-b 921600`` (or another value). You can also set a default with the ``ESPTOOL_BAUD`` environment variable. Higher baud rates speed up ``write-flash`` and ``read-flash`` operations.

The baud rate is limited to 115200 when esptool establishes the initial connection; higher speeds are used only for data transfers.

Most hardware works with ``-b 230400``; some support ``-b 460800``, ``-b 921600``, or ``-b 1500000`` or higher.

.. only:: esp8266

    If you have connectivity problems, you can set baud rates below 115200. You can also choose 74880, which is the :ref:`usual baud rate used by the ESP8266 <serial-port-settings>` to output :ref:`boot-log-esp8266` information.

.. only:: not esp8266

    If you have connectivity problems, you can set baud rates below 115200.
