{IDF_TARGET_BOOTLOADER_OFFSET:default="0x0", esp32="0x1000", esp32s2="0x1000"}

.. _troubleshooting:

Troubleshooting
===============

Flashing problems can be fiddly to troubleshoot. Try the suggestions here if you're having problems:

Bootloader Won't Respond
------------------------

If you see errors like "Failed to connect" then your chip is probably not entering the bootloader properly:

*  Check you are passing the correct serial port on the command line.
*  Check you have permissions to access the serial port, and other software (such as modem-manager on Linux) is not trying to interact with it. A common pitfall is leaving a serial terminal accessing this port open in another window and forgetting about it.
*  Check the chip is receiving 3.3V from a stable power source (see `Insufficient Power`_ for more details.)
*  Check that all pins are connected as described in :ref:`boot-mode`. Check the voltages at each pin with a multimeter, "high" pins should be close to 3.3V and "low" pins should be close to 0V.
*  If you have connected other devices to GPIO pins, try removing them and see if esptool starts working.
*  Try using a slower baud rate (``-b 9600`` is a very slow value that you can use to verify it's not a baud rate problem).

Writing to Flash Fails Part Way Through
---------------------------------------

If flashing fails with random errors part way through, retry with a lower baud rate.

Power stability problems may also cause this (see `Insufficient Power`_.)

Writing to Flash Succeeds but Program Doesn't Run
-------------------------------------------------

If esptool can flash your module with ``write_flash`` but your program doesn't run, check the following:

Wrong Flash Mode
^^^^^^^^^^^^^^^^

Some devices only support the ``dio`` flash mode. Writing to flash with ``qio`` mode will succeed but the chip can't read the flash back to run - so nothing happens on boot. Try passing the ``-fm dio`` option to ``write_flash``.

See the :ref:`spi-flash-modes` page for a full description of the flash modes and how to determine which ones are supported on your device.

Insufficient Power
^^^^^^^^^^^^^^^^^^

The 3.3V power supply for the ESP chip has to supply large amounts of current (up to 70mA continuous, 200-300mA peak, might be slightly higher). You also need sufficient capacitance on the power circuit to meet large spikes of power demand.

Insufficient Capacitance
''''''''''''''''''''''''

If you're using a pre-made development board or module then the built-in power regulator & capacitors are usually good enough, provided the input power supply is adequate.

.. note::

   This is not true for some very simple pin breakout modules - `similar to this <https://user-images.githubusercontent.com/205573/30140831-9da417a6-93ba-11e7-95c3-f422744967de.jpg>`_. These breakouts do not integrate enough capacitance to work reliably without additional components.
   Surface mount OEM modules like ESP-WROOM02 and ESP-WROOM32 require an external bulk capacitor on the PCB to be reliable, consult the module datasheet.

Power Supply Rating
'''''''''''''''''''

It is possible to have a power supply that supplies enough current for the serial bootloader stage with esptool, but not enough for normal firmware operation. You may see the 3.3V VCC voltage droop down if you measure it with a multimeter, but you can have problems even if this isn't happening.

Try swapping in a 3.3V supply with a higher current rating, add capacitors to the power line, and/or shorten any 3.3V power wires.

The 3.3V output from FTDI FT232R chips/adapters or Arduino boards *do not* supply sufficient current to power an ESP chip (it may seem to work sometimes, but it won't work reliably). Other USB TTL/serial adapters may also be marginal.

Missing Bootloader
^^^^^^^^^^^^^^^^^^
.. only:: esp8266

   The `ESP8266 SDK <https://github.com/espressif/ESP8266_RTOS_SDK>`_ uses a small firmware bootloader program. The hardware bootloader in ROM loads this firmware bootloader from flash, and then it runs the program.
   On ESP8266, firmware bootloader image (with a filename like ``boot_v1.x.bin``) has to be flashed at offset {IDF_TARGET_BOOTLOADER_OFFSET}. If the firmware bootloader is missing then the ESP8266 will not boot.

   Refer to ESP8266 SDK documentation for details regarding which binaries need to be flashed at which offsets.

.. only:: not esp8266

   `ESP-IDF <https://github.com/espressif/esp-idf>`_ and uses a small firmware bootloader program. The hardware bootloader in ROM loads this firmware bootloader from flash, and then it runs the program.
   On {IDF_TARGET_NAME}, the bootloader image should be flashed by ESP-IDF at offset {IDF_TARGET_BOOTLOADER_OFFSET}.

   Refer to ESP-IDF documentation for details regarding which binaries need to be flashed at which offsets.

SPI Pins Which Must Be Disconnected
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Compared to the ROM bootloader that esptool talks to, a running firmware uses more of the chip's pins to access the SPI flash.

If you set "Quad I/O" mode (``-fm qio``, the esptool default) then GPIOs 7, 8, 9 & 10 are used for reading the SPI flash and must be otherwise disconnected.

If you set "Dual I/O" mode (``-fm dio``) then GPIOs 7 & 8 are used for reading the SPI flash and must be otherwise disconnected.

Try disconnecting anything from those pins (and/or swap to Dual I/O mode if you were previously using Quad I/O mode but want to attach things to GPIOs 9 & 10). Note that if GPIOs 9 & 10 are also connected to input pins on the SPI flash chip, they may still be unsuitable for use as general purpose I/O.

In addition to these pins, GPIOs 6 & 11 are also used to access the SPI flash (in all modes). However flashing will usually fail completely if these pins are connected incorrectly.

Early Stage Crash
-----------------

.. only:: esp8266

   Use any of `serial terminal programs`_ to view the boot log. (ESP8266 baud rate is 74880bps). See if the program is crashing during early startup or outputting an error message.

.. only:: not esp8266

   Use any of `serial terminal programs`_ to view the boot log. ({IDF_TARGET_NAME} baud rate is 115200bps). See if the program is crashing during early startup or outputting an error message.

.. only:: not esp8266 and not esp32 and not esp32c2

   Issues When Using USB-Serial/JTAG or USB-OTG
   --------------------------------------------

   When working with ESP chips that implement a `USB-Serial/JTAG Controller <https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-guides/usb-serial-jtag-console.html>`_ or a `USB-OTG console <https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/usb-otg-console.html>`_, it's essential to be aware of potential issues related to the loaded application interfering with or reprogramming the GPIO pins used for USB communication.

   If the application accidentally reconfigures the USB peripheral pins or disables the USB peripheral, the device disappears from the system. You can also encounter unstable flashing or errors like ``OSError: [Errno 71] Protocol error``.

   If that happens, try :ref:`manually entering the download mode <manual-bootloader>` and then using the :ref:`erase_flash <erase_flash>` command to wipe the flash memory. Then, make sure to fix the issue in the application before flashing again.

Serial Terminal Programs
------------------------

There are many serial terminal programs suitable for debugging & serial interaction. The pySerial module (which is required for ``esptool``) includes one such command line terminal program - miniterm.py. For more details `see the related pySerial documentation <https://pyserial.readthedocs.io/en/latest/tools.html#module-serial.tools.miniterm>`_ or run ``miniterm -h``.
For exact serial port configuration values, see :ref:`serial-port-settings`.

.. only:: esp8266

   Note that not every serial program supports the unusual ESP8266 74880bps "boot log" baud rate. Support is especially sparse on Linux. miniterm.py supports this baud rate on all platforms.

Tracing Esptool Interactions
----------------------------

Running ``esptool.py --trace`` will dump all serial interactions to the standard output (this is *a lot* of output). This can be helpful when debugging issues with the serial connection, or when providing information for bug reports.

See :ref:`the related Advanced Topics page <tracing-communications>` for more information.

Configuration File
------------------

Although ``esptool.py`` has been tuned to work in the widest possible range of environments, an incompatible combination of hardware, OS, and drivers might cause it to fail. If you suspect this is the case, a custom configuration of internal variables might be necessary.

These variables and options can be specified in a configuration file. See :ref:`the related Configuration File page <config>` for more information.

Common Errors
-------------

This is a non-exhaustive list of the most common esptool errors together with explanations of possible causes and fixes. Before reading any error-specific advice, it is highly recommended to go through all of the `Troubleshooting`_ section first.

No serial data received.
^^^^^^^^^^^^^^^^^^^^^^^^

Esptool didn't receive any byte of data or a successful :ref:`slip packet <low-level-protocol>`. This error usually implies some kind of a hardware issue. This may be because the hardware is not working properly at all, the RX/TX serial lines are not connected, or because there is some problem with :ref:`resetting into the download mode <boot-mode>`.

.. only:: esp8266

   .. attention::

      There is a known issue regarding ESP8266 with the CH340 USB-to-serial converter (this includes NodeMCU and Wemos D1 mini devkits) on Linux. The regression affects only certain kernel versions. See `#653 <https://github.com/espressif/esptool/issues/653>`_ for details.

   On ESP8266, this error might be the result of a wrong boot mode. If your devkit supports this, try resetting into the download mode manually. See :ref:`manual-bootloader` for instructions.

.. only:: not esp8266

   Wrong boot mode detected (0xXX)! The chip needs to be in download mode.
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   Communication with the chip works (the ROM boot log is detected), but it is not being reset into the download mode automatically.

   To resolve this, check the autoreset circuitry (if your board has it), or try resetting into the download mode manually. See :ref:`manual-bootloader` for instructions.

   Download mode successfully detected, but getting no sync reply: The serial TX path seems to be down.
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   The chip successfully resets into the download mode and sends data to the host computer, but doesn't receive any response sent by ``esptool``. This implies a problem with the TX line running from the host to the ESP device. Double-check your board or breadboard circuit for any problems.

Invalid head of packet (0xXX): Possible serial noise or corruption.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This error is usually caused by one of the following reasons:

.. list::

   :esp8266: * The chip is not resetting into the download mode. If the chip runs in a normal boot from flash mode, the ROM writes a log to UART when booting (see :ref:`ESP8266 boot log <boot-log-esp8266>` for more information). This data in the serial buffer result in "Invalid head of packet". You can verify this by connecting with any of `Serial Terminal Programs`_ and seeing what data is the chip sending. If this turns out to be true, check the autoreset circuitry (if your board has it), or try resetting into the download mode manually. See :ref:`manual-bootloader` for instructions.
   * Using bad quality USB cable.
   * Sometimes breadboards can short the SPI flash pins on the board and cause this kind of problem. Try removing your development board from the breadboard.
   * The chip might be browning out during flashing. FTDI chips' internal 3.3V regulator is not enough to power an ESP, see `Insufficient Power`_.

Other things to try:

.. list::

   * Try to sync and communicate at a much lower baud rate, e.g. ``esptool.py --baud 9600 ...``.
   * Try `tracing the interactions <Tracing Esptool Interactions>`_ running ``esptool.py --trace ...`` and see if anything is received back at all.
   * Try skipping chip autodetection by specifying the chip type, run ``esptool.py --chip {IDF_TARGET_NAME} ...``.

If none of the above mentioned fixes help and your problem persists, please `open a new issue <https://github.com/espressif/esptool/issues/new/choose>`_.

A serial exception error occurred
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``esptool.py`` uses the `pySerial <https://pyserial.readthedocs.io/en/latest/>`_ Python module for accessing the serial port.
If pySerial cannot operate normally, it raises an error and terminates. Some of the most common pySerial error causes are:

.. list::

   * You don't have permission to access the port.
   * The port is being already used by other software.
   * The port doesn't exist.
   * The device gets unexpectedly disconnected.
   * The necessary serial port drivers are not installed or are faulty.

An example of a pySerial error:

.. code-block:: none

   A serial exception error occurred: read failed: [Errno 6] Device not configured

Errors originating from pySerial are, therefore, not a problem with ``esptool.py``, but are usually caused by a problem with hardware or drivers.
