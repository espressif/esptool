{IDF_TARGET_BOOTLOADER_OFFSET:default="0x0", esp32="0x1000", esp32s2="0x1000", esp32p4="0x2000", esp32c5="0x2000"}

.. _troubleshooting:

Troubleshooting
===============

Flashing problems can be fiddly to troubleshoot. The underlying issue can be caused by the drivers, OS, hardware, or even a combination of these. If your board is a custom design, check the `ESP Hardware Design Guidelines <https://docs.espressif.com/projects/esp-hardware-design-guidelines/>`_ or consider using our `free-of-charge schematic and PCB review service <https://www.espressif.com/en/contact-us/circuit-schematic-pcb-design-review>`_.

Try the following suggestions if your issues persist:

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

If esptool can flash your module with ``write-flash`` but your program doesn't run, check the following:

Wrong Flash Mode
^^^^^^^^^^^^^^^^

Some devices only support the ``dio`` flash mode. Writing to flash with ``qio`` mode will succeed but the chip can't read the flash back to run - so nothing happens on boot. Try passing the ``-fm dio`` option to ``write-flash``.

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

   Issues and Debugging in USB-Serial/JTAG or USB-OTG modes
   --------------------------------------------------------

   When working with ESP chips that implement a `USB-Serial/JTAG <https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-guides/usb-serial-jtag-console.html>`_ or a `USB-OTG <https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/usb-otg-console.html>`_ console (you are not using a classic USB-to-Serial adapter), it's essential to be aware of potential issues related to the loaded application interfering with or reprogramming the GPIO pins used for USB communication.

   If the application accidentally reconfigures the USB peripheral pins or disables the USB peripheral, the device disappears from the system. You can also encounter unstable flashing or errors like ``OSError: [Errno 71] Protocol error``.

   If that happens, try to :ref:`manually enter the download mode <manual-bootloader>` and then use the :ref:`erase-flash <erase-flash>` command to wipe the flash memory. Then, make sure to fix the issue in the application before flashing again.

   On boards with two USB ports (usually marked as USB and UART), you can use the USB port for flashing while listening on the UART port for debugging purposes. This setup is useful for retrieving core dumps or the reset reason in the event of a crash. To implement this, connect the UART port to another instance of any of the `serial terminal programs`_, while repeating the failing action over the USB port. You'll be able to monitor the crash log without interference from the USB port used for communication or it disappearing due to a firmware crash.
   If your devkit doesn't have a dedicated USB port connected to an on-board USB-to-UART bridge, you can use a separate adapter to connect to the UART pins on the board.

Serial Terminal Programs
------------------------

There are many serial terminal programs suitable for debugging & serial interaction. The pySerial module (which is required for ``esptool``) includes one such command line terminal program - miniterm.py. For more details `see the related pySerial documentation <https://pyserial.readthedocs.io/en/latest/tools.html#module-serial.tools.miniterm>`_ or run ``miniterm -h``.
For exact serial port configuration values, see :ref:`serial-port-settings`.

.. only:: esp8266

   Note that not every serial program supports the unusual ESP8266 74880bps "boot log" baud rate. Support is especially sparse on Linux. miniterm.py supports this baud rate on all platforms.

Tracing Esptool Interactions
----------------------------

Running ``esptool --trace`` will dump all serial interactions to the standard output (this is *a lot* of output). This can be helpful when debugging issues with the serial connection, or when providing information for bug reports.

See :ref:`the related Advanced Topics page <tracing-communications>` for more information.

Configuration File
------------------

Although ``esptool`` has been tuned to work in the widest possible range of environments, an incompatible combination of hardware, OS, and drivers might cause it to fail. If you suspect this is the case, a custom configuration of internal variables might be necessary.

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

   * Try to sync and communicate at a much lower baud rate, e.g. ``esptool --baud 9600 ...``.
   * Try `tracing the interactions <Tracing Esptool Interactions>`_ running ``esptool --trace ...`` and see if anything is received back at all.
   * Try skipping chip autodetection by specifying the chip type, run ``esptool --chip {IDF_TARGET_NAME} ...``.

If none of the above mentioned fixes help and your problem persists, please `open a new issue <https://github.com/espressif/esptool/issues/new/choose>`_.

A serial exception error occurred
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``esptool`` uses the `pySerial <https://pyserial.readthedocs.io/en/latest/>`_ Python module for accessing the serial port.
If pySerial cannot operate normally, it raises an error and terminates.

An example of a pySerial error:

.. code-block:: none

   A serial exception error occurred: read failed: [Errno 6] Device not configured

Errors originating from pySerial are, therefore, not a problem with ``esptool``, but are usually caused by a problem with hardware or drivers.

Some of the most common pySerial error causes are:

.. list::

   * The port is being already used by other software.
   * The port doesn't exist.
   * The device gets unexpectedly disconnected.
   * The necessary serial port drivers are not installed or are faulty.
   * You don't have permission to access the port.

On Linux, read and write access the serial port over USB is necessary. You can add your user to the ``dialout`` or ``uucp`` group to grant access to the serial port. See `Adding user to dialout or uucp on Linux <https://docs.espressif.com/projects/esp-idf/en/stable/get-started/establish-serial-connection.html#adding-user-to-dialout-or-uucp-on-linux>`_.


Failed to write to target RAM (result was 0107: Operation timed out)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``esptool`` requires a working and stable serial connection to the target. This connection can be affected by various factors, one of them being the OS drivers.
Some USB-to-Serial drivers exhibit unstable behavior in certain situations. This becomes especially apparent when transferring larger data packets (e.g., uploading the flasher stub or writing to flash).

This specific issue can sometimes be mitigated by:

.. list::

   * Using a :ref:`configuration file <config>` to increase esptool internal timeout values (mainly ``timeout`` and ``mem_end_rom_timeout``).
   * Updating or changing the USB-to-Serial drivers.
   * Using a different USB-to-Serial adapter.
   * Shortening the Host–>ESP serial communication path as much as possible (e.g., getting rid of USB hubs, using a shorter properly shielded cable, etc.).


Installation Fails on Unknown Project Name
------------------------------------------

If you see errors like this:

.. code-block:: none

   $ pip install esptool==5.1.0
   Collecting esptool==5.1.0
   ....
   WARNING: Generating metadata for package esptool produced metadata for project name unknown. Fix your #egg=esptool fragments.
   Discarding https://files.pythonhosted.org/packages/.../esptool-5.1.0.tar.gz (from https://pypi.org/simple/esptool/) (requires-python:>=3.10): Requested unknown from https://files.pythonhosted.org/packages/.../esptool-5.1.0.tar.gz has inconsistent name: filename has 'esptool', but metadata has 'unknown'
   ERROR: Could not find a version that satisfies the requirement esptool==5.1.0 (from versions: 4.0, 4.0.1, 4.1, 4.2, 4.2.1, 4.3, 4.4, 4.5, 4.5.1, 4.6, 4.6.1, 4.6.2, 4.7.0, 4.8.0, 4.8.1, 4.9.0, 4.10.0, 4.11.0, 5.0.0, 5.0.1, 5.0.2, 5.1.0)
   ERROR: No matching distribution found for esptool==5.1.0

or you are not able to install ``esptool`` version ``4.8.0`` or higher, then please make sure that your version of ``setuptools`` is at least ``64.0.0``. If you need to upgrade, you can run ``pip install setuptools>=64``.
Make sure that you are using a virtual environment and followed the installation instructions in the :ref:`installation` section.


Known Limitations and Issues
----------------------------

This section documents the currently known limitations and issues affecting esptool:

Flash and External Memory Support Limitations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

esptool has the following limitations when working with external flash and memory devices:

- NAND flash is currently not supported. Only NOR flash chips are supported.
- PSRAM access is not supported - esptool cannot read from or write to PSRAM.
- Octal (OPI) flash is supported only on ESP32-S3 devices.
- Accessing flash chip areas beyond 16MB (32-bit addressing) is supported only if **all** of the following conditions are met:

   - The :ref:`flasher stub <stub>` is used, as the ROM bootloader does not support 32-bit addressing.
   - The target chip is ESP32-S3, ESP32-C5, or ESP32-P4.
   - The flash chip is one of the following supported models:

      - W25Q256
      - GD25Q256
      - XM25QH256D

.. _sdm-limitations:

Secure Download Mode Limitations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When Secure Download Mode is enabled, the available serial protocol commands are restricted. In addition to being unable to read flash data or read/write RAM, the following limitations apply:

- The entire flash cannot be :ref:`erased <erase-flash>` using ``erase-flash``. Only flash regions aligned to multiples of ``4096`` (flash sector size) can be erased using ``erase-region``.

   - Writing a binary with purely ``0xFF`` bytes can be used as a workaround to essentially erase flash if necessary, but this is slow and achieves the same result as ``erase-region``.

- The baud rate cannot be :ref:`changed <baud-rate>` with the ``--baud`` option on ESP32-C5 and ESP32-C2.

   - Esptool needs to read specific registers to first detect the crystal frequency, which is then used to calculate the baud rate parameter for the ``CHANGE_BAUDRATE`` (``0x0F``) command. This is not possible in Secure Download Mode, because reading any registers is disabled.
   - The baud rate can be changed manually when using the :ref:`esptool API <scripting>` by sending the ``CHANGE_BAUDRATE`` command with the desired baud rate based on trial and error (e.g., seeing if the data is scrambled or not in a serial terminal program).

- Flash write or erase operations might fail with the ``0164`` or ``0106`` error codes.

   - This is usually caused by incorrect flash size settings. Since the actual flash size cannot be detected in Secure Download Mode, the ROM bootloader defaults to a flash size of 2MB. Trying to access flash regions larger than 2MB will then fail.
   - The flash size must be set manually using the ``--flash-size`` :ref:`option <flash-modes>` in CLI mode, or by calling the ``flash_set_parameters`` function when using the :ref:`esptool API <scripting>`.
   - Esptool prints a warning about this whenever possible.

- Accessing SPI flash memory regions larger than 16MB is not possible when Secure Download Mode is enabled.

   - This is only possible if the :ref:`flasher stub <stub>` is used as described in `Flash and External Memory Support Limitations`_, but stub flasher cannot be used in Secure Download Mode.
   - Any data written beyond the 16MB boundary will wrap around to the beginning of the flash because the 4-byte address gets truncated to 3 bytes.
   - An application running on the ESP device itself can still access data beyond 16MB (for example, during an OTA update).
   - It is recommended to only enable the Secure Download Mode if working with <16MB apps, if the app development is successfully finished, or if other ways to update the >16MB regions are available.
   - Esptool prints a warning about this whenever possible.

.. only:: not esp8266 and not esp32

   See the :ref:`supported-in-sdm` section for more details.

Secure Boot Limitations
^^^^^^^^^^^^^^^^^^^^^^^

- The :ref:`flasher stub <stub>` cannot currently be used on ESP32-C3 when Secure Boot is enabled.

   - This is due to a bug in the ROM bootloader that prevents custom code loaded into RAM from being executed.

.. _wdt-reset-limitations:

Watchdog Reset Limitations
^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``--after watchdog-reset`` :ref:`reset mode <after-reset>` mechanism was introduced to help to solve certain situations where the classic ``DTR``/``RTS`` reset lines are not available or not working properly. By its nature, it is a hack (hijacking the RTC WDT to trigger immediately and cause a full system reset).

Since it is not a standard reset mechanism, esptool uses it only when it is safe and beneficial. In other situations, it can be unstable or not available at all:

.. list::

   * Works and allows resetting out of download mode when USB-OTG is used for communication.
   * Disabled on the ESP32-C6 because it can cause a full system freeze requiring a power cycle to recover.
   * Not available at all on the ESP8266, ESP32, ESP32-H2, ESP32-H4, and ESP32-E22 because of hardware limitations.
   * Cannot be used in Secure Download Mode (SDM).
   * Can change its behavior between different chip ECO revisions.
   * Cannot be used to enter the download mode programmatically, the boot strapping pins have to still be physically pulled low.

Leaving Download Mode in USB-Serial/JTAG Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If USB-Serial/JTAG is used for communication and the download mode is :ref:`entered manually <manual-bootloader>` (typically by pressing the **EN** button while holding the **Boot** button on a DevKit), esptool cannot exit download mode using the default reset behavior.

Specifically, the USB-Serial/JTAG peripheral can only trigger a **core reset**, which does not re-sample the state of the boot strapping pin. As a result, the state of the boot pin remains sampled as LOW, even if it is physically released, and the chip stays in download mode instead of entering SPI boot mode (which requires the boot pin to be sampled as HIGH).

To automatically leave the download mode, the ``--after watchdog-reset`` option must be used. This triggers a full **system reset**, forcing the boot strapping pins to be re-sampled and allowing normal boot to proceed. This behavior is not enabled automatically, as doing so could introduce the issues described above.

Triggering a system reset manually is as easy as pressing the **EN** button on the DevKit or power-cycling it.
