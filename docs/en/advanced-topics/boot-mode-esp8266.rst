.. _boot-mode-esp8266:

ESP8266 Boot Mode Selection
===========================

Guide to selecting boot mode correctly on ESP8266.

On many development boards with built-in USB/Serial, this is done for you and ``esptool`` can automatically reset the board into bootloader mode. For other configurations, you will need to follow these steps:

Required Pins
-------------

The following ESP8266 pins must be in a known state for either normal (flash boot) or serial bootloader operation. Most development boards or modules make necessary connections already, internally:

+--------+--------------------------------------------------------------------------------------------------------------------+
| GPIO   | State                                                                                                              |
+========+====================================================================================================================+
| 15     | Pulled Low/GND (directly connected to GND, or external pull-down resistor)                                         |
+--------+--------------------------------------------------------------------------------------------------------------------+
| 2      | Pull-up resistor High/VCC, or No Connection (pin has internal weak pullup, external pullup resistor is optional)   |
+--------+--------------------------------------------------------------------------------------------------------------------+

If these pins are set differently to shown, nothing on the ESP8266 will work as expected. See `ESP8266 Pin List document <https://www.espressif.com/en/support/documents/technical-documents?keys=ESP8266+Pin+List>`__ to see what boot modes are enabled for different pin combinations.

When the ESP8266 goes into serial bootloader mode, the Boot ROM switches GPIO2 to an output and the UART TX signal is also output to this pin. For this reason GPIO2 should not be directly connected to VCC. Similarly, make sure GPIO2 is not connected to another peripheral where this may cause an issue when in download mode.

Select Bootloader Mode
----------------------

The ESP8266 will enter the serial bootloader when GPIO0 is held low on reset. Otherwise it will run the program in flash.

+---------------+----------------------------------------+
| GPIO0 Input   | Mode                                   |
+===============+========================================+
| Low/GND       | ROM serial bootloader for esptool      |
+---------------+----------------------------------------+
| High/VCC      | Normal execution mode                  |
+---------------+----------------------------------------+

Many configurations use a "Flash" button that pulls GPIO0 low when pressed.

Automatic Bootloader
--------------------

``esptool`` can automatically enter the bootloader on many boards by using the RTS and DTR modem status lines to toggle GPIO0 and EN automatically.

Make the following connections for ``esptool`` to automatically enter the bootloader:

+---------------------------------+--------------+
| ESP8266 Pin                     | Serial Pin   |
+=================================+==============+
| CH_PD ("enable") *or* nRESET    | RTS          |
+---------------------------------+--------------+
| GPIO0                           | DTR          |
+---------------------------------+--------------+

Note that some serial terminal programs (not esptool) will assert both RTS and DTR when opening the serial port, pulling them low together and holding the ESP8266 in reset. If you've wired RTS to the ESP8266 then you should disable RTS/CTS "hardware flow control" in the program.
Development boards like NodeMCU use additional circuitry to avoid this problem - if both RTS and DTR are asserted together, this doesn't reset the chip.

In Linux serial ports by default will assert RTS when nothing is attached to them. This can hold the ESP8266 in a reset loop which may cause some serial adapters to subsequently reset loop. This functionality can be disabled by disabling ``HUPCL`` (ie ``sudo stty -F /dev/ttyUSB0 -hupcl``).


.. _boot-log-esp8266:

ESP8266 Boot Log
================

The ESP8266 boot rom writes a log to the UART when booting. The timing is a little bit unusual: ``74880 baud``

::

    ets Jan  8 2014,rst cause 1, boot mode:(3,7)

    load 0x40100000, len 24236, room 16
    tail 12
    chksum 0xb7
    ho 0 tail 12 room 4
    load 0x3ffe8000, len 3008, room 12
    tail 4
    chksum 0x2c
    load 0x3ffe8bc0, len 4816, room 4
    tail 12
    chksum 0x46
    csum 0x46


Boot ROM Log Explanation:
-------------------------

**rst_cause:**

+---------------+----------------------------------------+
| Value         | Meaning                                |
+===============+========================================+
| 1             | power-on                               |
+---------------+----------------------------------------+
| 2             | external-reset                         |
+---------------+----------------------------------------+
| 4             | hardware watchdog-reset                |
+---------------+----------------------------------------+


**The first parameter of boot_mode:**

+-------------------------+----------------------------------------------+
| Value                   | Meaning                                      |
+=========================+==============================================+
| 1 (eg. boot mode:(1,x)) | UART download mmode (download FW into Flash) |
+-------------------------+----------------------------------------------+
| 2 (eg. boot mode:(3,x)) | Boot from flash mode                         |
+-------------------------+----------------------------------------------+

**chksum:**

If value of “chksum” == value of “csum”, it means flash has been read correctly during booting.

The rest of boot messages are used internally by Espressif.
