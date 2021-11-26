{IDF_TARGET_BAUD_RATE:default="115200", esp8266="74880 "}

Serial Connection
=================

The ROM serial bootloader of Espressif chips uses a 3.3V UART serial connection. Many development boards make the serial connections for you onboard.

However, if you are wiring the chip yourself to a USB/Serial adapter or similar then the following connections must be made:

+---------------------+-------------------+
| ESP Chip Pin        | Serial Port Pin   |
+=====================+===================+
| TX                  | RX (receive)      |
+---------------------+-------------------+
| RX                  | TX (transmit)     |
+---------------------+-------------------+
| Ground              | Ground            |
+---------------------+-------------------+

Note that TX (transmit) on the ESP chip is connected to RX (receive) on the serial port connection, and vice versa.

Do not connect the chip to 5V TTL serial adapters, and especially not to "standard" RS-232 adapters! 3.3V serial only! 

.. _serial-port-settings:

Serial Port Settings
--------------------

When communicating with the {IDF_TARGET_NAME} ROM serial bootloader, the following serial port settings are recommended:

+---------------------+-------------------+ 
| Baud rate           | {IDF_TARGET_BAUD_RATE}            |
+---------------------+-------------------+
| Data bits           | 8                 |
+---------------------+-------------------+
| Stop bits           | 1                 |
+---------------------+-------------------+
| Parity              | None              |
+---------------------+-------------------+
| Flow control        | None              |
+---------------------+-------------------+

.. only:: esp8266

    .. note::

        Baud rate {IDF_TARGET_BAUD_RATE} is what the {IDF_TARGET_NAME} bootloader uses. The apps on top of the Espressif SDK (e.g. Arduino sketch) talk at 115200 if not specified otherwise.
