{IDF_TARGET_BAUD_RATE:default="115200", esp8266="74880 "}

Serial Connection
=================

The ROM serial bootloader of Espressif chips uses a 3.3V UART serial connection. Many development boards provide onboard serial connections.

If you are wiring the chip yourself to a USB/Serial adapter or similar, make the following connections:

+---------------------+-------------------+
| ESP Chip Pin        | Serial Port Pin   |
+=====================+===================+
| TX                  | RX (receive)      |
+---------------------+-------------------+
| RX                  | TX (transmit)     |
+---------------------+-------------------+
| Ground              | Ground            |
+---------------------+-------------------+

Note: TX (transmit) on the ESP chip connects to RX (receive) on the serial port, and vice versa.

**Warning:** Do not connect the chip to 5V TTL serial adapters or standard RS-232 adapters! Use 3.3V serial only.

.. _serial-port-settings:

Serial Port Settings
--------------------

When communicating with the {IDF_TARGET_NAME} ROM serial bootloader, use the following serial port settings:

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

.. only:: esp32c2

    .. note::

        You might experience issues when using low baud rates on {IDF_TARGET_NAME}. If you encounter problems, use at least 115200 or higher.

.. only:: esp8266

.. note::

    The baud rate {IDF_TARGET_BAUD_RATE} is used by the {IDF_TARGET_NAME} bootloader. Applications on top of the Espressif SDK (e.g., Arduino sketches) use 115200 unless specified otherwise.
