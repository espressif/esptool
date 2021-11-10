Serial Connection
=================

The ROM serial bootloader of Espressif chips uses a 3.3V UART serial connection. Many development boards make the serial connections for you onboard.

However, if you are wiring the chip yourself to a USB/Serial adapter or similar then the following connections must be made:

+---------------------+-------------------+
| ESP Chip Pin        | Serial Port Pin   |
+=====================+===================+
| TX (aka GPIO1)      | RX (receive)      |
+---------------------+-------------------+
| RX (aka GPIO3)      | TX (transmit)     |
+---------------------+-------------------+
| Ground              | Ground            |
+---------------------+-------------------+

Note that TX (transmit) on the ESP chip is connected to RX (receive) on the serial port connection, and vice versa.

Do not connect the chip to 5V TTL serial adapters, and especially not to "standard" RS-232 adapters! 3.3V serial only!
