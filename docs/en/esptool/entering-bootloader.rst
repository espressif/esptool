.. _entering-the-bootloader:

Entering the Bootloader
=======================

Espressif chips have to be reset in a certain way in order to launch the serial bootloader.

On some development boards (including NodeMCU, WeMOS, HUZZAH Feather, Core Board, ESP32-WROVER-KIT), esptool can automatically trigger a reset into the serial bootloader - in which case you don't need to read this section.

For everyone else, three things must happen to enter the serial bootloader - a reset, required pins set correctly, and GPIO0 pulled low:

Boot Mode
---------

Espressif chips choose the boot mode each time they reset. A reset event can happen in one of several ways:

.. list::

    *  Power applied to chip.
    :esp8266: *  The nRESET pin was low and is pulled high.
    *  The CH_PD/EN pin ("enable") pin was low and is pulled high.

.. only:: esp8266

    On ESP8266, both the nRESET and CH_PD pins must be pulled high for the chip to start operating.

.. only:: esp8266 or esp32

    For more details on selecting the boot mode, see the related :ref:`Advanced Topics page<boot-mode>`.
