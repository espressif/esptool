.. _entering-the-bootloader:

Entering the Bootloader
=======================

Espressif chips have to be reset in a certain way in order to launch the serial bootloader.

On some development boards (including NodeMCU, WeMOS, HUZZAH Feather, Core Board, ESP32-WROVER-KIT), esptool can automatically trigger a reset into the serial bootloader - in which case you don't need to read this section.

For everyone else, three things must happen to enter the serial bootloader - a reset, required pins set correctly, and GPIO0 pulled low:

Boot Mode
---------

Espressif chips choose the boot mode each time they reset. A reset event can happen in one of several ways:

*  Power applied to chip.
*  The nRESET pin was low and is pulled high (on ESP8266 only).
*  The CH_PD/EN pin ("enable") pin was low and is pulled high.

On ESP8266, both the nRESET and CH_PD pins must be pulled high for the chip to start operating.

For more details on selecting the boot mode, see the following Advanced Topics pages:

*  :ref:`ESP8266 Boot Mode Selection <boot-mode-esp8266>`
*  :ref:`ESP32 Boot Mode Selection <boot-mode-esp32>`
