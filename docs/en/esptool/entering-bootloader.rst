.. _entering-the-bootloader:

Entering the Bootloader
=======================

Espressif chips have to be reset in a certain way in order to launch the serial bootloader, only then can ``esptool.py`` communicate with the ESP chip.

On some development boards (including NodeMCU, WeMOS, HUZZAH Feather, Core Board, ESP32-WROVER-KIT), esptool can :ref:`automatically trigger a reset into the serial bootloader <automatic-bootloader>` - in which case you don't need to read this section.

For everyone else, three things must happen to enter the serial bootloader (firmware download mode) - a reset, required pins set correctly, and a correct strapping pin pulled low. For more information, see the detailed :ref:`Boot Mode Selection<boot-mode>` guide.

Boot Mode
---------

Espressif chips choose the boot mode each time they reset. A reset event can happen in one of several ways:

.. list::

    *  Power applied to chip.
    :esp8266: *  The nRESET pin was low and is pulled high.
    *  The CH_PD/EN pin ("enable") pin was low and is pulled high.

.. only:: esp8266

    On {IDF_TARGET_NAME}, both the nRESET and CH_PD pins must be pulled high for the chip to start operating.
