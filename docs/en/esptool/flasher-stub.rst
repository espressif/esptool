.. _stub:

Flasher Stub
============

``esptool.py`` is a serial flasher utility that communicates with the ROM bootloader in `Espressif SoCs <https://www.espressif.com/en/products/hardware/socs>`_ to load user applications or read chip data via the serial port.

The ROM bootloader is programmed into the ESP chip during manufacturing and cannot be updated. A new version is issued only with a new chip revision.

``esptool.py`` overcomes the limitations of a fixed ROM bootloader by implementing a flasher stub (also known as a "stub loader" or simply "stub"). This is a small application used as a temporary substitute or extension for the ROM bootloader.

When ``esptool.py`` connects to a chip, it first uploads the flasher stub, which temporarily replaces the original bootloader. All subsequent operations are then handled by the stub.

Benefits
--------

The flasher stub behaves like the original bootloader but uses optimized UART routines for improved performance.

The main benefits are faster flashing and other operations (such as reading flash), as well as the ability to work around bugs in ROM bootloaders.

Disabling the Stub Loader
-------------------------

In some cases, you may need to disable the stub loader (e.g., for debugging). To do so, run ``esptool.py`` with the ``--no-stub`` argument. All operations will then be handled by the original ROM bootloader. See the related :ref:`advanced options page <disable_stub>`.
