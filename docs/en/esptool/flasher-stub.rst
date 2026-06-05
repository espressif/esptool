.. _stub:

Flasher Stub
============

``esptool`` is a serial flasher utility. It communicates with the ROM bootloader in `Espressif SoCs <https://www.espressif.com/en/products/hardware/socs>`_ in order to load user applications or read chip data via serial port.

The ROM bootloader is burned into the ESP chip during manufacturing and cannot be updated. A new version is issued only when a new chip revision is released.

``esptool`` works around the limitations imposed by a fixed ROM bootloader by implementing a flasher stub (also known as "stub loader" or just "stub"). It is a small application used as a temporary substitute or extension for the ROM.

When ``esptool`` connects to a chip, it first uploads the flasher stub, which basically replaces the original bootloader. All following operations are then handled by the stub.

Benefits
--------

The flasher stub behaves the same as the original bootloader, but uses more heavily optimized UART routines.

The main benefit is improved performance of flashing and some other operations (like reading flash). Additionally, it also allows to work around any bugs in ROM bootloaders.

Disabling the Stub Loader
-------------------------

There might be cases where it is necessary to disable the stub loader (e.g. debugging). To do that, run ``esptool`` with the ``--no-stub`` argument. All operations will then be handled by the original ROM bootloader. See the related :ref:`advanced options page <disable_stub>`.

Source and Development
----------------------

The flasher stub is developed in the `esp-flasher-stub <https://github.com/espressif/esp-flasher-stub>`_ project on GitHub. Prebuilt stub binaries are bundled with esptool releases. The sources, build instructions, and release notes are available in that repository.

Reporting Issues
----------------

Where to report a problem depends on what is failing:

* **Stub behaviour** (chip support, flash read/write/erase inside the stub, stub crashes or incorrect results): open an issue in `esp-flasher-stub issue tracker <https://github.com/espressif/esp-flasher-stub/issues>`_.
* **esptool integration** (uploading or starting the stub, CLI options, interaction between esptool and the stub): open an issue in `esptool issue tracker <https://github.com/espressif/esptool/issues>`_.

If a problem appears only with the default stub but disappears when falling back to the legacy stub (see below), please report it in `esp-flasher-stub issue tracker <https://github.com/espressif/esp-flasher-stub/issues>`_ so the new stub can be fixed before legacy support is removed.
