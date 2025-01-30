Esptool.py Documentation
========================

This is the documentation for ``esptool.py`` - a Python-based, open source, platform independent serial communication tool. Esptool communicates with the ROM bootloader (or flasher stub) in `Espressif SoCs <https://www.espressif.com/en/products/hardware/socs>`_.
The flasher stub is a small program included with esptool that replaces the original ROM bootloader in the chip to fix some of its limitations and bugs. See :ref:`stub` for more details.

``esptool.py``, ``espefuse.py`` and ``espsecure.py`` are a complete toolset for working with Espressif chips. They can do a number of things, for example:

* Read, write, erase, and verify binary data stored in flash.
* Read chip features and other related data such as MAC address or flash chip ID.
* Read and write the one-time-programmable eFuses.
* Prepare binary executable images ready for flashing.
* Analyze, assemble, and merge binary images.

This document describes using ``esptool.py`` with the {IDF_TARGET_NAME} SoC. To switch to a different SoC target, choose target from the dropdown in the upper left.

Quick Start
-----------

Getting started is easy:

1) Install ``esptool.py``:

    ::

        $ pip install esptool

    For detailed instructions, see :ref:`installation`.


2) Connect an Espressif chip to your computer.

.. note::

    Please note that serial communication has to work and chip has to be in the :ref:`download mode <entering-the-bootloader>`.
    This is usually done :ref:`automatically <automatic-bootloader>` or can be done :ref:`manually <manual-bootloader>`. Esptool cannot function until this is resolved. For more information, see :ref:`troubleshooting`.

3) Run ``esptool.py`` commands. For example, to read information about your chip's SPI flash, run:

    ::

        $ esptool.py -p PORT flash_id

    Replace ``PORT`` with the name of used serial port. If connection fails, see :ref:`troubleshooting`.

After successfully executing the command, esptool will hard reset the chip, causing it to run the user code. This behavior can be adjusted, see :ref:`advanced-options`.

Alternatives
------------

``esptool.py`` is not the only tool for working with Espressif chips. Some notable options include:

- `esptool.js <https://github.com/espressif/esptool-js>`__ is a JavaScript port of esptool.py that can be used in a web browser or in a Node.js environment.
- `espflash <https://github.com/esp-rs/espflash>`__ is a Rust port of esptool.py. It relies on the support in `esp-hal <https://github.com/esp-rs/esp-hal>`__, which may delay support for new chips.
- `OpenOCD <https://docs.espressif.com/projects/esp-idf/en/stable/api-guides/jtag-debugging/index.html#upload-application-for-debugging>`__ is a general-purpose tool for debugging and flashing chips.

Among these, esptool.py is the most feature-rich, and support for the newest chips and features usually appears here first.

More Information
----------------

.. toctree::
   :maxdepth: 1

   Installation <installation>
   Esptool <esptool/index>
   :not esp8266:Espefuse <espefuse/index>
   :not esp8266:Espsecure <espsecure/index>
   Remote Serial Ports <remote-serial-ports>
   Advanced Topics <advanced-topics/index>
   Troubleshooting <troubleshooting>
   Contribute <contributing>
   Versions <versions>
   Migration Guide <migration-guide>
   Resources <resources>
   About <about>
