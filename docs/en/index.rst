Esptool Documentation
=====================

.. important::

    This document describes how to use ``esptool`` with the {IDF_TARGET_NAME} SoC. To switch to a different SoC target, choose target from the dropdown in the upper left corner.

    Please note that this documentation is for the version of ``esptool`` v5. You can find your version in the command output or by running ``esptool version``.
    For the version of ``esptool`` v4 please refer to the `v4 documentation <https://docs.espressif.com/projects/esptool/en/release-v4/esp32/>`_ or pick from the dropdown in the upper left corner.

This is the documentation for ``esptool`` - a Python-based, open-source, platform-independent utility for flashing, provisioning, and interacting with Espressif SoCs. Esptool communicates with the ROM bootloader (or the flasher stub) in `Espressif SoCs <https://www.espressif.com/en/products/hardware/socs>`_.

The flasher stub is a small program included with esptool that replaces the original ROM bootloader in the chip to fix some of its limitations and bugs. See :ref:`stub` for more details.

``esptool``, ``espefuse`` and ``espsecure`` are a complete toolset for working with Espressif chips. They can do a number of things, for example:

* Read, write, erase, and verify binary data stored in flash.
* Read chip features and other related data such as MAC address or flash chip ID.
* Read and write the one-time-programmable eFuses.
* Prepare binary executable images ready for flashing.
* Analyze, assemble, and merge binary images.

``esptool`` can be used both as a command-line tool and as a Python library. The command-line is the most common way to use the tool, and is the primary focus of this documentation. To use it as a library, see the :ref:`scripting <scripting>` section.


Quick Start
-----------

Getting started is easy:

1) Install ``esptool``:

    ::

        $ pip install esptool

    For detailed instructions, see :ref:`installation`.


2) Connect an Espressif chip to your computer.

.. note::

    Please note that serial communication has to work and chip has to be in the :ref:`download mode <entering-the-bootloader>`.
    This is usually done :ref:`automatically <automatic-bootloader>` or can be done :ref:`manually <manual-bootloader>`. Esptool cannot function until this is resolved. For more information, see :ref:`troubleshooting`.

3) Run ``esptool`` commands. For example, to read information about your chip's SPI flash, run:

    ::

        $ esptool -p PORT flash-id

    Replace ``PORT`` with the name of used serial port. If connection fails, see :ref:`troubleshooting`.

After successfully executing the command, esptool will hard reset the chip, causing it to run the user code. This behavior can be adjusted, see :ref:`advanced-options`.

Alternatives
------------

``esptool`` is not the only tool for working with Espressif chips. Some notable options include:

- `esptool.js <https://github.com/espressif/esptool-js>`__ is a JavaScript port of esptool that can be used in a web browser or in a Node.js environment.
- `espflash <https://github.com/esp-rs/espflash>`__ is a Rust port of esptool. It relies on the support in `esp-hal <https://github.com/esp-rs/esp-hal>`__, which may delay support for new chips.
- `OpenOCD <https://docs.espressif.com/projects/esp-idf/en/stable/api-guides/jtag-debugging/index.html#upload-application-for-debugging>`__ is a general-purpose tool for debugging and flashing chips.

Among these, esptool is the most feature-rich, and support for the newest chips and features usually appears here first.

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
