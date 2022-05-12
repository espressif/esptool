Esptool.py Documentation
========================

This is the documentation for ``esptool.py`` - a Python-based, open source, platform independent utility to communicate with the ROM bootloader in `Espressif SoCs <https://www.espressif.com/en/products/hardware/socs>`_.

``esptool.py``, ``espefuse.py`` and ``espsecure.py`` are a complete toolset for working with Espressif chips. They can do a number of things, for example:

* Read, write, erase, and verify binary data stored in flash.
* Read chip features and other related data such as MAC address or flash chip ID.
* Read and write the one-time-programmable efuses.
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

3) Run ``esptool.py`` commands:

    ::

        $ esptool.py -p PORT flash_id

    Replace ``PORT`` with the name of used serial port. If connection fails, see :ref:`troubleshooting`.

More Information
----------------

.. toctree::
   :maxdepth: 1

   Installation <installation>
   Esptool <esptool/index>
   :not esp8266:Espefuse <espefuse/index>
   :not esp8266:Espsecure <espsecure/index>
   Advanced Topics <advanced-topics/index>
   Troubleshooting <troubleshooting>
   Contribute <contributing>
   Versions <versions>
   About <about>
