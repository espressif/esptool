.. _esptool:

esptool.py
==========

Use ``esptool.py -h`` to see a summary of all available commands and command line options.

To see all options for a particular command, append ``-h`` to the command name. ie ``esptool.py write_flash -h``.

.. toctree::
   :maxdepth: 1

   Basic Options <basic-options>
   Basic Commands <basic-commands>
   Advanced Options <advanced-options>
   Advanced Commands <advanced-commands>
   Entering the Bootloader <entering-bootloader>
   Serial Connection <serial-connection>
   Flashing Firmware <flashing-firmware>
   Flasher Stub <flasher-stub>
   Flash Modes <flash-modes>
   Configuration File <configuration-file>
   Scripting <scripting>

.. only:: not esp8266

   Instructions for other tools bundled with esptool:

   * :ref:`espefuse`
   * :ref:`espsecure`
   * :ref:`esp_rfc2217_server.py <rfc2217_server>`
