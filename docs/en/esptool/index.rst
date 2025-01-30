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
   Flasher Stub <flasher-stub>
   Flash Modes <flash-modes>
   Entering the Bootloader <entering-bootloader>
   Serial Connection <serial-connection>
   Configuration File <configuration-file>
   Remote Serial Ports <remote-serial-ports>
   Flashing Firmware <flashing-firmware>
   Scripting <scripting>

.. only:: not esp8266

   Instructions for other tools bundled with esptool:

   * :ref:`espefuse`
   * :ref:`espsecure`
