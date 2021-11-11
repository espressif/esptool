Flashing Firmware
=================

Esptool is used under the hood of many development frameworks for Espressif SoCs, such as `ESP-IDF <https://docs.espressif.com/projects/esp-idf/>`_, `Arduino <https://docs.espressif.com/projects/arduino-esp32/>`_, or `PlatformIO <https://docs.platformio.org/en/latest/platforms/espressif32.html>`_.
After the resulting firmware binary files are compiled, esptool is used to flash these into the device.

Sometimes there might be a need to comfortably flash a bigger amount of decives with the same binaries or to share flashing instructions with a third party.
It is possible to compile the firmware just once and then repeatedly use esptool (manually or :ref:`in a custom script <scripting>`) to flash the files.

Sharing these instructions and below mentioned assets with a third party (for example a manufacturer) should suffice to allow reproducible and quick flashing of your application into an Espressif chip.

.. note::

    The following texts are just an example, please see the documentation of the development framework of your choice for precise instructions.

Prerequisites
-------------

* Installed esptool, see the :ref:`installation guide <installation>` for instructions.
* All of the compiled binary files in a known location.
* Espressif chip connected to your computer.

Binary Files Location
---------------------

The generated binary files are usually stored in the ``build`` folder of your project.

For example, when building the `hello-world example project <https://github.com/espressif/esp-idf/tree/master/examples/get-started/hello_world>`_ in ESP-IDF, the resulting app binary can be found in  ``.../esp-idf/examples/get-started/hello_world/build/hello_world.bin``.
The same applies to the bootloader and the partition table.

The location of generated binaries depends on the used development framework. If you are unsure of the location, see the generated esptool `command <#command>`__ containing the full paths.

Command
-------

Compile and upload your firmware once with your preferred framework. The detailed esptool command will be displayed in the output right before the flashing happens.

It is also possible to assemble the command manually, please see the :ref:`esptool usage documentation<esptool>` for more information.

ESP-IDF
^^^^^^^

ESP-IDF outputs the full esptool command used for flashing after the build is finished::

    Project build complete. To flash, run this command:
    python esptool.py -p (PORT) -b 460800 --before default_reset --after hard_reset --chip esp32  write_flash --flash_mode dio --flash_size detect --flash_freq 40m 0x1000 build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin 0x10000 build/hello_world.bin
    or run 'idf.py -p (PORT) flash'

Arduino
^^^^^^^

The full esptool command is hidden from the user by default. To expose it, open the preferences window and check the ``Show verbose output during: upload`` option. A full command will be shown while uploading the sketch.

PlatformIO
^^^^^^^^^^

To do a verbose upload and see the exact esptool invocation, run ``pio run -v -t upload`` in the terminal. In the generated output, there is the full esptool command, e.g.:

::

    “.../.platformio/penv/bin/python2.7” “.../.platformio/packages/tool-esptoolpy/esptool.py” --chip esp32 --port “/dev/cu.usbserial001” --baud 921600 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0x1000 .../.platformio/packages/framework-arduinoespressif32/tools/sdk/bin/bootloader_dio_40m.bin 0x8000 .../project_folder/.pio/build/esp32doit-devkit-v1/partitions.bin 0xe000 .../.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin 0x10000 .pio/build/esp32doit-devkit-v1/firmware.bin


Flashing
--------

If you split the output, you’ll find the ``write_flash`` command with a list of paths to binary files and their respective flashing offsets. If necessary, change the paths to the actual file locations.

Change ``PORT`` to the name of :ref:`actually used serial port <serial-port>` and run the command. A successful flash looks like this::

    $ python esptool.py -p /dev/tty.usbserial-0001 -b 460800 --before default_reset --after hard_reset --chip esp32  write_flash --flash_mode dio --flash_size detect --flash_freq 40m 0x1000 build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin 0x10000 build/hello_world.bin
    esptool.py v3.2-dev
    Serial port /dev/tty.usbserial-0001
    Connecting.........
    Chip is ESP32-D0WD (revision 1)
    Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
    Crystal is 40MHz
    MAC: de:ad:be:ef:1d:ea
    Uploading stub...
    Running stub...
    Stub running...
    Changing baud rate to 460800
    Changed.
    Configuring flash size...
    Auto-detected Flash size: 16MB
    Flash will be erased from 0x00001000 to 0x00007fff...
    Flash will be erased from 0x00008000 to 0x00008fff...
    Flash will be erased from 0x00010000 to 0x00039fff...
    Flash params set to 0x0240
    Compressed 25536 bytes to 15935...
    Wrote 25536 bytes (15935 compressed) at 0x00001000 in 0.7 seconds (effective 275.5 kbit/s)...
    Hash of data verified.
    Compressed 3072 bytes to 103...
    Wrote 3072 bytes (103 compressed) at 0x00008000 in 0.1 seconds (effective 334.1 kbit/s)...
    Hash of data verified.
    Compressed 169232 bytes to 89490...
    Wrote 169232 bytes (89490 compressed) at 0x00010000 in 2.6 seconds (effective 513.0 kbit/s)...
    Hash of data verified.

    Leaving...
    Hard resetting via RTS pin...

It is now possible to unplug the flashed device and repeat the process by connecting another one and running the command again.
