{IDF_TARGET_BOOTLOADER_OFFSET:default="0x0", esp32="0x1000", esp32s2="0x1000", esp32p4="0x2000"}

.. _flashing:

Flashing Firmware
=================

Esptool is used under the hood of many development frameworks for Espressif SoCs, such as `ESP-IDF <https://docs.espressif.com/projects/esp-idf/>`_, `Arduino <https://docs.espressif.com/projects/arduino-esp32/>`_, or `PlatformIO <https://docs.platformio.org/en/latest/platforms/espressif32.html>`_.
After the resulting firmware binary files are compiled, esptool is used to flash these into the device.

Sometimes there might be a need to comfortably flash a bigger amount of devices with the same binaries or to share flashing instructions with a third party.
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

ESP-IDF outputs the full esptool command used for flashing after the build is finished, for example::

    Project build complete. To flash, run:
    idf.py flash
    or
    idf.py -p PORT flash
    or
    python -m esptool --chip {IDF_TARGET_PATH_NAME} -b 460800 --before default_reset --after hard_reset write-flash --flash-mode dio --flash-size 2MB --flash-freq 40m {IDF_TARGET_BOOTLOADER_OFFSET} build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin 0x10000 build/hello_world.bin
    or from the "esp-idf/examples/get-started/hello_world/build" directory
    python -m esptool --chip {IDF_TARGET_PATH_NAME} -b 460800 --before default_reset --after hard_reset write-flash "@flash_args"

Arduino
^^^^^^^

The full esptool command is hidden from the user by default. To expose it, open the preferences window and check the ``Show verbose output during: upload`` option. A full command will be shown while uploading the sketch.

PlatformIO
^^^^^^^^^^

To do a verbose upload and see the exact esptool invocation, run ``pio run -v -t upload`` in the terminal. In the generated output, there is the full esptool command, you will see something like:

::

    ".../.platformio/penv/bin/python" ".../.platformio/packages/tool-esptoolpy/esptool.py" --chip {IDF_TARGET_PATH_NAME} --port "/dev/cu.usbserial001" --baud 921600 --before default_reset --after hard_reset write-flash -z --flash-mode dio --flash-freq 40m --flash-size detect {IDF_TARGET_BOOTLOADER_OFFSET} .../.platformio/packages/framework-arduinoespressif32/tools/sdk/bin/bootloader_dio_40m.bin 0x8000 .../project_folder/.pio/build/esp32doit-devkit-v1/partitions.bin 0xe000 .../.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin 0x10000 .pio/build/esp32doit-devkit-v1/firmware.bin


Flashing
--------

If you split the output, you'll find the ``write-flash`` command with a list of paths to binary files and their respective flashing offsets. If necessary, change the paths to the actual file locations.

Change ``PORT`` to the name of :ref:`actually used serial port <serial-port>` and run the command. A successful flash looks like this::

    $ python -m esptool -p /dev/tty.usbserial-0001 -b 460800 --before default_reset --after hard_reset --chip {IDF_TARGET_PATH_NAME} write-flash --flash-mode dio --flash-size detect --flash-freq 40m {IDF_TARGET_BOOTLOADER_OFFSET} build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin 0x10000 build/hello_world.bin
    esptool.py v4.8.1
    Serial port /dev/tty.usbserial-0001:
    Connecting.........
    Connected to ESP32 on /dev/tty.usbserial-0001:
    Chip type:          ESP32-D0WD (revision 1)
    Features:           WiFi, BT, Dual Core, 240MHz, Vref calibration in eFuse, Coding Scheme None
    Crystal frequency:  40MHz
    MAC:                de:ad:be:ef:1d:ea

    Uploading stub flasher...
    Running stub flasher...
    Stub flasher running.
    Changing baud rate to 460800...
    Changed.
    Configuring flash size...
    Auto-detected flash size: 4MB
    Flash will be erased from 0x00001000 to 0x00007fff...
    Flash will be erased from 0x00008000 to 0x00008fff...
    Flash will be erased from 0x00010000 to 0x00039fff...
    Flash parameters set to 0x0240.
    SHA digest in image updated.
    Compressed 25536 bytes to 15935...
    Wrote 25536 bytes (15935 compressed) at 0x00001000 in 0.7 seconds (effective 275.5 kbit/s).
    Hash of data verified.
    Compressed 3072 bytes to 103...
    Wrote 3072 bytes (103 compressed) at 0x00008000 in 0.1 seconds (effective 334.1 kbit/s).
    Hash of data verified.
    Compressed 169232 bytes to 89490...
    Wrote 169232 bytes (89490 compressed) at 0x00010000 in 2.6 seconds (effective 513.0 kbit/s).
    Hash of data verified.

    Hard resetting via RTS pin...

It is now possible to unplug the flashed device and repeat the process by connecting another one and running the command again.
