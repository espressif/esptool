.. _scripting:

Embedding into Custom Scripts
=============================

``esptool.py`` can be easily integrated into Python applications or called from other Python scripts.

Using Esptool as a Python Module
--------------------------------

The esptool module provides a comprehensive Python API for interacting with ESP chips programmatically. By leveraging the API, developers can automate tasks such as flashing firmware, reading device information, managing flash memory, or preparing and analyzing binary images. The API supports both high-level abstractions and low-level control.

Using the Command-Line Interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The most straightforward and basic integration option is to pass arguments to ``esptool.main()``. This workaround allows you to pass exactly the same arguments as you would on the CLI:

.. code-block:: python

    import esptool

    command = ['--baud', '460800', 'read-flash', '0', '0x200000', 'flash_contents.bin']
    print("Using command ", " ".join(command))
    esptool.main(command)

Public API Reference
^^^^^^^^^^^^^^^^^^^^

For more control and custom integration, esptool exposes a public API - a set of high-level functions that encapsulate common operations and simplify the interaction with the ESP chip. These functions are designed to be user-friendly and provide an intuitive way to work with the chip. The public API is the recommended way to interact with the chip programmatically.

Basic Workflow:

1. **Detect and Connect**: Use ``detect_chip()`` to automatically identify the connected ESP chip and establish a connection, or manually create and instantiate a specific ``ESPLoader`` object (e.g. ``ESP32ROM``) and establish a connection in two steps.
2. **Run Stub Flasher (Optional)**: Upload and execute the :ref:`stub flasher <stub>` which provides enhanced functionality and speed.
3. **Perform Operations**: Utilize the chip object's methods or public API command functions to interact with the device.
4. **Reset and Cleanup**: Ensure proper reset and resource cleanup using context managers.

------------

This example demonstrates writing two binary files using high-level commands:

.. code-block:: python

    from esptool.cmds import detect_chip, attach_flash, reset_chip, run_stub, write_flash

    PORT = "/dev/ttyACM0"
    BOOTLOADER = "bootloader.bin"
    FIRMWARE = "firmware.bin"

    with detect_chip(PORT) as esp:
        esp = run_stub(esp)  # Skip this line to avoid running the stub flasher
        attach_flash(esp)  # Attach the flash memory chip, required for flash operations
        with open(BOOTLOADER, "rb") as bl_file, open(FIRMWARE, "rb") as fw_file:
            write_flash(esp, [(0, bl_file), (0x1000, fw_file)])  # Write the binary files
        reset_chip(esp, "hard-reset")  # Reset the chip

- The ``esp`` object has to be replaced with the stub flasher object returned by ``run_stub(esp)`` when the stub flasher is activated. This step can be skipped if the stub flasher is not needed.
- Running ``attach_flash(esp)`` is required for any flash-memory-related operations to work.
- Using the ``esp`` object in a context manager ensures the port gets closed properly after the block is executed.

------------

The following example demonstrates running a series of flash memory operations in one go:

.. code-block:: python

    from esptool.cmds import (
    erase_flash,
    attach_flash,
    flash_id,
    read_flash,
    reset_chip,
    run_stub,
    verify_flash,
    write_flash,
    )
    from esptool.targets import ESP32ROM  # Import the target class, e.g. ESP8266ROM, ESP32S3ROM, etc.

    PORT = "/dev/ttyACM0"
    BOOTLOADER = "bootloader.bin"
    FIRMWARE = "firmware.bin"

    with ESP32ROM(PORT) as esp:
        esp.connect()  # Connect to the ESP chip, needed when ESP32ROM is instantiated directly
        esp = run_stub(esp)  # Run the stub loader (optional)
        attach_flash(esp)  # Attach the flash memory chip, required for flash operations
        flash_id(esp)  # Print information about the flash chip
        erase_flash(esp)  # Erase the flash memory first
        with open(BOOTLOADER, "rb") as bl_file, open(FIRMWARE, "rb") as fw_file:
            write_flash(esp, [(0, bl_file), (0x1000, fw_file)])  # Write the binary files
            verify_flash(esp, [(0, bl_file), (0x1000, fw_file)])  # Verify the written data
        read_flash(esp, 0x0, 0x2400, "output.bin")  # Read the flash memory into a file
        reset_chip(esp, "hard-reset")  # Reset the chip

- This example doesn't use ``detect_chip()``, but instantiates a ``ESP32ROM`` class directly. This is useful when you know the target chip in advance. In this scenario ``esp.connect()`` is required to establish a connection with the device.
- Multiple operations can be chained together in a single context manager block.

------------

The Public API implements a custom ``ImageSource`` input type, which expands to ``str | bytes | IO[bytes]`` - a path to the firmware image file, an opened file-like object, or the image data as bytes.

As output, the API returns a ``bytes`` object representing the binary image or writes the image to a file if the ``output`` parameter is provided.

The following example converts an ELF file to a flashable binary, prints the image information, and flashes the image. The example demonstrates three different ways to achieve the same result, showcasing the flexibility of the API:

.. code-block:: python

    ELF = "firmware.elf"

    # var 1 - Loading ELF from a file, not writing binary to a file
    bin_file = elf2image(ELF, "esp32c3")
    image_info(bin_file)
    with detect_chip(PORT) as esp:
        attach_flash(esp)
        write_flash(esp, [(0, bin_file)])

    # var 2 - Loading ELF from an opened file object, not writing binary to a file
    with open(ELF, "rb") as elf_file, detect_chip(PORT) as esp:
        bin_file = elf2image(elf_file, "esp32c3")
        image_info(bin_file)
        attach_flash(esp)
        write_flash(esp, [(0, bin_file)])

    # var 3 - Loading ELF from a file, writing binary to a file
    elf2image(ELF, "esp32c3", "image.bin")
    image_info("image.bin")
    with detect_chip(PORT) as esp:
        attach_flash(esp)
        write_flash(esp, [(0, "image.bin")])


------------

**The following section provides a detailed reference for the public API functions.**

Chip Control Operations
"""""""""""""""""""""""

.. autofunction:: esptool.cmds.detect_chip

.. autofunction:: esptool.cmds.run_stub

.. autofunction:: esptool.cmds.load_ram

.. autofunction:: esptool.cmds.run

.. autofunction:: esptool.cmds.reset_chip

------------

Chip Information Operations
"""""""""""""""""""""""""""

.. autofunction:: esptool.cmds.chip_id

.. autofunction:: esptool.cmds.get_security_info

.. autofunction:: esptool.cmds.read_mac

------------

Flash Memory Manipulation Operations
""""""""""""""""""""""""""""""""""""

.. autofunction:: esptool.cmds.attach_flash

.. autofunction:: esptool.cmds.flash_id

.. autofunction:: esptool.cmds.read_flash

.. autofunction:: esptool.cmds.write_flash

.. autofunction:: esptool.cmds.erase_flash

.. autofunction:: esptool.cmds.erase_region

.. autofunction:: esptool.cmds.verify_flash

.. autofunction:: esptool.cmds.read_flash_status

.. autofunction:: esptool.cmds.write_flash_status

.. autofunction:: esptool.cmds.read_flash_sfdp

------------

Memory Operations
"""""""""""""""""

.. autofunction:: esptool.cmds.read_mem

.. autofunction:: esptool.cmds.write_mem

.. autofunction:: esptool.cmds.dump_mem

------------

Binary Image Manipulation Operations
""""""""""""""""""""""""""""""""""""

The following commands can run without the need for a connected chip:

.. autofunction:: esptool.cmds.elf2image

.. autofunction:: esptool.cmds.merge_bin

.. autofunction:: esptool.cmds.image_info

------------

Utility Functions
"""""""""""""""""

.. autofunction:: esptool.cmds.version

------------

For more information, refer to the command implementations in `esptool/cmds.py <https://github.com/espressif/esptool/blob/master/esptool/cmds.py>`_.


Low-Level API Reference
^^^^^^^^^^^^^^^^^^^^^^^

.. warning::

    The low-level API provides more control but requires a deeper understanding of the ESP chip, the esptool internals, and the :ref:`serial protocol <serial-protocol>`. It is recommended to use the public API functions for most use cases.

    Also, the low-level internals are not a part of the public API, so they may change in between releases.

    Please submit a :ref:`feature request <feature-requests>` if you are missing something from the officially supported API.

For granular control and more configuration freedom, you can directly access the low-level methods and attributes of the ``ESPLoader`` object and create your own routines. The following is an example of a custom routine to flash the {IDF_TARGET_NAME}:

.. note::

    This example code is a very basic implementation of ``esptool.py -p /dev/ttyACM0 write-flash 0x10000 firmware.bin``

.. code-block:: python

    from esptool.cmds import detect_chip

    # The port of the connected ESP
    PORT = "/dev/ttyACM0"
    # The binary file
    BIN_FILE = "./firmware.bin"
    # Flash offset to flash the binary to
    FLASH_ADDRESS = 0x10000

    def progress_callback(percent):
        print(f"Wrote: {int(percent)}%")

    with detect_chip(PORT) as esp:
        description = esp.get_chip_description()
        features = esp.get_chip_features()
        print(f"Detected ESP on port {PORT}: {description}")
        print("Features:", ", ".join(features))

        esp = esp.run_stub()
        with open(BIN_FILE, 'rb') as binary:
            # Load the binary
            binary_data = binary.read()
            total_size = len(binary_data)
            print(f"Binary size: {total_size} bytes")

            # Write binary blocks
            esp.flash_begin(total_size, FLASH_ADDRESS)
            for i in range(0, total_size, esp.FLASH_WRITE_SIZE):
                block = binary_data[i:i + esp.FLASH_WRITE_SIZE]
                # Pad the last block
                block = block + bytes([0xFF]) * (esp.FLASH_WRITE_SIZE - len(block))
                esp.flash_block(block, i + FLASH_ADDRESS)
                progress_callback(i / total_size * 100)
            esp.flash_finish()

            # Reset the chip out of bootloader mode
            esp.hard_reset()

------------

For more information, refer to the methods of the ``ESPLoader`` class  in `esptool/loader.py <https://github.com/espressif/esptool/blob/master/esptool/loader.py>`_.

.. _logging:

Redirecting Output with a Custom Logger
---------------------------------------

Esptool allows redirecting output by implementing a custom logger class. This can be useful when integrating esptool with graphical user interfaces or other systems where the default console output is not appropriate. Below is an example demonstrating how to create and use a custom logger:

.. code-block:: python

    from esptool.logger import log, TemplateLogger
    import sys

    class CustomLogger(TemplateLogger):
        log_to_file = True
        log_file = "esptool.log"

        def print(self, message="", *args, **kwargs):
            # Print to console
            print(f"[CustomLogger]: {message}", *args, **kwargs)
            # Optionally log to a file
            if self.log_to_file:
                with open(self.log_file, "a") as log:
                    log.write(f"{message}\n")

        def note(self, message):
            self.print(f"NOTE: {message}")

        def warning(self, message):
            self.print(f"WARNING: {message}")

        def error(self, message):
            self.print(message, file=sys.stderr)

        def stage(self, finish=False):
            # Collapsible stages not needed in this example
            pass

        def progress_bar(
            self,
            cur_iter,
            total_iters,
            prefix = "",
            suffix = "",
            bar_length: int = 30,
        ):
            # Progress bars replaced with simple percentage output in this example
            percent = f"{100 * (cur_iter / float(total_iters)):.1f}"
            self.print(f"Finished: {percent}%")

        def set_verbosity(self, verbosity):
            # Set verbosity level not needed in this example
            pass

    # Replace the default logger with the custom logger
    log.set_logger(CustomLogger())

    # From now on, all esptool output will be redirected through the custom logger
    # Your code here ...

In this example, the ``CustomLogger`` class provides additional functionality such as logging messages to a file, which the original ``EsptoolLogger`` (imported from ``esptool.logger`` as an initiated object ``log``) doesn't. The ``EsptoolLogger.set_logger()`` method is used to replace the default logger with the custom logger.

To ensure compatibility with esptool, the custom logger should re-implement (or inherit) the following methods from the original ``EsptoolLogger`` class (see the reference implementation `here <https://github.com/espressif/esptool/blob/master/esptool/logger.py>`__), this is enforced by the ``TemplateLogger`` abstract class:

- ``print``: Handles plain message logging.
- ``note``: Logs informational messages.
- ``warning``: Logs warning messages.
- ``error``: Logs error messages.
- ``stage``: Starts or ends a collapsible output stage.
- ``progress_bar``: Displays a progress bar.
- ``set_verbosity``: Sets the verbosity level for logging.

.. autoclass:: esptool.logger.EsptoolLogger
   :members: print, note, warning, error, stage, progress_bar, set_verbosity
   :member-order: bysource

These methods are essential for maintaining proper integration and behavior with esptool. Additionally, all output printing should be made using ``log.print()`` (or the respective method, such as ``log.info()`` or ``log.warning()``) instead of the standard ``print()`` function to ensure the output is routed through the custom logger. This ensures consistency and allows the custom logger to handle all output appropriately. You can further customize this logger to fit your application's needs, such as integrating with GUI components or advanced logging frameworks.
