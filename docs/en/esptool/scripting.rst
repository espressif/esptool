.. _scripting:

Embedding into Custom Scripts
=============================

``esptool.py``, ``espefuse.py``, and ``espsecure.py`` can easily be integrated into Python applications or called from other Python scripts.

While it currently does have a poor Python API, something which `#208 <https://github.com/espressif/esptool/issues/208>`_ will address, it allows for passing CLI arguments to ``esptool.main()``. This workaround makes integration very straightforward as you can pass exactly the same arguments as you would on the CLI:

.. code-block:: python

    import esptool

    command = ['--baud', '460800', 'read_flash', '0', '0x200000', 'flash_contents.bin']
    print("Using command ", " ".join(command))
    esptool.main(command)


Using Esptool as a Python Module
--------------------------------

The following is an example on how to use esptool as a Python module and leverage its Python API to flash the {IDF_TARGET_NAME}:

.. note::

    This example code functionally equivalent to ``esptool.py -p /dev/ttyACM0 write_flash 0x10000 firmware.bin``


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
        print(f"Features: {", ".join(features)}")

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
                progress_callback(float(i + len(block)) / total_size * 100)
            esp.flash_finish()

            # Reset the chip out of bootloader mode
            esp.hard_reset()


.. _logging:

Redirecting Output with a Custom Logger
---------------------------------------

Esptool allows redirecting output by implementing a custom logger class. This can be useful when integrating esptool with graphical user interfaces or other systems where the default console output is not appropriate. Below is an example demonstrating how to create and use a custom logger:

.. code-block:: python

    from esptool.logger import log, TemplateLogger

    class CustomLogger(TemplateLogger):
        log_to_file = True
        log_file = "esptool.log"

        def print(self, message, *args, **kwargs):
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

        def print_overwrite(self, message):
            # Overwriting not needed, print normally
            self.print(message)

        def set_progress(self, percentage):
            # Progress updates not needed, pass
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
- ``print_overwrite``: Handles message overwriting (can be a simple ``print()`` if overwriting is not needed).
- ``set_progress``: Handles percentage updates of long-running operations - ``write_flash``, ``read_flash``, and ``dump_mem`` (useful for GUI visualisation, e.g. as a progress bar).

These methods are essential for maintaining proper integration and behavior with esptool. Additionally, all calls to the logger should be made using ``log.print()`` (or the respective method, such as ``log.info()`` or ``log.warning()``) instead of the standard ``print()`` function to ensure the output is routed through the custom logger. This ensures consistency and allows the custom logger to handle all output appropriately. You can further customize this logger to fit your application's needs, such as integrating with GUI components or advanced logging frameworks.
