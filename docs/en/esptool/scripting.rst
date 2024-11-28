.. _scripting:

Embedding into Custom Scripts
-----------------------------

``esptool.py``, ``espefuse.py``, and ``espsecure.py`` can easily be integrated into Python applications or called from other Python scripts.

While it currently does have a poor Python API, something which `#208 <https://github.com/espressif/esptool/issues/208>`_ will address, it allows for passing CLI arguments to ``esptool.main()``. This workaround makes integration very straightforward as you can pass exactly the same arguments as you would on the CLI:

.. code-block:: python

    command = ['--baud', '460800', 'read_flash', '0', '0x200000', 'flash_contents.bin']
    print('Using command %s' % ' '.join(command))
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
