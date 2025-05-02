.. _espefuse-scripting:

Embedding into Custom Scripts
=============================

Similar to :ref:`esptool.py <scripting>`, ``espefuse.py`` can be easily integrated into Python applications or called from other Python scripts.

For details on redirecting the output, see :ref:`esptool.py logging section <logging>`.

Using Espefuse as a Python Module
---------------------------------

The espefuse module provides a comprehensive Python API for interacting with ESP32 chips programmatically. By leveraging the API, developers can automate tasks such as reading and writing eFuse values, managing secure boot, and more.

The API also provides the benefit of being able to chain commands with ``esptool.py`` commands and create a custom script. With this approach, you can e.g. flash firmware and set eFuse values in one go.

Using the Command-Line Interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The most straightforward and basic integration option is to pass arguments to ``espefuse.main()``. This workaround allows you to pass exactly the same arguments as you would on the CLI:

.. code-block:: python

    import espefuse

    command = ["--port", "/dev/ttyACM0", "summary"]
    print("Using command ", " ".join(command))
    espefuse.main(command)


Public API Reference
^^^^^^^^^^^^^^^^^^^^

Basic Workflow:

1. **Detect and Connect**: Connect to the chip and load the available eFuse commands for the given chip.
2. **Execute Commands**: Execute the commands you need, e.g. read the current eFuse values.
3. **Reset and Cleanup**: Reset the chip if needed. Context manager will take care of closing the port.

This example demonstrates a basic workflow using the espefuse API to read the current eFuse values:

.. code-block:: python

    from espefuse import init_commands

    PORT = "/dev/ttyACM0"

    # Autodetect and connect to the chip and load the eFuse commands for the given chip
    with init_commands(port=PORT) as espefuse:
        espefuse.summary()  # Print the current eFuse values

        # Get the value of single eFuse
        custom_mac = espefuse.efuses["CUSTOM_MAC"].get()
        print(f"CUSTOM_MAC: {custom_mac}")

.. note::

    It is also possible to operate in virtual mode, which allows to read and write eFuse values without connecting to the chip for testing purposes.
    For more information, refer to :func:`init_commands <espefuse.efuse_interface.init_commands>` docstring or take a look at tests in :file:`test/test_espefuse.py`.

------------

This API can be also used to chain commands with esptool.py commands.

.. code-block:: python

    from espefuse import init_commands
    from esptool import attach_flash, flash_id, reset_chip

    PORT = "/dev/ttyACM0"

    with init_commands(port=PORT) as espefuse:
        espefuse.summary()  # Get the current eFuse values
        # Esptool commands
        attach_flash(espefuse.esp)  # Attach the flash memory chip, required for flash operations
        flash_id(espefuse.esp)  # Get the flash information
        reset_chip(espefuse.esp, "hard-reset")  # Reset the chip

------------

If you would like to have a better control over the ESP object from esptool, you can first get the ESP object from esptool as described in :ref:`esptool.py <scripting>` and then pass it to the espefuse API.

.. code-block:: python

    from espefuse import init_commands
    from esptool import detect_chip, run_stub, attach_flash, flash_id, reset_chip

    PORT = "/dev/ttyACM0"

    # Get the ESP object from esptool
    with detect_chip(PORT) as esp:
        # Prepare the ESP object; run stub and attach flash
        esp = run_stub(esp)
        attach_flash(esp)

        # Pass the ESP object to the espefuse API
        with init_commands(esp=esp) as espefuse:
            espefuse.summary()  # Get the current eFuse values
            # External ESP object was passed, so port won't be closed here

        # Here you can continue with esptool commands if needed
        flash_id(esp)  # Get the flash information

        reset_chip(esp, "hard-reset")  # Reset the chip

------------

Batch Mode
^^^^^^^^^^

For burning eFuses, it is possible to use batch mode. This allows to queue multiple eFuse operations and execute them all at once.
Please note that nesting batch mode is also supported.

Batch mode is enabled by passing the ``batch_mode=True`` argument to the function :func:`init_commands <espefuse.init_commands>`.
Or can be enabled later by calling the :func:`use_batch_mode <espefuse.BaseCommands.use_batch_mode>` method.

The :func:`burn_all <espefuse.BaseCommands.burn_all>` method will execute all queued eFuse operations and decrement the batch mode counter.

Here is an example of how to use a batch mode on ESP32:

.. code-block:: python

    from espefuse import init_commands

    PORT = "/dev/ttyACM0"

    # Connect to chip and enable batch mode
    with init_commands(port=PORT, batch_mode=True) as espefuse:
        # Queue multiple eFuse operations
        with open("flash_encryption_key.bin", "rb") as f:
            espefuse.burn_key(["flash_encryption"], [f], no_protect_key=True)
        espefuse.burn_efuse({"FLASH_CRYPT_CNT": 0x7})
        espefuse.burn_efuse({"DISABLE_DL_ENCRYPT": 1})
        espefuse.burn_efuse({"JTAG_DISABLE": 1})

        # Execute all queued eFuse operations
        espefuse.burn_all()

        # Check that all eFuses are set properly
        espefuse.summary()

        # Checks written eFuses
        if espefuse.efuses["FLASH_CRYPT_CNT"].get() != 0x7:
            raise esptool.FatalError("FLASH_CRYPT_CNT was not set")
        if espefuse.efuses["DISABLE_DL_ENCRYPT"].get() != 1:
            raise esptool.FatalError("DISABLE_DL_ENCRYPT was not set")
        if espefuse.efuses["JTAG_DISABLE"].is_readable() or espefuse.efuses["JTAG_DISABLE"].is_writeable():
            raise esptool.FatalError("JTAG_DISABLE should be read and write protected")

.. note::

    Please note that provided example is written for ESP32. For other chips, the names of eFuses might be different and signature of the :func:`burn_key <espefuse.BaseCommands.burn_key>` function might also be different.

After ``espefuse.burn_all()``, all needed eFuses will be burnt to chip in order ``BLK_MAX`` to ``BLK_0``. This order prevents cases when protection is set before the value goes to a block. Please note this while developing your scripts.
Upon completion, the new eFuses will be read back, and checks will be performed on the written eFuses by ``espefuse.py``. In production, you might need to check that all written eFuses are set properly.
In the example above, we check that ``FLASH_CRYPT_CNT`` and ``DISABLE_DL_ENCRYPT`` are set properly. Also, we check that ``JTAG_DISABLE`` is read and write protected.

------------

**The following section provides a detailed reference for the public API functions.**

Init Commands
^^^^^^^^^^^^^

.. autofunction:: espefuse.init_commands

.. autofunction:: espefuse.get_esp

------------

Batch Mode Helpers
^^^^^^^^^^^^^^^^^^

.. autofunction:: espefuse.BaseCommands.use_batch_mode

.. autofunction:: espefuse.BaseCommands.burn_all

------------

Common Read Commands
^^^^^^^^^^^^^^^^^^^^

.. autofunction:: espefuse.BaseCommands.summary

.. autofunction:: espefuse.BaseCommands.dump

.. autofunction:: espefuse.BaseCommands.get_custom_mac

.. autofunction:: espefuse.BaseCommands.adc_info

.. autofunction:: espefuse.BaseCommands.check_error

------------

Common Write Commands
^^^^^^^^^^^^^^^^^^^^^

.. autofunction:: espefuse.BaseCommands.burn_efuse

.. autofunction:: espefuse.BaseCommands.read_protect_efuse

.. autofunction:: espefuse.BaseCommands.write_protect_efuse

.. autofunction:: espefuse.BaseCommands.burn_block_data

.. autofunction:: espefuse.BaseCommands.burn_bit

.. autofunction:: espefuse.BaseCommands.burn_custom_mac

.. autofunction:: espefuse.BaseCommands.set_flash_voltage

------------

Chip-Specific Commands
^^^^^^^^^^^^^^^^^^^^^^

.. autofunction:: espefuse.efuse.{IDF_TARGET_PATH_NAME}.commands.burn_key

.. autofunction:: espefuse.efuse.{IDF_TARGET_PATH_NAME}.commands.burn_key_digest


eFuse Operations
^^^^^^^^^^^^^^^^

.. autofunction:: espefuse.efuse.base_fields.EfuseFieldBase.get

.. autofunction:: espefuse.efuse.base_fields.EfuseFieldBase.is_readable

.. autofunction:: espefuse.efuse.base_fields.EfuseFieldBase.is_writeable

.. autofunction:: espefuse.efuse.base_fields.EfuseFieldBase.get_meaning
