.. _espefuse:

espefuse.py
===========

``espefuse.py`` is a tool for communicating with Espressif chips for the purpose of reading/writing ("burning") the one-time-programmable eFuses. Burning occurs only in one direction from 0 to 1 (never cleared 1->0).

.. warning::

    Because eFuse is one-time-programmable, it is possible to permanently damage or "brick" your {IDF_TARGET_NAME} using this tool. Use it with great care.

For more details about Espressif chips eFuse features, see the `Technical Reference Manual <https://www.espressif.com/en/support/documents/technical-documents>`__.

``espefuse.py`` is installed alongside ``esptool.py``, so if ``esptool.py`` (v2.0 or newer) is available on the PATH then ``espefuse.py`` should be as well.

Initial State of Efuses
-----------------------

On relatively new chip, most eFuses are unburned (value 0). Some eFuses are already burned at the factory stage:

- MAC (Factory MAC Address).
- ADC calibration
- Chip package and revision.
- etc.

Supported Commands
------------------

.. toctree::
   :maxdepth: 1

   dump <dump-cmd>
   summary <summary-cmd>
   burn_efuse <burn-efuse-cmd>
   burn_block_data <burn-block-data-cmd>
   burn_bit <burn-bit-cmd>
   read_protect_efuse and write_protect_efuse <read-write-protections-cmd>
   burn_key <burn-key-cmd>
   burn_key_digest <burn-key-digest-cmd>
   burn_custom_mac <burn-custom-mac-cmd>
   get_custom_mac <get-custom-mac-cmd>
   adc_info <adc-info-cmd>
   set_flash_voltage <set-flash-voltage-cmd>
   execute_scripts <execute-scripts-cmd>
   check_error <check-error-cmd>

Optional General Arguments Of Commands
--------------------------------------

- ``-h``, ``--help`` - Show help message and exit. Use ``-h`` to see a summary of all available commands and command line options. To see all options for a particular chip and command, add ``-c {IDF_TARGET_NAME}`` and ``-h`` to the command name, i.e. ``espefuse.py -c {IDF_TARGET_NAME} burn_key -h``.
- ``--chip``, ``-c`` - Target chip type. If this argument is omitted, the tool automatically detects the chip type when connected. But if the command has a help option, the chip is not connected, and the default chip is ``esp32``, please specify the specific type of chip to get the correct help. Example of usage: ``-c esp32``, ``-c esp32c3``, ``-c esp32s2`` and others.
- ``--baud``, ``-b`` - Serial port baud rate, the same as for esptool.
- ``--port``, ``-p`` - Serial port device, ``-p /dev/ttyUSB0`` (Linux and macOS) or ``-p COM1`` (Windows).
- ``--before`` -  What to do before connecting to the chip: ``default_reset``, ``no_reset``, ``esp32r1``, ``no_reset_no_sync``.
- ``--debug``, ``-d`` - Show debugging information.
- ``--virt`` - For host tests. The tool will work in the virtual mode (without connecting to a chip).
- ``--path-efuse-file`` - For host tests. Use it together with ``--virt`` option. The tool will work in the virtual mode (without connecting to a chip) and save eFuse memory to a given file. If the file does not exists the tool creates it. To reset written eFuses just delete the file. Usage: ``--path-efuse-file efuse_memory.bin``.
- ``--do-not-confirm`` - Do not pause for confirmation before permanently writing eFuses. Use with caution. If this option is not used, a manual confirmation step is required, you need to enter the word ``BURN`` to continue burning.

Virtual mode
^^^^^^^^^^^^

This mode is enabled with the ``--virt`` flag (need to specify chip with ``--chip``). This helps to test commands without physical access to the chip. Burned data is not saved between commands. Using ``--path-efuse-file``, you can save the written data to a file. Delete the file to clear eFuses.

Confirmation
^^^^^^^^^^^^

Each burn operation requires manual confirmation, you need to type the word ``BURN`` to continue burning. Using the ``--do-not-confirm`` option allows to skip it.

Coding Scheme
-------------

The coding scheme helps the eFuse controller to detect an error of the eFuse blocks. There are special registers that indicate that there is an error in the block.

{IDF_TARGET_NAME} supports the following coding schemes:

.. only:: esp32
    
    * ``None`` no need any special encoding data. BLOCK0.
    * ``3/4``, requires encoding data. The BLOCK length is reduced from 256 bits to 192 bits.
    * ``Repeat`` not supported by this tool and IDF. The BLOCK length is reduced from 256 bits to 128 bits.

    BLOCK1-3 can have any of this coding scheme. It depends on the ``CODING_SCHEME`` eFuse.

.. only:: not esp32
    
    * ``None`` no need any special encoding data, but internally it copies data four times. BLOCK0.
    * ``RS`` (Reed-Solomon), it uses 6 bytes of automatic error correction.

   Rest eFuse blocks from BLOCK1 to BLOCK(max) have ``RS`` coding scheme.

This tool automatically adds encoding data to the burning data if it requires. Encoded data is calculated individually for each block.

All coding schemes (except ``None``) require additional encoding data to be provided at write time. Due to the encoding data, such blocks cannot be overwritten again without breaking the block's coding scheme. Use the :ref:`perform-multiple-operations` feature or list multiple eFuses/keys.

Burning Efuse
-------------

Burning occurs in order from BLOCK(max) to BLOCK0. This prevents read/write protection from being set before the data is set. After burning, the tool reads the written data back and compares the original data, and additionally checks the status of the coding scheme, if there are any errors, it re-burns the data again to correct it.

.. _perform-multiple-operations:

Perform Multiple Operations In A Single Espefuse Run
----------------------------------------------------

Some eFuse blocks have an encoding scheme (Reed-Solomon or 3/4) that requires encoded data, making these blocks only writable once. If you need to write multiple keys/eFuses to one block using different commands, you can use this feature - multiple commands. This feature burns given data once at the end of all commands. All commands supported by version v3.2 or later are supported to be chained together.

The example below shows how to use the two commands ``burn_key_digest`` and ``burn_key`` to write the Secure Boot key and Flash Encryption key into one BLOCK3 for the ``ESP32-C2`` chip. Using these commands individually will result in only one key being written correctly.

.. code-block:: none

    > espefuse.py -c esp32c2  \
                            burn_key_digest secure_images/ecdsa256_secure_boot_signing_key_v2.pem \
                            burn_key BLOCK_KEY0 images/efuse/128bit_key.bin XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS

Recommendations
---------------

1. The `Technical Reference Manual <https://www.espressif.com/en/support/documents/technical-documents>`__ has a recommendation for reducing the number of burn operations as much as possible. The tool supports several ways to do this:

    - Combine multiple commands into one with this :ref:`perform-multiple-operations` feature.
    - Most commands support getting a list of arguments (eFuse names, keys).

3. Make sure the power supply is stable because this may cause burning problems.
