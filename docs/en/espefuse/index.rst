.. _espefuse:

espefuse.py
===========

``espefuse.py`` is a tool for communicating with Espressif chips for the purpose of reading/writing ("burning") the one-time-programmable eFuses. Burning occurs only in one direction from 0 to 1 (never cleared 1->0).

.. warning::

    Because eFuse is one-time-programmable, it is possible to permanently damage or "brick" your {IDF_TARGET_NAME} using this tool. Use it with great care.

For more details about Espressif chips eFuse features, see the `{IDF_TARGET_NAME} Technical Reference Manual <{IDF_TARGET_TRM_EN_URL}>`__.

``espefuse.py`` is installed alongside ``esptool.py``, so if ``esptool.py`` (v2.0 or newer) is available on the PATH then ``espefuse.py`` should be as well.

Initial State of eFuses
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
   burn-efuse <burn-efuse-cmd>
   burn-block-data <burn-block-data-cmd>
   burn-bit <burn-bit-cmd>
   read-protect-efuse and write-protect-efuse <read-write-protections-cmd>
   burn-key <burn-key-cmd>
   burn-key-digest <burn-key-digest-cmd>
   burn-custom-mac <burn-custom-mac-cmd>
   get-custom-mac <get-custom-mac-cmd>
   adc-info <adc-info-cmd>
   set-flash-voltage <set-flash-voltage-cmd>
   check-error <check-error-cmd>

Optional General Arguments Of Commands
--------------------------------------

- ``-h``, ``--help`` - Show help message and exit. Use ``-h`` to see a summary of all available commands and command line options. To see all options for a particular chip and command, add ``-c {IDF_TARGET_NAME}`` and ``-h`` to the command name, i.e. ``espefuse.py -c {IDF_TARGET_NAME} burn-key -h``.
- ``--chip``, ``-c`` - Target chip type. If this argument is omitted, the tool automatically detects the chip type when connected. But if the command has a help option, the chip is not connected, and the default chip is ``esp32``, please specify the specific type of chip to get the correct help. Example of usage: ``-c esp32``, ``-c esp32c3``, ``-c esp32s2`` and others.
- ``--baud``, ``-b`` - Serial port baud rate, the same as for esptool.
- ``--port``, ``-p`` - Serial port device, for example: ``-p /dev/ttyUSB0`` (Linux and macOS) or ``-p COM1`` (Windows).
- ``--before`` -  What to do before connecting to the chip: ``default-reset``, ``no-reset``, ``esp32r1``, ``no-reset-no-sync``.
- ``--debug``, ``-d`` - Show debugging information.
- ``--virt`` - For host tests. The tool will work in the virtual mode (without connecting to a chip).
- ``--path-efuse-file`` - For host tests. Use it together with ``--virt`` option. The tool will work in the virtual mode (without connecting to a chip) and save eFuse memory to a given file. If the file does not exists the tool creates it. To reset written eFuses just delete the file. Usage: ``--path-efuse-file efuse_memory.bin``.
- ``--do-not-confirm`` - Do not pause for confirmation before permanently writing eFuses. Use with caution. If this option is not used, a manual confirmation step is required, you need to enter the word ``BURN`` to continue burning.
- ``--extend-efuse-table`` - CSV file from `ESP-IDF <https://docs.espressif.com/projects/esp-idf/>`_ (esp_efuse_custom_table.csv).

Virtual Mode
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

    * ``None`` no need any special encoding data. BLOCK0 is always None.
    * ``3/4``, requires encoding data. The BLOCK length is reduced from 256 bits to 192 bits.
    * ``Repeat`` not supported by this tool and IDF. The BLOCK length is reduced from 256 bits to 128 bits.

    BLOCK1-3 can have any of this coding scheme. It depends on the ``CODING_SCHEME`` eFuse.

.. only:: not esp32

    * ``None`` no need any special encoding data, but internally it copies data four times. BLOCK0.
    * ``RS`` (Reed-Solomon), it uses 6 bytes of automatic error correction.

   Rest eFuse blocks from BLOCK1 to BLOCK(max) have ``RS`` coding scheme.

This tool automatically adds encoding data to the burning data if it requires. Encoded data is calculated individually for each block.

All coding schemes (except ``None``) require additional encoding data to be provided at write time. Due to the encoding data, such blocks cannot be overwritten again without breaking the block's coding scheme. Use the :ref:`perform-multiple-operations` feature or list multiple eFuses/keys.

Burning eFuse
-------------

Burning occurs in order from BLOCK(max) to BLOCK0. This prevents read/write protection from being set before the data is set. After burning, the tool reads the written data back and compares the original data, and additionally checks the status of the coding scheme, if there are any errors, it re-burns the data again to correct it.

.. _perform-multiple-operations:

Perform Multiple Operations In A Single Espefuse Run
----------------------------------------------------

Some eFuse blocks have an encoding scheme (Reed-Solomon or 3/4) that requires encoded data, making these blocks only writable once. If you need to write multiple keys/eFuses to one block using different commands, you can use this feature - multiple commands. This feature burns given data once at the end of all commands. All commands supported by version v3.2 or later are supported to be chained together.

The example below shows how to use the two commands ``burn-key-digest`` and ``burn-key`` to write the Secure Boot key and Flash Encryption key into one BLOCK3 for the ``ESP32-C2`` chip. Using these commands individually will result in only one key being written correctly.

.. code-block:: none

    > espefuse.py -c esp32c2  \
                            burn-key-digest secure_images/ecdsa256_secure_boot_signing_key_v2.pem \
                            burn-key BLOCK_KEY0 images/efuse/128bit_key.bin XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS

Extend eFuse Table
------------------

This tool supports the use of `CSV files <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/efuse.html#description-csv-file>`_ from the `ESP-IDF <https://docs.espressif.com/projects/esp-idf/>`_ (e.g., ``esp_efuse_custom_table.csv``) to add custom eFuse fields. You can use this argument with any supported commands to access these custom eFuses.

.. code-block:: none

    > espefuse.py -c esp32 --extend-efuse-table path/esp_efuse_custom_table.csv summary

Below is an example of an ``esp_efuse_custom_table.csv`` file. This example demonstrates how to define single eFuse fields, ``structured eFuse fields`` and ``non-sequential bit fields``:

.. code-block:: none

    MODULE_VERSION,                EFUSE_BLK3,       56,           8,          Module version
    DEVICE_ROLE,                   EFUSE_BLK3,       64,           3,          Device role
    SETTING_1,                     EFUSE_BLK3,       67,           6,          [SETTING_1_ALT_NAME] Setting 1
    SETTING_2,                     EFUSE_BLK3,       73,           5,          Setting 2
    ID_NUM,                        EFUSE_BLK3,      140,           8,          [MY_ID_NUM] comment
    ,                              EFUSE_BLK3,      132,           8,          [MY_ID_NUM] comment
    ,                              EFUSE_BLK3,      122,           8,          [MY_ID_NUM] comment
    CUSTOM_SECURE_VERSION,         EFUSE_BLK3,       78,          16,          Custom secure version
    ID_NUMK,                       EFUSE_BLK3,      150,           8,          [MY_ID_NUMK] comment
    ,                              EFUSE_BLK3,      182,           8,          [MY_ID_NUMK] comment
    MY_DATA,                       EFUSE_BLK3,      190,          10,          My data
    MY_DATA.FIELD1,                EFUSE_BLK3,      190,           7,          Field1

When you include this CSV file, the tool will generate a new section in the summary called ``User fuses``.

.. code-block:: none

    User fuses:
    MODULE_VERSION (BLOCK3)                            Module version (56-63)                             = 0 R/W (0x00)
    DEVICE_ROLE (BLOCK3)                               Device role (64-66)                                = 0 R/W (0b000)
    SETTING_1 (BLOCK3)                                 [SETTING_1_ALT_NAME] Setting 1 (67-72)             = 0 R/W (0b000000)
    SETTING_2 (BLOCK3)                                 Setting 2 (73-77)                                  = 0 R/W (0b00000)
    ID_NUM_0 (BLOCK3)                                  [MY_ID_NUM] comment (140-147)                      = 0 R/W (0x00)
    ID_NUM_1 (BLOCK3)                                  [MY_ID_NUM] comment (132-139)                      = 0 R/W (0x00)
    ID_NUM_2 (BLOCK3)                                  [MY_ID_NUM] comment (122-129)                      = 0 R/W (0x00)
    CUSTOM_SECURE_VERSION (BLOCK3)                     Custom secure version (78-93)                      = 0 R/W (0x0000)
    ID_NUMK_0 (BLOCK3)                                 [MY_ID_NUMK] comment (150-157)                     = 0 R/W (0x00)
    ID_NUMK_1 (BLOCK3)                                 [MY_ID_NUMK] comment (182-189)                     = 0 R/W (0x00)
    MY_DATA (BLOCK3)                                   My data (190-199)                                  = 0 R/W (0b0000000000)
    MY_DATA_FIELD1 (BLOCK3)                            Field1 (190-196)                                   = 0 R/W (0b0000000)

You can reference these fields using the names and aliases provided in the CSV file. For non-sequential bits, the names are modified slightly with the addition of _0 and _1 postfixes for every sub-field, to ensure safer handling.

For the current example, you can reference the custom fields with the following names: MODULE_VERSION, DEVICE_ROLE, SETTING_1, SETTING_2, ID_NUM_0, ID_NUM_1, ID_NUM_2, CUSTOM_SECURE_VERSION, ID_NUMK_0, ID_NUMK_1, MY_DATA, MY_DATA_FIELD1; and aliases: SETTING_1_ALT_NAME, MY_ID_NUM_0, MY_ID_NUM_1, MY_ID_NUM_2, MY_ID_NUMK_0, MY_ID_NUMK_1.

For convenience, the espefuse summary command includes the used bit range of the field in a comment, such as ``(150-157)`` len = 8 bits.

For more details on the structure and usage of the CSV file, refer to the `eFuse Manager <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/efuse.html#description-csv-file>`_ chapter in the ESP-IDF documentation.

Scripting
---------

Espefuse can be used as a Python library. See :ref:`espefuse.py Scripting <espefuse-scripting>` for more details.

.. toctree::
   :maxdepth: 1
   :hidden:

   scripting

Recommendations
---------------

1. The `{IDF_TARGET_NAME} Technical Reference Manual <{IDF_TARGET_TRM_EN_URL}>`__ has a recommendation for reducing the number of burn operations as much as possible. The tool supports several ways to do this:

    - Combine multiple commands into one with this :ref:`perform-multiple-operations` feature.
    - Most commands support getting a list of arguments (eFuse names, keys).

3. Make sure the power supply is stable because this may cause burning problems.
