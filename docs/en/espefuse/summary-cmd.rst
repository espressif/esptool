.. _summary-cmd:

Summary
=======

The ``espefuse.py summary`` command reads the eFuses from the chip and outputs them in text or json format. It is also possible to save it to a file. The command also supports eFuse filtering by name.

Optional arguments:

- ``--format`` - Select the summary format:
    - ``summary`` - text format (default option).
    - ``json`` - json format. Usage ``--format json``.
    - ``value_only`` - only the value of the eFuse specified as an argument will be displayed. For more information, refer to the :ref:`Filtering eFuses <filtering-eFuses>` section.
- ``--file`` - File to save the efuse summary. Usage ``--file efuses.json``.
- List of eFuses to filter. For more information, refer to the :ref:`Filtering eFuses <filtering-eFuses>` section.

.. _text-format-summary:

Text Format Summary
-------------------

The text format of summary consists of 3 main columns:

1. This column consists of the eFuse name and additional information: the block name associated with this eFuse field and encoding errors (if any).
2. Description of eFuse field.
3. This column has human readable value, read/write protection status, raw value (hexadecimal or binary).

Read and Write Protection Status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``R/W`` output indicates a protection status of a specific eFuse field/block:

- ``-/W`` indicates that read protection is set. Value of such eFuse field will always show all-zeroes, even though hardware may use the correct value. In espefuse v2.6 and newer, read-protected eFuse values are displayed as question marks (``??``). On earlier versions, they are displayed as zeroes.

    .. code-block:: none

        BLOCK1 (BLOCK1):
        = ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/W

- ``R/-`` indicates that write protection is set. No further bits can be set.
- ``-/-`` means both read and write protection are set.

Some eFuses have no protection at all, and some eFuses have only one read or write protection. There is no mark in the summary to expose it.

Display Efuse Summary
^^^^^^^^^^^^^^^^^^^^^

The eFuse summary may vary from version to version of this tool and differ for different chips. Below is the summary for the {IDF_TARGET_NAME} chip.

For details on the meaning of each eFuse value, refer to the `Technical Reference Manual <http://espressif.com/en/support/download/documents>`__.

.. include:: inc/summary_{IDF_TARGET_NAME}.rst

Json Format Summary
-------------------

The json representation of eFuses for the ESP32 chip is shown below.

Each field includes ``raw_value``: a lowercase hexadecimal string of the fuse bits
with a ``0x`` prefix. The format is the same for every field: non-``bytes`` fields
are padded with leading zero bits to a nibble (4-bit) boundary; ``bytes`` fields
use the same byte order as the ``value`` hex (see the :ref:`text format summary <text-format-summary>`),
as a continuous digit string after the ``0x`` prefix (no spaces).

.. code-block:: none

    > espefuse.py summary --format json

    {
        "ABS_DONE_0": {
            "bit_len": 1,
            "block": 0,
            "category": "security",
            "description": "Secure boot V1 is enabled for bootloader image",
            "efuse_type": "bool",
            "name": "ABS_DONE_0",
            "pos": 4,
            "raw_value": "0x0",
            "readable": true,
            "value": false,
            "word": 6,
            "writeable": true
        },
        "BLOCK1": {
            "bit_len": 256,
            "block": 1,
            "category": "security",
            "description": "Flash encryption key",
            "efuse_type": "bytes:32",
            "name": "BLOCK1",
            "pos": 0,
            "raw_value": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "readable": true,
            "value": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "word": 0,
            "writeable": true
        },
    ...
        "CODING_SCHEME": {
            "bit_len": 2,
            "block": 0,
            "category": "config",
            "description": "Efuse variable block length scheme",
            "efuse_type": "uint:2",
            "name": "CODING_SCHEME",
            "pos": 0,
            "raw_value": "0x0",
            "readable": true,
            "value": "NONE (BLK1-3 len=256 bits)",
            "word": 6,
            "writeable": true
        },
    ....
    }

Save Json Format Summary To File
--------------------------------

.. code-block:: none

    > espefuse.py summary --format json --file efuses.json

    Connecting..........
    Detecting chip type... Unsupported detection protocol, switching and trying again...
    Connecting....
    Detecting chip type... ESP32

    === Run "summary" command ===
    Saving efuse values to efuses.json

.. _filtering-eFuses:

Filtering Efuses and Displaying Only the Value
----------------------------------------------

The ``espefuse.py summary`` command supports filtering eFuses by name. The eFuses to filter needs to be specified as positional arguments. If no eFuses are specified, complete summary will be displayed. Example:

.. code-block:: none

    > espefuse.py summary ABS_DONE_0 BLOCK1

    === Run "summary" command ===
    EFUSE_NAME (Block) Description  = [Meaningful Value] [Readable/Writeable] (Hex Value)
    ----------------------------------------------------------------------------------------
    Security fuses:
    ABS_DONE_0 (BLOCK0)                                Secure boot V1 is enabled for bootloader image     = False R/W (0b0)
    BLOCK1 (BLOCK1)                                    Flash encryption key
    = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W

If ``--format value_only`` is specified, only the value of the eFuse specified as an argument will be displayed. Only one eFuse can be specified as an argument for this format. Example:

.. code-block:: none

    > espefuse.py summary --format value_only MAC

    === Run "summary" command ===
    00:00:00:00:00:00 (CRC 0x00 OK)
