.. _burn-custom-mac-cmd:

Burn Custom Mac
===============

The ``espefuse.py burn-custom-mac`` command burns a 48-bit Custom MAC Address.

Positional arguments:

* ``MAC``. Custom MAC Address (``CUSTOM_MAC``) to burn given in hexadecimal format with bytes separated by colons (e.g. AA:CD:EF:01:02:03)

Optional arguments:

* ``--force-write-always``. Write the eFuse key even if it looks like it is already been written, or is write protected. Note that this option can't disable write protection, or clear any bit which has already been set.

If ``CUSTOM_MAC`` is placed in an eFuse block with a coding scheme and already has data then it is not possible to write new data without breaking the encoding. The correct way is to contact Espressif to order chips with ``CUSTOM_MAC`` pre-burned from the factory. Another way is, it is not recommended, to use the ``--force-write-always`` flag to ignore the encoding violation.

.. only:: esp32

    This command burns a few eFuse fields:

    1. ``CUSTOM_MAC``
    2. ``MAC_VERSION`` = 1
    3. ``CUSTOM_MAC_CRC`` = crc8(``CUSTOM_MAC``)

    .. code-block:: none

        > espefuse.py burn-custom-mac 48:63:92:15:72:16

        === Run "burn-custom-mac" command ===
            - 'MAC_VERSION' (Version of the MAC field) 0x00 -> 0x1
            - 'CUSTOM_MAC' (Custom MAC) 0x000000000000 -> 0x167215926348
            - 'CUSTOM_MAC_CRC' (CRC of custom MAC) 0x00 -> 0x75

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [03] BLOCK3               is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK3  - OK (write block == read block)
        Reading updated efuses...
        Custom MAC Address version 1: 48:63:92:15:72:16 (CRC 0x75 OK)
        Successful

        > espefuse.py summary
        ...
        MAC_VERSION (BLOCK3):                              Version of the MAC field                           = Custom MAC in BLOCK3 R/W (0x01)
        CUSTOM_MAC (BLOCK3):                               Custom MAC
        = 48:63:92:15:72:16 (CRC 0x75 OK) R/W
        CUSTOM_MAC_CRC (BLOCK3):                           CRC of custom MAC                                  = 117 R/W (0x75)
        ...
        BLOCK3 (BLOCK3):                                   Variable Block 3
        = 75 48 63 92 15 72 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 R/W

.. only:: esp32c2

    This command burns a few eFuse fields:

    1. ``CUSTOM_MAC``
    2. ``CUSTOM_MAC_USED`` = 1

    .. code-block:: none

        > espefuse.py burn-custom-mac 48:63:92:15:72:16

        === Run "burn-custom-mac" command ===
            - 'CUSTOM_MAC' (Custom MAC addr) 0x000000000000 -> 0x167215926348

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is not empty
                (written ): 0x0000000000000080
                (to write): 0x0400000000000000
                (coding scheme = NONE)
        [01] BLOCK1               is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK1  - OK (write block == read block)
        BURN BLOCK0  - OK (all write block bits are set)
        Reading updated efuses...
        Custom MAC Address: 48:63:92:15:72:16 (OK)
        Successful

        > espefuse.py summary
        ...
        CUSTOM_MAC_USED (BLOCK0)                           Enable CUSTOM_MAC programming                      = True R/W (0b1)
        CUSTOM_MAC (BLOCK1)                                Custom MAC addr
        = 48:63:92:15:72:16 (OK) R/W

.. only:: esp32c3 or esp32s2 or esp32s3

    This command burns a given MAC to ``CUSTOM_MAC`` field.

    .. code-block:: none

        > espefuse.py burn-custom-mac 48:63:92:15:72:16

        === Run "burn-custom-mac" command ===
            - 'CUSTOM_MAC' (Custom MAC Address) 0x000000000000 -> 0x167215926348

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [03] BLOCK_USR_DATA       is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK3  - OK (write block == read block)
        Reading updated efuses...
        Custom MAC Address: 48:63:92:15:72:16 (OK)
        Successful

        > espefuse.py summary
        ...
        CUSTOM_MAC (BLOCK3)                                Custom MAC Address
        = 48:63:92:15:72:16 (OK) R/W
