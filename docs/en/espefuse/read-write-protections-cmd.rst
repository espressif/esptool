.. _read-write-protections-cmd:

Read Write Protection
=====================

There are two commands (to get the correct list of eFuse fields that can be protected, specify the chip with ``--chip``):

- ``espefuse.py read-protect-efuse``. It sets read protection for given eFuse names.
- ``espefuse.py write-protect-efuse``. It sets write protection for given eFuse names.

Positional arguments:

- eFuse name. It can receive a list of eFuse names (like EFUSE_NAME1 EFUSE_NAME2 etc.).

Read protection prevents software from reading eFuse fields, only hardware can access such eFuses. Such eFuses are read as zero and the data is marked as ``??`` in this tool.

Write protection prevents further changes of eFuse fields.

Not all eFuses have read and write protections. See the help for these commands for the eFuse names that can be protected.

eFuses are often read/write protected as a group, so protecting one of eFuse will result in some related eFuses becoming protected. The tool will show the full list of eFuses that will be protected.

Read and Write Protection Status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``R/W`` output indicates a protection status of a specific eFuse field/block:

- ``-/W`` indicates that read protection is set. Value of such eFuse field will always show all-zeroes, even though hardware may use the correct value. In espefuse v2.6 and newer, read-protected eFuse values are displayed as question marks (``??``). On earlier versions, they are displayed as zeroes.

    .. code-block:: none

        BLOCK1 (BLOCK1):
        = ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/W

- ``R/-`` indicates that write protection is set. No further bits can be set.
- ``-/-`` means both read and write protection are set.

Usage
-----

.. code-block:: none

    > espefuse.py read-protect-efuse BLOCK2 BLOCK3 MAC_VERSION

    === Run "read-protect-efuse" command ===
    If Secure Boot V2 is used, BLOCK2 must be readable, please stop this operation!
    Permanently read-disabling efuse BLOCK2
    Permanently read-disabling efuses MAC_VERSION, BLOCK3
    Permanently read-disabling efuses MAC_VERSION, BLOCK3

    Check all blocks for burn...
    idx, BLOCK_NAME,          Conclusion
    [00] BLOCK0               is empty, will burn the new value
    .
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.
    BURN
    BURN BLOCK0  - OK (write block == read block)
    Reading updated efuses...
    Checking efuses...
    Successful

.. code-block:: none

    > espefuse.py write-protect-efuse WR_DIS FLASH_CRYPT_CNT

    === Run "write-protect-efuse" command ===
    Permanently write-disabling efuse WR_DIS
    Permanently write-disabling efuses FLASH_CRYPT_CNT, UART_DOWNLOAD_DIS

    Check all blocks for burn...
    idx, BLOCK_NAME,          Conclusion
    [00] BLOCK0               is empty, will burn the new value
    .
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.
    BURN
    BURN BLOCK0  - OK (write block == read block)
    Reading updated efuses...
    Checking efuses...
    Successful
