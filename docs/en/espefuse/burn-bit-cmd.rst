.. _burn-bit-cmd:

Burn Bit
========

The ``espefuse.py burn_bit`` command burns bits in eFuse blocks by bit number. This is useful when the fields are not represented in the eFuse table.

Positional arguments:

- ``block`` - eFuse block.
- ``bit number`` - Bit number in the eFuse block [0..BLK_LEN-1] (list of numbers, like 10 15 18 17 5 etc.).

Optional arguments:

- ``--force-write-always``. Burn it even if it looks like it is already been written, or is write protected. Note that this option can not disable write protection, or clear any bit which has already been set.

Usage
-----

Burning bits to BLOCK2:

.. code-block:: none

    > espefuse.py burn_bit BLOCK2 15 16 17 18 19 20

    === Run "burn_bit" command ===
    bit_number:   [255]........................................................[0]
    BLOCK2    : 0x00000000000000000000000000000000000000000000000000000000001f8000
    BLOCK2          (secure_boot_v1 s) [2 ] regs_to_write: 001f8000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

    Check all blocks for burn...
    idx, BLOCK_NAME,          Conclusion
    [02] BLOCK2               is empty, will burn the new value
    .
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.
    BURN
    BURN BLOCK2  - OK (write block == read block)
    Reading updated efuses...
    Successful

Burning in Multiple Blocks
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    > espefuse.py --virt burn_bit BLOCK2 15 16 17 18 19 20 \
                         burn_bit BLOCK3 15 16 17 18 19 20

    === Run "burn_bit" command ===
    bit_number:   [255]........................................................[0]
    BLOCK2    : 0x00000000000000000000000000000000000000000000000000000000001f8000
    BLOCK2          (secure_boot_v1 s) [2 ] regs_to_write: 001f8000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

    Batch mode is enabled, the burn will be done at the end of the command.

    === Run "burn_bit" command ===
    bit_number:   [255]........................................................[0]
    BLOCK3    : 0x00000000000000000000000000000000000000000000000000000000001f8000
    BLOCK3          (                ) [3 ] regs_to_write: 001f8000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

    Batch mode is enabled, the burn will be done at the end of the command.

    Check all blocks for burn...
    idx, BLOCK_NAME,          Conclusion
    [02] BLOCK2               is empty, will burn the new value
    [03] BLOCK3               is empty, will burn the new value
    .
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.
    BURN
    BURN BLOCK3  - OK (write block == read block)
    BURN BLOCK2  - OK (write block == read block)
    Reading updated efuses...
