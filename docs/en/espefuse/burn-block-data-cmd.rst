.. _burn-block-data-cmd:

Burn Block Data
===============

The ``espefuse.py burn_block_data`` command allows writing arbitrary data (non-key data) from a file into an eFuse block, for software use.

This command is available in ``espefuse.py`` v2.6 and newer.

Positional arguments:

* ``Name of key block``
* ``Datafile``. File containing data to burn into the eFuse block. The file size can be smaller than the eFuse block size.

It can be list of blocks and datafiles (like BLOCK1 datafile1.bin BLOCK2 datafile2.bin etc.).

Optional arguments:

* ``--force-write-always``. Write the eFuse key even if it looks like it is already been written, or is write protected. Note that this option can't disable write protection, or clear any bit which has already been set.
* ``--offset``. Byte offset in the eFuse block.

**Example:** Write to eFuse BLOCK3 from binary file ``device_id.bin``, starting at eFuse byte offset 6:

.. code-block:: none

    > espefuse.py -p PORT burn_block_data --offset 6 BLOCK3 device_id.bin

    === Run "burn_block_data" command ===
    [03] BLOCK3               size=32 bytes, offset=06 - > [00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 00 00 00 00 00 00 00 00 00].

    Check all blocks for burn...
    idx, BLOCK_NAME,          Conclusion
    [03] BLOCK3               is empty, will burn the new value
    .
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.
    BURN
    BURN BLOCK3  - OK (write block == read block)
    Reading updated efuses...
    Successful

Peculiarities
-------------

1. Data is written to the eFuse block in normal byte order (treating the eFuse block as if it was an array of bytes). It can be read back in firmware using eFuse API or from the eFuse read registers (but these reads must be always be complete register words, 4-byte aligned).

.. code-block:: none

    > espefuse.py dump
    ...
    BLOCK3          (                ) [3 ] read_regs: 00000000 01000000 05040302 09080706 0d0c0b0a 00000f0e 00000000 00000000

    > espefuse.py summary
    ....
    BLOCK3 (BLOCK3):                                   Variable Block 3
    = 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 00 00 00 00 00 00 00 00 00 R/W

2. Part of the eFuse block can be written at a time. The ``--offset`` argument allows writing to a byte offset inside the eFuse block itself.
3. This command is not suitable for writing key data which will be used by flash encryption or secure boot hardware, use ``burn_key`` for this.
