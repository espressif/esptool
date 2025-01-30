.. _dump-cmd:

Dump
====

The ``espefuse.py dump`` command allows:

- display raw values of eFuse registers, grouped by block. Output corresponds directly to eFuse register values in the `register space <https://github.com/espressif/esp-idf/blob/master/components/soc/{IDF_TARGET_NAME}/include/soc/efuse_reg.h>`__.
- save dump into files.

Optional arguments:

- ``--format`` - Selects the dump format:
    - ``default`` - Usual console eFuse dump;
    - ``joint`` - All eFuse blocks are stored in one file;
    - ``split`` - Each eFuse block is placed in its own file. The tool will create multiple files based on the given the ``--file_name`` argument. Example: "--file_name /path/blk.bin", blk0.bin, blk1.bin ... blkN.bin. Use the ``burn_block_data`` cmd to write it back to another chip.
- ``--file_name`` - The path to the file in which to save the dump, if not specified, output to the console.

Raw Values Of Efuse Registers
-----------------------------

The number of blocks depends on the chips and can vary from 4 to 11. A block can have different names, which can be used with ``burn_key`` or ``burn_block_data``.

The order of registers in the dump:

.. code-block:: none

                                                        REG_0    REG_1    REG_2    REG_3    REG_4    REG_5
    BLOCK0          (                ) [0 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000

.. only:: esp32

    .. code-block:: none

        > espefuse.py  dump

        Detecting chip type... Unsupported detection protocol, switching and trying again...
        Connecting....
        Detecting chip type... ESP32
        BLOCK0          (                ) [0 ] read_regs: 00000000 7e5a6e58 00e294b9 0000a200 00000333 00100000 00000004
        BLOCK1          (flash_encryption) [1 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK2          (secure_boot_v1 s) [2 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK3          (                ) [3 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

        EFUSE_REG_DEC_STATUS        0x00000000

.. only:: esp32c2

    .. code-block:: none

        > espefuse.py dump

        Connecting.........
        Detecting chip type... ESP32-C2
        BLOCK0          (BLOCK0          ) [0 ] read_regs: 00000000 00000000
        BLOCK1          (BLOCK1          ) [1 ] read_regs: 11efcdab 00000000 00000000
        BLOCK2          (BLOCK2          ) [2 ] read_regs: 558000a4 000094b5 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY0      (BLOCK3          ) [3 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

        BLOCK0          (BLOCK0          ) [0 ] err__regs: 00000000 00000000
        EFUSE_RD_RS_ERR_REG         0x00000000

.. only:: not esp32 and not esp32c2

    .. code-block:: none

        > espefuse.py dump

        Connecting....
        Detecting chip type... ESP32-C3
        BLOCK0          (                ) [0 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000
        MAC_SPI_8M_0    (BLOCK1          ) [1 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_SYS_DATA  (BLOCK2          ) [2 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_USR_DATA  (BLOCK3          ) [3 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY0      (BLOCK4          ) [4 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY1      (BLOCK5          ) [5 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY2      (BLOCK6          ) [6 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY3      (BLOCK7          ) [7 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY4      (BLOCK8          ) [8 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_KEY5      (BLOCK9          ) [9 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        BLOCK_SYS_DATA2 (BLOCK10         ) [10] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

        BLOCK0          (                ) [0 ] err__regs: 00000000 00000000 00000000 00000000 00000000 00000000
        EFUSE_RD_RS_ERR0_REG        0x00000000
        EFUSE_RD_RS_ERR1_REG        0x00000000

In the last lines, which are separated from the main dump, you can see the encoding scheme status for each block. If there are all zeros, then there are no coding scheme errors.

Save Dump To Files
------------------

This command saves dump for each block into a separate file. You need to provide the common path name ``/chip1/blk.bin``, it will create files in the given directory (the directory must exist): /chip1/blk0.bin, /chip1/blk1.bin - /chip1/blkN.bin. Use ``burn_block_data`` command to write them back to another chip. Note that some blocks may be read-protected, in which case the data in the block will be zero.

.. code-block:: none

    > espefuse.py dump --format split --file_name backup/chip1/blk.bin

    === Run "dump" command ===
    backup/chip1/blk0.bin
    backup/chip1/blk1.bin
    backup/chip1/blk2.bin
    backup/chip1/blk3.bin
    backup/chip1/blk4.bin
    backup/chip1/blk5.bin
    backup/chip1/blk6.bin
    backup/chip1/blk7.bin
    backup/chip1/blk8.bin
    backup/chip1/blk9.bin
    backup/chip1/blk10.bin

These dump files can be written to another chip:

.. code-block:: none

    > espefuse.py burn_block_data BLOCK0 backup/chip1/blk0.bin \
    BLOCK1 backup/chip1/blk1.bin \
    BLOCK2 backup/chip1/blk2.bin

To save all eFuse blocks in one file, use the following command:

.. code-block:: none

    > espefuse.py dump --format joint --file_name backup/chip1/efuses.bin

    === Run "dump" command ===
    backup/chip1/efuses.bin
