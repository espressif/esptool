.. _check-error-cmd:

Check Error
===========

The ``espefuse.py check-error`` command checks eFuse errors. It triggers several reads to force the eFuse controller to reload eFuses and update status registers. This command can be run after burn operations to make sure that there is not errors.

Optional argument:

* ``--recovery``. It repairs encoding errors in eFuse blocks, if possible.

The summary log below shows an error in BLOCK0.

.. code-block:: none

    > espefuse.py summary
    ...
    WDT_DELAY_SEL (BLOCK0)[FAIL:1]                     Selects RTC WDT timeout threshold at startup       = False R/W (0b0)
    ...
    Error(s) in BLOCK0 [ERRORS:1 FAIL:1]

    BLOCK0          (                ) [0 ] err__regs: 00000400 00000000 00000000 00000000 00000000 00000000
    EFUSE_RD_RS_ERR0_REG        0x00000000
    EFUSE_RD_RS_ERR1_REG        0x00000000
    WARNING: Coding scheme has encoding bit error warnings

Usage
-----

Checks the status registers of eFuse blocks and throws an error if there is an error.

.. code-block:: none

    > espefuse.py check-error

    Error(s) in BLOCK1 [ERRORS:0 FAIL:1]
    Error(s) in BLOCK2 [ERRORS:1 FAIL:1]
    Error(s) in BLOCK3 [ERRORS:1 FAIL:1]

    BLOCK0          (                ) [0 ] err__regs: 00000000 00000000 00000000 00000000 00000000 00000000
    EFUSE_RD_RS_ERR0_REG        0x00008990
    EFUSE_RD_RS_ERR1_REG        0x00000000

    === Run "check-error" command ===
    Error(s) in BLOCK1 [ERRORS:0 FAIL:1]
    Error(s) in BLOCK2 [ERRORS:1 FAIL:1]
    Error(s) in BLOCK3 [ERRORS:1 FAIL:1]

    BLOCK0          (                ) [0 ] err__regs: 00000000 00000000 00000000 00000000 00000000 00000000
    EFUSE_RD_RS_ERR0_REG        0x00008990
    EFUSE_RD_RS_ERR1_REG        0x00000000

    A fatal error occurred: Error(s) were detected in eFuses

Repairs encoding errors in eFuse blocks, if possible.

.. code-block:: none

    > espefuse.py check-error --recovery

    Error(s) in BLOCK1 [ERRORS:0 FAIL:1]
    Error(s) in BLOCK2 [ERRORS:1 FAIL:1]
    Error(s) in BLOCK3 [ERRORS:1 FAIL:1]

    BLOCK0          (                ) [0 ] err__regs: 00000000 00000000 00000000 00000000 00000000 00000000
    EFUSE_RD_RS_ERR0_REG        0x00008990
    EFUSE_RD_RS_ERR1_REG        0x00000000

    === Run "check-error" command ===
    Error(s) in BLOCK1 [ERRORS:0 FAIL:1]
    Error(s) in BLOCK2 [ERRORS:1 FAIL:1]
    Error(s) in BLOCK3 [ERRORS:1 FAIL:1]

    BLOCK0          (                ) [0 ] err__regs: 00000000 00000000 00000000 00000000 00000000 00000000
    EFUSE_RD_RS_ERR0_REG        0x00008990
    EFUSE_RD_RS_ERR1_REG        0x00000000
    Recovery of block coding errors.
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.
    BURN
    Error in BLOCK3, re-burn it again (#0), to fix it. fail_bit=1, num_errors=0
    Error in BLOCK3, re-burn it again (#1), to fix it. fail_bit=1, num_errors=0
    Error in BLOCK3, re-burn it again (#2), to fix it. fail_bit=1, num_errors=0
    BURN BLOCK3  - OK (write block == read block)
    Error in BLOCK2, re-burn it again (#0), to fix it. fail_bit=1, num_errors=1
    Error in BLOCK2, re-burn it again (#1), to fix it. fail_bit=1, num_errors=1
    Error in BLOCK2, re-burn it again (#2), to fix it. fail_bit=1, num_errors=1
    BURN BLOCK2  - OK (write block == read block)
    Error in BLOCK1, re-burn it again (#0), to fix it. fail_bit=1, num_errors=0
    Error in BLOCK1, re-burn it again (#1), to fix it. fail_bit=1, num_errors=0
    Error in BLOCK1, re-burn it again (#2), to fix it. fail_bit=1, num_errors=0
    BURN BLOCK1  - OK (write block == read block)
    Error(s) in BLOCK1 [ERRORS:0 FAIL:1]
    Error(s) in BLOCK2 [ERRORS:1 FAIL:1]
    Error(s) in BLOCK3 [ERRORS:0 FAIL:1]

    BLOCK0          (                ) [0 ] err__regs: 00000000 00000000 00000000 00000000 00000000 00000000
    EFUSE_RD_RS_ERR0_REG        0x00008890
    EFUSE_RD_RS_ERR1_REG        0x00000000

    A fatal error occurred: Error(s) were detected in eFuses

If all errors are fixed, then this message is displayed:

.. code-block:: none

    No errors detected
