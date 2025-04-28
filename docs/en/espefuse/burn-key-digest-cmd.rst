.. _burn-key-digest-cmd:

Burn Key Digest
===============

The ``espefuse.py burn-key-digest`` command parses a RSA public key and burns the digest to eFuse block for use with `Secure Boot V2 <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/secure-boot-v2.html#signature-block-format>`_.

Positional arguments:

.. list::

    :not esp32 and not esp32c2: - ``block`` - Name of key block.
    - ``Keyfile``. Key file to digest (PEM format).
    :not esp32 and not esp32c2: - ``Key purpose``. The purpose of this key [``SECURE_BOOT_DIGEST0``, ``SECURE_BOOT_DIGEST1``, ``SECURE_BOOT_DIGEST2``].

.. only:: not esp32 and not esp32c2

    It can be list of blocks and keyfiles and key purposes (like BLOCK_KEY0 keyfile0.pem SECURE_BOOT_DIGEST0 BLOCK_KEY1 keyfile1.pem SECURE_BOOT_DIGEST1 etc.).

Optional arguments:

.. list::

    :esp32: - ``--no-protect-key``. Disable default read and write protecting of the key.
    :not esp32: - ``--no-write-protect``. Disable write-protecting of the key. The key remains writable. The keys use the RS coding scheme that does not support post-write data changes. Forced write can damage RS encoding bits. The write-protecting of keypurposes does not depend on the option, it will be set anyway.
    :not esp32: - ``--no-read-protect``. Disable read-protecting of the key. This option does not change anything, because Secure Boot keys are readable anyway.
    - ``--force-write-always``. Write the eFuse key even if it looks like it is already been written, or is write protected. Note that this option can't disable write protection, or clear any bit which has already been set.
    - ``--show-sensitive-info``. Show data to be burned (may expose sensitive data). Enabled if --debug is used. Use this option to see the byte order of the data being written.

.. only:: esp32

    {IDF_TARGET_NAME} must have chip version > 3 (v300) and coding scheme = ``None`` otherwise an error will be shown. The key will be burned to BLOCK2.

.. only:: esp32c2

    The key will be burned to BLOCK3.

The secure boot v2 key(s) will be readable and write protected.

Usage
-----

.. only:: esp32

    .. code-block:: none

        > espefuse.py burn-key-digest secure_boot_key_v2_0.pem

        === Run "burn-key-digest" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        - BLOCK2 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
        Disabling write to efuse BLOCK2...

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        [02] BLOCK2               is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK2  - OK (write block == read block)
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful

        > espefuse.py summary
        ...
        BLOCK2 (BLOCK2):                                   Secure boot key
        = a2 cd 39 85 df 00 d7 95 07 0f f6 7c 8b ab e1 7d 39 11 95 c4 5b 37 6e 7b f0 ec 04 5e 36 30 02 5d R/-

.. only:: esp32c2

    See :ref:`perform-multiple-operations` for how to burn flash encryption and secure boot keys to the same eFuse key block at the same time.

    .. code-block:: none

        > espefuse.py burn-key-digest secure_boot_v2_ecdsa192.pem

        === Run "burn-key-digest" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK_KEY0_HI_128 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Disabling write to key block

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        [03] BLOCK_KEY0           is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK3  - OK (write block == read block)
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful

        > espefuse.py  summary
        ...
        XTS_KEY_LENGTH_256 (BLOCK0)                        Flash encryption key length                        = 128 bits key R/W (0b0)
        ...
        BLOCK_KEY0 (BLOCK3)                                BLOCK_KEY0 - 256-bits. 256-bit key of Flash Encryp
        = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 c2 bd 9c 1a b4 b7 44 22 59 c6 d3 12 0b 79 1f R/-
                                                        tion
        BLOCK_KEY0_LOW_128 (BLOCK3)                        BLOCK_KEY0 - lower 128-bits. 128-bit key of Flash
        = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/-
                                                        Encryption
        BLOCK_KEY0_HI_128 (BLOCK3)                         BLOCK_KEY0 - higher 128-bits. 128-bits key of Secu
        = 02 c2 bd 9c 1a b4 b7 44 22 59 c6 d3 12 0b 79 1f R/-
                                                        re Boot.

.. only:: esp32c3 or esp32s2 or esp32s3

    .. code-block:: none

        > espefuse.py burn-key-digest \
                    BLOCK_KEY0 ~/esp/tests/efuse/secure_boot_key_v2_0.pem  SECURE_BOOT_DIGEST0  \
                    BLOCK_KEY1 ~/esp/tests/efuse/secure_boot_key_v2_1.pem  SECURE_BOOT_DIGEST1  \
                    BLOCK_KEY2 ~/esp/tests/efuse/secure_boot_key_v2_2.pem  SECURE_BOOT_DIGEST2

        === Run "burn-key-digest" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK_KEY0 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                'KEY_PURPOSE_0': 'USER' -> 'SECURE_BOOT_DIGEST0'.
                Disabling write to 'KEY_PURPOSE_0'.
                Disabling write to key block

        - BLOCK_KEY1 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                'KEY_PURPOSE_1': 'USER' -> 'SECURE_BOOT_DIGEST1'.
                Disabling write to 'KEY_PURPOSE_1'.
                Disabling write to key block

        - BLOCK_KEY2 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                'KEY_PURPOSE_2': 'USER' -> 'SECURE_BOOT_DIGEST2'.
                Disabling write to 'KEY_PURPOSE_2'.
                Disabling write to key block

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        [04] BLOCK_KEY0           is empty, will burn the new value
        [05] BLOCK_KEY1           is empty, will burn the new value
        [06] BLOCK_KEY2           is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK6  - OK (write block == read block)
        BURN BLOCK5  - OK (write block == read block)
        BURN BLOCK4  - OK (write block == read block)
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful

        > espefuse.py summary

        KEY_PURPOSE_0 (BLOCK0)                             KEY0 purpose                                       = SECURE_BOOT_DIGEST0 R/- (0x9)
        KEY_PURPOSE_1 (BLOCK0)                             KEY1 purpose                                       = SECURE_BOOT_DIGEST1 R/- (0xa)
        KEY_PURPOSE_2 (BLOCK0)                             KEY2 purpose                                       = SECURE_BOOT_DIGEST2 R/- (0xb)
        ...
        BLOCK_KEY0 (BLOCK4)
        Purpose: SECURE_BOOT_DIGEST0
        Encryption key0 or user data
        = a2 cd 39 85 df 00 d7 95 07 0f f6 7c 8b ab e1 7d 39 11 95 c4 5b 37 6e 7b f0 ec 04 5e 36 30 02 5d R/-
        BLOCK_KEY1 (BLOCK5)
        Purpose: SECURE_BOOT_DIGEST1
        Encryption key1 or user data
        = a3 cd 39 85 df 00 d7 95 07 0f f6 7c 8b ab e1 7d 39 11 95 c4 5b 37 6e 7b f0 ec 04 5e 36 30 02 5d R/-
        BLOCK_KEY2 (BLOCK6)
        Purpose: SECURE_BOOT_DIGEST2
        Encryption key2 or user data
        = a4 cd 39 85 df 00 d7 95 07 0f f6 7c 8b ab e1 7d 39 11 95 c4 5b 37 6e 7b f0 ec 04 5e 36 30 02 5d R/-
