.. _burn-key-cmd:

Burn Key
========

The ``espefuse burn-key`` command burns keys to eFuse blocks:

.. list::

    :esp32: - `Secure Boot V1 <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/secure-boot-v1.html>`_
    - `Secure Boot V2 <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/secure-boot-v2.html>`_
    - `Flash Encryption <https://docs.espressif.com/projects/esp-idf/en/latest/{IDF_TARGET_PATH_NAME}/security/flash-encryption.html>`_
    - etc.

Positional arguments:

.. list::

    - ``block`` - Name of key block.
    :esp32: - ``Keyfile``. It is a raw binary file. It must contain 256 bits of binary key if the coding scheme is ``None`` and 128 bits if ``3/4``.
    :not esp32 and not esp32h2: - ``Keyfile``. It is a raw binary file. The length of binary key depends on the key purpose option.
    :esp32h2: - ``Keyfile``. It is a raw binary file. The length of binary key depends on the key purpose option. For the ``ECDSA_KEY`` purpose use ``PEM`` file.
    :not esp32: - ``Key purpose``. The purpose of this key.

.. only:: esp32

    It can be list of key blocks and keyfiles (like BLOCK1 file1.bin BLOCK2 file2.bin etc.).

.. only:: not esp32

    It can be list of key blocks and keyfiles and key purposes (like BLOCK_KEY1 file1.bin USER BLOCK_KEY2 file2.bin USER etc.).

Optional arguments:

.. list::

    :esp32: - ``--no-protect-key``. Disable default read and write protecting of the key. If this option is not set, once the key is flashed it can not be read back.
    :not esp32: - ``--no-write-protect``. Disable write-protecting of the key. The key remains writable. The keys use the RS coding scheme that does not support post-write data changes. Forced write can damage RS encoding bits. The write-protecting of keypurposes does not depend on the option, it will be set anyway.
    :not esp32: - ``--no-read-protect``. Disable read-protecting of the key. The key remains readable software. The key with keypurpose [USER, RESERVED and .._DIGEST] will remain readable anyway, but for the rest keypurposes the read-protection will be defined by this option (Read-protect by default).
    - ``--force-write-always``. Write the eFuse key even if it looks like it is already been written, or is write protected. Note that this option can't disable write protection, or clear any bit which has already been set.
    - ``--show-sensitive-info``. Show data to be burned (may expose sensitive data). Enabled if --debug is used. Use this option to see the byte order of the data being written.

.. only:: esp32

    {IDF_TARGET_NAME} supports keys:

    * Secure boot key. Use ``secure_boot_v1`` or ``secure_boot_v2`` as block name. The key is placed in BLOCK2.
    * Flash encryption key. Use ``flash_encryption`` as block name. The key is placed in BLOCK1.

    Keys for ``flash_encryption`` and ``secure_boot_v1`` will be burned as read and write protected. The hardware will still have access to them.  These keys are burned in reversed byte order.

    Key for ``secure_boot_v2`` will be burned only as write protected. The key must be readable because the software need access to it.

    .. warning::

        Do not use the names ``BLOCK1`` and ``BLOCK2`` to burn flash encryption and secure boot v2 keys because byte order will be incorrect and read protection will not meet security requirements.

.. only:: not esp32 and not esp32c2

    {IDF_TARGET_NAME} supports eFuse key purposes. This means that each eFuse block has a special eFuse field that indicates which key is in the eFuse block. During the burn operation this eFuse key purpose is burned as well with write protection (the ``--no-write-protect`` flag has no effect on this field). The {IDF_TARGET_NAME} chip supports the following key purposes:

    .. list::

        - USER.
        - RESERVED.
        :esp32p4 or esp32s2 or esp32s3: - XTS_AES_256_KEY_1. The first 256 bits of 512bit flash encryption key.
        :esp32p4 or esp32s2 or esp32s3: - XTS_AES_256_KEY_2. The second 256 bits of 512bit flash encryption key.
        :esp32c5 or esp32c61 or esp32h2 or esp32h21 or esp32h4 or esp32p4: - ECDSA_KEY. It can be ECDSA private keys based on NIST192p or NIST256p curve. The private key is extracted from the given file and written into a eFuse block with write and read protection enabled. This private key shall be used by ECDSA accelerator for the signing purpose.
        :esp32c5: - ECDSA_KEY_P192. ECDSA private keys based on NIST192p curve.
        :esp32c5: - ECDSA_KEY_P256. ECDSA private keys based on NIST256p curve.
        :esp32c5: - ECDSA_KEY_P384. ECDSA private keys based on NIST384p curve. This allows you to write a whole 48-byte key into two blocks with ``ECDSA_KEY_P384_H`` and ``ECDSA_KEY_P384_L`` purposes.
        :esp32c5: - ECDSA_KEY_P384_H. Upper 32 bytes of the 48-byte ECDSA_P384 key (last 16 bytes of key + 16 padding bytes).
        :esp32c5: - ECDSA_KEY_P384_L. Lower 32 bytes of the 48-byte ECDSA_P384 key.
        - XTS_AES_128_KEY. 256 bit flash encryption key.
        - HMAC_DOWN_ALL.
        - HMAC_DOWN_JTAG.
        - HMAC_DOWN_DIGITAL_SIGNATURE.
        - HMAC_UP.
        - SECURE_BOOT_DIGEST0. 1 secure boot key.
        - SECURE_BOOT_DIGEST1. 2 secure boot key.
        - SECURE_BOOT_DIGEST2. 3 secure boot key.
        :esp32p4 or esp32s2 or esp32s3: - XTS_AES_256_KEY. This is a virtual key purpose for flash encryption key. This allows you to write a whole 512-bit key into two blocks with ``XTS_AES_256_KEY_1`` and ``XTS_AES_256_KEY_2`` purposes without splitting the key file.
        :esp32c5 or esp32h4 or esp32p4: - KM_INIT_KEY. This is a key that is used for the generation of AES/ECDSA keys by the key manager.

.. only:: esp32c5 or esp32c61 or esp32h2 or esp32h21 or esp32h4 or esp32p4

    {IDF_TARGET_NAME} has the ECDSA accelerator for signature purposes and supports private keys based on the NIST192p or NIST256p curve (some chips support NIST384p). These two commands below can be used to generate such keys (``PEM`` file). The ``burn-key`` command with the ``ECDSA_KEY`` purpose takes the ``PEM`` file and writes the private key into a eFuse block. The key is written to the block in reverse byte order.

    .. list::

      - For NIST192p, the private key is 192 bits long, so 8 padding bytes ("0x00") are added.
      - For NIST256p, the private key is 256 bits long.
      - For NIST384p, the private key is 384 bits long, so 16 padding bytes ("0x00") are added.

    .. code-block:: none

        > espsecure generate_signing_key -v 2 -s ecdsa192 ecdsa192.pem
        ECDSA NIST192p private key in PEM format written to ecdsa192.pem

    .. code-block:: none

        > espsecure generate_signing_key -v 2 -s ecdsa256 ecdsa256.pem
        ECDSA NIST256p private key in PEM format written to ecdsa256.pem

.. only:: esp32c2

    {IDF_TARGET_NAME} has only one eFuse key block (256 bits long). It is block #3 - ``BLOCK_KEY0``. This block can have user, flash encryption, secure boot keys. This chip does not have any eFuse key purpose fields, but we use the key purpose option to distinguish between such keys. The key purpose option determines protection and byte order for key.

    .. list::

        - USER
        - XTS_AES_128_KEY. 256 bits flash encryption key. The secure boot key can not be used with this option. In addition, eFuse ``XTS_KEY_LENGTH_256`` is set to 1, which means that the flash encryption key is 256 bits long.
        - XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS. 128 bits flash encryption key. The 128 bits of this key will be burned to the low part of the eFuse block. These bits will be read protected.
        - SECURE_BOOT_DIGEST. Secure boot key. The first 128 bits of key will be burned to the high part of the eFuse block.

    {IDF_TARGET_NAME} can have in eFuse block the following combination of keys:

    1. Both, Flash encryption (low 128 bits of eFuse block) and Secure boot key (high 128 bits of eFuse block).
    2. only Flash encryption (low 128 bits of eFuse block), rest part of eFuse block is not possible to use in future.
    3. only Flash encryption key (256 bits long), whole eFuse key block.
    4. only Secure boot key (high 128 bits of eFuse block).
    5. no keys, used for user purposes. Chip does not have security features.

.. only:: not esp32

    All keys will be burned with write protection if ``--no-write-protect`` is not used.

    Only flash encryption key is read protected if ``--no-read-protect`` is not used.

    All keys, except flash encryption, will be burned in direct byte order. The encryption key is written in reverse byte order for compatibility with encryption hardware.

.. only:: esp32

    Key Coding Scheme
    ^^^^^^^^^^^^^^^^^

    When the ``None`` coding scheme is in use, keys are 256-bits (32 bytes) long. When 3/4 Coding Scheme is in use (``CODING_SCHEME`` eFuse has value 1 not 0), keys are 192-bits (24 bytes) long and an additional 64 bits of error correction data are also written.
    espefuse v2.6 or newer supports the 3/4 Coding Scheme. The key file must be the appropriate length for the coding scheme currently in use.

Unprotected Keys
^^^^^^^^^^^^^^^^

By default, when an encryption key block is burned it is also read and write protected.

.. only:: esp32

    The ``--no-protect-key`` option will disable this behaviour (you can separately read or write protect the key later).

.. only:: not esp32

    The ``--no-read-protect`` and ``--no-write-protect`` options will disable this behaviour (you can separately read or write protect the key later).

.. note::

    Leaving a key unprotected may compromise its use as a security feature.

.. code-block:: none

    espefuse burn-key secure_boot_v1 secure_boot_key_v1.bin

.. only:: esp32

    Note that the hardware flash encryption and secure boot v1 features require the key to be written to the eFuse block in reversed byte order, compared to the order used by the AES algorithm on the host. Using corresponding block name, the tool automatically reverses the bytes when writing. For this reason, an unprotected key will read back in the reverse order.

Force Writing a Key
^^^^^^^^^^^^^^^^^^^

Normally, a key will only be burned if the eFuse block has not been previously written to. The ``--force-write-always`` option can be used to ignore this and try to burn the key anyhow.

Note that this option is still limited by the eFuse hardware - hardware does not allow any eFuse bits to be cleared 1->0, and can not write anything to write protected eFuse blocks.

Usage
-----

.. only:: esp32

    .. code-block:: none

        > espefuse burn-key flash_encryption  256bit_fe_key.bin

        === Run "burn-key" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK1 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Reversing the byte order
                Disabling read to key block
                Disabling write to key block

        Burn keys in efuse blocks.
        The key block will be read and write protected

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        [01] BLOCK1               is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK1  - OK (write block == read block)
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful

    .. code-block:: none

        > espefuse summary
        ...
        BLOCK1 (BLOCK1):                                   Flash encryption key
        = ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/-

    Byte order for flash encryption key is reversed. Content of flash encryption key file ("256bit_fe_key.bin"):

    .. code-block:: none

        0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f

    When the ``no protection`` option is used then you can see the burned key:

    .. code-block:: none

        > espefuse burn-key flash_encryption  256bit_fe_key.bin --no-protect-key

        === Run "burn-key" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK1 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Reversing the byte order

        Key is left unprotected as per --no-protect-key argument.
        Burn keys in efuse blocks.
        The key block will left readable and writeable (due to --no-protect-key)

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [01] BLOCK1               is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK1  - OK (write block == read block)
        Reading updated efuses...
        Successful

    .. code-block:: none

        > espefuse summary
        ...
        BLOCK1 (BLOCK1):                                   Flash encryption key
        = 1f 1e 1d 1c 1b 1a 19 18 17 16 15 14 13 12 11 10 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00 R/W

.. only:: esp32s2 or esp32s3

    Burning XTS_AES_256_KEY:

    The first 256 bit of the key goes to given BLOCK (here it is ``BLOCK_KEY0``) with key purpose = ``XTS_AES_256_KEY_1``. The last 256 bit of the key will be burned to the first free key block after BLOCK (here it is ``BLOCK_KEY1``) and set key purpose to ``XTS_AES_256_KEY_2`` for this block.

    This example uses ``--no-read-protect`` to expose the byte order written into eFuse blocks.

    Content of flash encryption key file (``512bits_0.bin``):

    .. code-block:: none

        0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
        2021 2223 2425 2627 2829 2a2b 2c2d 2e2f  3031 3233 3435 3637 3839 3a3b 3c3d 3e3f

    .. code-block:: none

        > espefuse burn-key BLOCK_KEY0 ~/esp/tests/efuse/512bits_0.bin  XTS_AES_256_KEY --no-read-protect

        === Run "burn-key" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK_KEY0 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Reversing byte order for AES-XTS hardware peripheral
                'KEY_PURPOSE_0': 'USER' -> 'XTS_AES_256_KEY_1'.
                Disabling write to 'KEY_PURPOSE_0'.
                Disabling write to key block

        - BLOCK_KEY1 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Reversing byte order for AES-XTS hardware peripheral
                'KEY_PURPOSE_1': 'USER' -> 'XTS_AES_256_KEY_2'.
                Disabling write to 'KEY_PURPOSE_1'.
                Disabling write to key block

        Keys will remain readable (due to --no-read-protect)

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        [04] BLOCK_KEY0           is empty, will burn the new value
        [05] BLOCK_KEY1           is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK5  - OK (write block == read block)
        BURN BLOCK4  - OK (write block == read block)
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful

        > espefuse summary
        ...
        KEY_PURPOSE_0 (BLOCK0)                             KEY0 purpose                                       = XTS_AES_256_KEY_1 R/- (0x2)
        KEY_PURPOSE_1 (BLOCK0)                             KEY1 purpose                                       = XTS_AES_256_KEY_2 R/- (0x3)
        ...
        BLOCK_KEY0 (BLOCK4)
        Purpose: XTS_AES_256_KEY_1
        Encryption key0 or user data
        = 1f 1e 1d 1c 1b 1a 19 18 17 16 15 14 13 12 11 10 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00 R/-
        BLOCK_KEY1 (BLOCK5)
        Purpose: XTS_AES_256_KEY_2
        Encryption key1 or user data
        = 3f 3e 3d 3c 3b 3a 39 38 37 36 35 34 33 32 31 30 2f 2e 2d 2c 2b 2a 29 28 27 26 25 24 23 22 21 20 R/-

.. only:: esp32c2

    .. code-block:: none

        > espefuse -c esp32c2  \
                                burn-key-digest secure_images/ecdsa256_secure_boot_signing_key_v2.pem \
                                burn-key BLOCK_KEY0 images/efuse/128bit_key.bin XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS

        === Run "burn-key-digest" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK_KEY0_HI_128 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Disabling write to key block


        Batch mode is enabled, the burn will be done at the end of the command.

        === Run "burn-key" command ===
        Sensitive data will be hidden (see --show-sensitive-info)
        Burn keys to blocks:
        - BLOCK_KEY0_LOW_128 -> [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
                Reversing byte order for AES-XTS hardware peripheral
                Disabling read to key block
                Disabling write to key block
                The same value for WR_DIS is already burned. Do not change the efuse.

        Batch mode is enabled, the burn will be done at the end of the command.

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

.. only:: esp32c5

    .. code-block:: none

        > espefuse -c esp32c2  BLOCK_KEY0 secure_images/ecdsa384_secure_boot_signing_key.pem ECDSA_KEY_P384 --no-read-protect --show-sensitive-info

        === Run "burn-key" command ===
        Burn keys to blocks:
        - BLOCK_KEY0 -> [0e d2 8e c6 86 f0 f6 af 50 51 c3 5c 41 2b c7 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
                Reversing byte order for ECDSA_KEY_P384_H hardware peripheral...
                'KEY_PURPOSE_0': 'USER' -> 'ECDSA_KEY_P384_H'.
                Disabling write to 'KEY_PURPOSE_0'...
                Disabling write to key block...

        - BLOCK_KEY1 -> [65 ca a4 5b 5f 67 5c fe 34 89 f3 4a 57 d1 5a 41 d6 1c 7d ea 7a 3f cd 34 79 f2 94 c2 ad cb 94 7d]
                Reversing byte order for ECDSA_KEY_P384_L hardware peripheral...
                'KEY_PURPOSE_1': 'USER' -> 'ECDSA_KEY_P384_L'.
                Disabling write to 'KEY_PURPOSE_1'...
                Disabling write to key block...

        Keys will remain readable (due to --no-read-protect).

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        [04] BLOCK_KEY0           is empty, will burn the new value
        [05] BLOCK_KEY1           is empty, will burn the new value
        .
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK5  - OK (write block == read block)
        BURN BLOCK4  - OK (write block == read block)
        BURN BLOCK0  - OK (write block == read block)
        Reading updated eFuses...
        Successful.

    .. note::

        The flags ``--no-read-protect`` and ``--show-sensitive-info`` in this command are used for demonstration purposes only, to show the key byte order. The ECDSA_KEY keys is always written in reverse byte order. The 48 bytes of the key are extracted from the provided PEM file, and 16 padding bytes are added to form a total of 64 bytes for two eFuse blocks. Due to the required reverse byte order, the last 16 bytes of the key plus 16 padding bytes are written to BLOCK_KEY0 with the key purpose ``ECDSA_KEY_P384_H``, and the remaining 32 bytes are written to the next available eFuse block (here, BLOCK_KEY1) with the key purpose ``ECDSA_KEY_P384_L``.
