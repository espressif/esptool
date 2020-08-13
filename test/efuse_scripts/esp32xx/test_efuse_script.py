# flake8: noqa
espefuse(esp, efuses, args, 'burn_efuse DIS_FORCE_DOWNLOAD 1 DIS_CAN 1 DIS_USB 1')
espefuse(esp, efuses, args, 'burn_bit BLOCK_USR_DATA 64 66 69 72 78 82 83 90')
espefuse(esp, efuses, args, 'read_protect_efuse BLOCK_SYS_DATA2')
espefuse(esp, efuses, args, 'write_protect_efuse BLOCK_SYS_DATA2')
espefuse(esp, efuses, args, 'burn_block_data BLOCK_KEY5 ../../images/efuse/256bit')
espefuse(esp, efuses, args, 'burn_key BLOCK_KEY0 ../../images/efuse/256bit XTS_AES_256_KEY_1 --no-read-protect')
espefuse(esp, efuses, args, 'burn_key_digest BLOCK_KEY1 ../../secure_images/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0')

efuses.burn_all()

espefuse(esp, efuses, args, 'summary')
espefuse(esp, efuses, args, 'adc_info')


# Checks written eFuses
if efuses["DIS_FORCE_DOWNLOAD"].get() != 1:
    raise esptool.FatalError("DIS_FORCE_DOWNLOAD was not set")
if efuses["DIS_CAN"].get() != 1:
    raise esptool.FatalError("DIS_CAN was not set")
if efuses["DIS_USB"].get() != 1:
    raise esptool.FatalError("DIS_USB was not set")

if efuses["BLOCK_USR_DATA"].get_meaning() != "00 00 00 00 00 00 00 00 25 41 0c 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("BLOCK_USR_DATA was not set correctly")


if efuses["BLOCK_SYS_DATA2"].is_readable() or efuses["BLOCK_SYS_DATA2"].is_writeable():
    raise esptool.FatalError("BLOCK_SYS_DATA2 should be read and write protected")


if efuses["BLOCK_KEY5"].get_meaning() != "a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf":
    raise esptool.FatalError("BLOCK_KEY5 was not set correctly")


if efuses["BLOCK_KEY0"].get_meaning() != "bf be bd bc bb ba b9 b8 b7 b6 b5 b4 b3 b2 b1 b0 af ae ad ac ab aa a9 a8 a7 a6 a5 a4 a3 a2 a1 a0":
    raise esptool.FatalError("BLOCK_KEY0 was not set correctly")

if not efuses["BLOCK_KEY0"].is_readable() or efuses["BLOCK_KEY0"].is_writeable():
    raise esptool.FatalError("BLOCK_KEY0 should be readable and not writable")

if efuses["KEY_PURPOSE_0"].get_meaning() != "XTS_AES_256_KEY_1":
    raise esptool.FatalError("KEY_PURPOSE_0 was not set XTS_AES_256_KEY_1")

if efuses["KEY_PURPOSE_0"].is_writeable():
    raise esptool.FatalError("KEY_PURPOSE_0 should be write-protected")


if efuses["BLOCK_KEY1"].get_meaning() != "cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63":
    raise esptool.FatalError("BLOCK_KEY1 was not set correctly")

if efuses["KEY_PURPOSE_1"].get_meaning() != "SECURE_BOOT_DIGEST0":
    raise esptool.FatalError("KEY_PURPOSE_1 was not set SECURE_BOOT_DIGEST0")

if efuses["KEY_PURPOSE_1"].is_writeable():
    raise esptool.FatalError("KEY_PURPOSE_1 should be write-protected")

if not efuses["BLOCK_KEY1"].is_readable() or efuses["BLOCK_KEY1"].is_writeable():
    raise esptool.FatalError("BLOCK_KEY1 should be readable and not writable")


espefuse(esp, efuses, args, 'burn_key BLOCK_KEY0 ../../images/efuse/256bit XTS_AES_256_KEY_1')
efuses.burn_all()
if efuses["BLOCK_KEY0"].is_readable() or efuses["BLOCK_KEY0"].is_writeable():
    raise esptool.FatalError("BLOCK_KEY0 should be not readable and not writeable")
