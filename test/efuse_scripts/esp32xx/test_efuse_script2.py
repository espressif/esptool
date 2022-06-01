# flake8: noqa
# fmt: off
espefuse(esp, efuses, args, 'burn_efuse DIS_FORCE_DOWNLOAD 1 DIS_CAN 1 DIS_DOWNLOAD_MODE 1')
if efuses["DIS_FORCE_DOWNLOAD"].get() != 0:
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, 'burn_bit BLOCK_USR_DATA 64 66 69 72 78 82 83 90')
if efuses["BLOCK_USR_DATA"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, 'read_protect_efuse BLOCK_SYS_DATA2')
espefuse(esp, efuses, args, 'write_protect_efuse BLOCK_SYS_DATA2')
if not efuses["BLOCK_SYS_DATA2"].is_readable() or not efuses["BLOCK_SYS_DATA2"].is_writeable():
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, 'burn_block_data BLOCK_KEY5 ../../images/efuse/256bit')
if efuses["BLOCK_KEY5"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, 'burn_key BLOCK_KEY0 ../../images/efuse/256bit XTS_AES_128_KEY --no-read-protect')
if efuses["BLOCK_KEY0"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")
if not efuses["BLOCK_KEY0"].is_readable() or not efuses["BLOCK_KEY0"].is_writeable():
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, 'burn_key_digest BLOCK_KEY1 ../../secure_images/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0')
if efuses["BLOCK_KEY1"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")
if not efuses["BLOCK_KEY1"].is_readable() or not efuses["BLOCK_KEY1"].is_writeable():
    raise esptool.FatalError("Burn should be at the end")
