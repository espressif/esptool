# flake8: noqa
espefuse(esp, efuses, args, "burn_efuse JTAG_DISABLE 1 DISABLE_SDIO_HOST 1 CONSOLE_DEBUG_DISABLE 1")
if efuses["JTAG_DISABLE"].get() != 0:
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, "burn_key flash_encryption ../../images/efuse/256bit --no-protect-key")
if efuses["BLOCK1"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")
if not efuses["BLOCK1"].is_readable() or not efuses["BLOCK1"].is_writeable():
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, "burn_key_digest ../../secure_images/rsa_secure_boot_signing_key.pem")
if efuses["BLOCK2"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")
if not efuses["BLOCK2"].is_readable() or not efuses["BLOCK2"].is_writeable():
    raise esptool.FatalError("Burn should be at the end")

espefuse(esp, efuses, args, "burn_bit BLOCK3 64 66 69 72 78 82 83 90")
espefuse(esp, efuses, args, "burn_custom_mac AA:BB:CC:DD:EE:88")

if efuses["BLOCK3"].get_meaning() != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("Burn should be at the end")
