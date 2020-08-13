# flake8: noqa
espefuse(esp, efuses, args, "burn_efuse JTAG_DISABLE 1 DISABLE_SDIO_HOST 1 CONSOLE_DEBUG_DISABLE 1")
espefuse(esp, efuses, args, "burn_key flash_encryption ../../images/efuse/256bit --no-protect-key")
espefuse(esp, efuses, args, "burn_key_digest ../../secure_images/rsa_secure_boot_signing_key.pem")
espefuse(esp, efuses, args, "burn_bit BLOCK3 64 66 69 72 78 82 83 90")
espefuse(esp, efuses, args, "burn_custom_mac AA:BB:CC:DD:EE:88")

efuses.burn_all()

espefuse(esp, efuses, args, "summary")
espefuse(esp, efuses, args, "adc_info")
espefuse(esp, efuses, args, "get_custom_mac")


# Checks written eFuses
if efuses["JTAG_DISABLE"].get() != 1:
    raise esptool.FatalError("JTAG_DISABLE was not set")
if efuses["DISABLE_SDIO_HOST"].get() != 1:
    raise esptool.FatalError("DISABLE_SDIO_HOST was not set")
if efuses["CONSOLE_DEBUG_DISABLE"].get() != 1:
    raise esptool.FatalError("CONSOLE_DEBUG_DISABLE was not set")


if efuses["BLOCK1"].get_meaning() != "bf be bd bc bb ba b9 b8 b7 b6 b5 b4 b3 b2 b1 b0 af ae ad ac ab aa a9 a8 a7 a6 a5 a4 a3 a2 a1 a0":
    raise esptool.FatalError("BLOCK1 was not set correctly")

if not efuses["BLOCK1"].is_readable() or not efuses["BLOCK1"].is_writeable():
    raise esptool.FatalError("BLOCK1 should be readable and writeable")


if efuses["BLOCK2"].get_meaning() != "cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63":
    raise esptool.FatalError("BLOCK2 was not set correctly")

if not efuses["BLOCK2"].is_readable() or efuses["BLOCK2"].is_writeable():
    raise esptool.FatalError("BLOCK2 should not be readable and not writeable")


if efuses["BLOCK3"].get_meaning() != "69 aa bb cc dd ee 88 00 25 41 0c 04 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00":
    raise esptool.FatalError("BLOCK3 was not set correctly")

if efuses["CUSTOM_MAC"].get_meaning() != "aa:bb:cc:dd:ee:88 (CRC 0x69 OK)":
    raise esptool.FatalError("CUSTOM_MAC was not set correctly")


espefuse(esp, efuses, args, "read_protect_efuse BLOCK1")
espefuse(esp, efuses, args, "write_protect_efuse BLOCK1")
efuses.burn_all()
if efuses["BLOCK1"].is_readable() or efuses["BLOCK1"].is_writeable():
    raise esptool.FatalError("BLOCK_KEY0 should be not readable and not writeable")
