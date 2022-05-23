# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

from .esp32c3 import ESP32C3ROM
from ..stub_flasher import ESP32C2StubCode


class ESP32C2ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C2"
    IMAGE_CHIP_ID = 12

    STUB_CODE = ESP32C2StubCode

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42400000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3C400000

    # Magic value for ESP32C2 ECO0 and ECO1 respectively
    CHIP_DETECT_MAGIC_VALUE = [0x6F51306F, 0x7C41A06F]

    EFUSE_BASE = 0x60008800
    MAC_EFUSE_REG = EFUSE_BASE + 0x040

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x30
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 21

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x30
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_BASE + 0x30
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 6

    EFUSE_XTS_KEY_LENGTH_256_REG = EFUSE_BASE + 0x30
    EFUSE_XTS_KEY_LENGTH_256 = 1 << 10

    EFUSE_BLOCK_KEY0_REG = EFUSE_BASE + 0x60

    EFUSE_RD_DIS_REG = EFUSE_BASE + 0x30
    EFUSE_RD_DIS = 3

    FLASH_FREQUENCY = {
        "60m": 0xF,
        "30m": 0x0,
        "20m": 0x1,
        "15m": 0x2,
    }

    def get_pkg_version(self):
        num_word = 3
        block1_addr = self.EFUSE_BASE + 0x044
        word3 = self.read_reg(block1_addr + (4 * num_word))
        pkg_version = (word3 >> 21) & 0x0F
        return pkg_version

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C2",
        }.get(self.get_pkg_version(), "unknown ESP32-C2")
        chip_revision = self.get_chip_revision()

        return "%s (revision %d)" % (chip_name, chip_revision)

    def get_chip_revision(self):
        si = self.get_security_info()
        return si["api_version"]

    def _post_connect(self):
        # ESP32C2 ECO0 is no longer supported by the flasher stub
        if self.get_chip_revision() == 0:
            self.stub_is_disabled = True
            self.IS_STUB = False

    """ Try to read (encryption key) and check if it is valid """

    def is_flash_encryption_key_valid(self):
        key_len_256 = (
            self.read_reg(self.EFUSE_XTS_KEY_LENGTH_256_REG)
            & self.EFUSE_XTS_KEY_LENGTH_256
        )

        word0 = self.read_reg(self.EFUSE_RD_DIS_REG) & self.EFUSE_RD_DIS
        rd_disable = word0 == 3 if key_len_256 else word0 == 1

        # reading of BLOCK3 is NOT ALLOWED so we assume valid key is programmed
        if rd_disable:
            return True
        else:
            # reading of BLOCK3 is ALLOWED so we will read and verify for non-zero.
            # When chip has not generated AES/encryption key in BLOCK3,
            # the contents will be readable and 0.
            # If the flash encryption is enabled it is expected to have a valid
            # non-zero key. We break out on first occurance of non-zero value
            key_word = [0] * 7 if key_len_256 else [0] * 3
            for i in range(len(key_word)):
                key_word[i] = self.read_reg(self.EFUSE_BLOCK_KEY0_REG + i * 4)
                # key is non-zero so break & return
                if key_word[i] != 0:
                    return True
            return False


class ESP32C2StubLoader(ESP32C2ROM):
    """Access class for ESP32C2 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C2ROM.STUB_CLASS = ESP32C2StubLoader
