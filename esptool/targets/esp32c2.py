# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import time

from .esp32c3 import ESP32C3ROM
from ..loader import ESPLoader, StubMixin
from ..logger import log
from ..util import FatalError


class ESP32C2ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C2"
    IMAGE_CHIP_ID = 12

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42400000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3C400000

    EFUSE_BASE = 0x60008800
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x040
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

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3C000000, 0x3C400000, "DROM"],
        [0x3FCA0000, 0x3FCE0000, "DRAM"],
        [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
        [0x3FF00000, 0x3FF50000, "DROM_MASK"],
        [0x40000000, 0x40090000, "IROM_MASK"],
        [0x42000000, 0x42400000, "IROM"],
        [0x4037C000, 0x403C0000, "IRAM"],
    ]

    RTCCNTL_BASE_REG = 0x60008000
    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0084
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x0088
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x009C
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    UF2_FAMILY_ID = 0x2B88D29C

    KEY_PURPOSES: dict[int, str] = {}

    def get_pkg_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 22) & 0x07

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C2",
            1: "ESP32-C2",
        }.get(self.get_pkg_version(), "unknown ESP32-C2")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_minor_chip_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 16) & 0xF

    def get_major_chip_version(self):
        num_word = 1
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 20) & 0x3

    def get_flash_cap(self):
        # ESP32-C2 doesn't have eFuse field FLASH_CAP.
        # Can't get info about the flash chip.
        return 0

    def get_flash_vendor(self):
        # ESP32-C2 doesn't have eFuse field FLASH_VENDOR.
        # Can't get info about the flash chip.
        return ""

    def get_crystal_freq(self):
        # The crystal detection algorithm of ESP32/ESP8266 works for ESP32-C2 as well.
        return ESPLoader.get_crystal_freq(self)

    def change_baud(self, baud):
        rom_with_26M_XTAL = not self.IS_STUB and self.get_crystal_freq() == 26
        if rom_with_26M_XTAL:
            # The code is copied over from ESPLoader.change_baud().
            # Probably this is just a temporary solution until the next chip revision.

            # The ROM code thinks it uses a 40 MHz XTAL. Recompute the baud rate
            # in order to trick the ROM code to set the correct baud rate for
            # a 26 MHz XTAL.
            false_rom_baud = baud * 40 // 26

            log.print(f"Changing baud rate to {baud}")
            self.command(
                self.ESP_CHANGE_BAUDRATE, struct.pack("<II", false_rom_baud, 0)
            )
            log.print("Changed.")
            self._set_port_baudrate(baud)
            time.sleep(0.05)  # get rid of garbage sent during baud rate change
            self.flush_input()
        else:
            ESPLoader.change_baud(self, baud)

    def _post_connect(self):
        # ESP32C2 ECO0 is no longer supported by the flasher stub
        if not self.secure_download_mode and self.get_chip_revision() == 0:
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
            # non-zero key. We break out on first occurrence of non-zero value
            key_word = [0] * 7 if key_len_256 else [0] * 3
            for i in range(len(key_word)):
                key_word[i] = self.read_reg(self.EFUSE_BLOCK_KEY0_REG + i * 4)
                # key is non-zero so break & return
                if key_word[i] != 0:
                    return True
            return False

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 21))):
            raise FatalError("SPI Pin numbers must be in the range 0-20.")


class ESP32C2StubLoader(StubMixin, ESP32C2ROM):
    """Stub loader for ESP32-C2, runs on top of ROM."""

    pass


ESP32C2ROM.STUB_CLASS = ESP32C2StubLoader
