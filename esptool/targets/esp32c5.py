# SPDX-FileCopyrightText: 2024-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import time

from .esp32c3 import ESP32C3ROM
from .esp32c6 import ESP32C6ROM
from ..loader import ESPLoader, StubMixin
from ..logger import log
from ..util import FatalError


class ESP32C5ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-C5"
    IMAGE_CHIP_ID = 23

    BOOTLOADER_FLASH_OFFSET = 0x2000

    EFUSE_BASE = 0x600B4800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_FORCE_USE_KEY_MANAGER_KEY_REG = EFUSE_BASE + 0x34
    EFUSE_FORCE_USE_KEY_MANAGER_KEY_SHIFT = 10
    FORCE_USE_KEY_MANAGER_VAL_XTS_AES_KEY = 2

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 22
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 27
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 5
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 10
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 15

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x44000000
    DROM_MAP_START = 0x42000000
    DROM_MAP_END = 0x44000000

    PCR_SYSCLK_CONF_REG = 0x60096110
    PCR_SYSCLK_XTAL_FREQ_V = 0x7F << 24
    PCR_SYSCLK_XTAL_FREQ_S = 24

    UARTDEV_BUF_NO = 0x4085F514  # Variable in ROM .bss which indicates the port in use

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42000000, 0x44000000, "DROM"],
        [0x40800000, 0x40860000, "DRAM"],
        [0x40800000, 0x40860000, "BYTE_ACCESSIBLE"],
        [0x4003A000, 0x40040000, "DROM_MASK"],
        [0x40000000, 0x4003A000, "IROM_MASK"],
        [0x42000000, 0x44000000, "IROM"],
        [0x40800000, 0x40860000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0xF71C0343

    KEY_PURPOSES: dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
        12: "KM_INIT_KEY",
        15: "XTS_AES_128_PSRAM_KEY",
        16: "ECDSA_KEY_P192",
        17: "ECDSA_KEY_P384_L",
        18: "ECDSA_KEY_P384_H",
    }

    def get_pkg_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 26) & 0x07

    def get_minor_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_major_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 4) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C5",
        }.get(self.get_pkg_version(), "Unknown ESP32-C5")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return [
            "Wi-Fi 6 (dual-band)",
            "BT 5 (LE)",
            "IEEE802.15.4",
            "Single Core + LP Core",
            "240MHz",
        ]

    def get_crystal_freq(self):
        # The crystal detection algorithm of ESP32/ESP8266
        # works for ESP32-C5 as well.
        return ESPLoader.get_crystal_freq(self)

    def get_crystal_freq_rom_expect(self):
        return (
            self.read_reg(self.PCR_SYSCLK_CONF_REG) & self.PCR_SYSCLK_XTAL_FREQ_V
        ) >> self.PCR_SYSCLK_XTAL_FREQ_S

    def hard_reset(self):
        ESPLoader.hard_reset(self, self.uses_usb_jtag_serial())

    def change_baud(self, baud):
        if self.secure_download_mode:  # ESPTOOL-1231
            log.warning(
                "Baud rate change is not supported in secure download mode. "
                "Keeping 115200 baud."
            )
        elif not self.IS_STUB:
            crystal_freq_rom_expect = self.get_crystal_freq_rom_expect()
            crystal_freq_detect = self.get_crystal_freq()
            log.print(
                f"ROM expects crystal freq: {crystal_freq_rom_expect} MHz, "
                f"detected {crystal_freq_detect} MHz."
            )
            baud_rate = baud
            # If detect the XTAL is 48MHz, but the ROM code expects it to be 40MHz
            if crystal_freq_detect == 48 and crystal_freq_rom_expect == 40:
                baud_rate = baud * 40 // 48
            # If detect the XTAL is 40MHz, but the ROM code expects it to be 48MHz
            elif crystal_freq_detect == 40 and crystal_freq_rom_expect == 48:
                baud_rate = baud * 48 // 40
            else:
                ESPLoader.change_baud(self, baud_rate)
                return

            log.print(f"Changing baud rate to {baud_rate}...")
            self.command(
                self.ESP_CMDS["CHANGE_BAUDRATE"], struct.pack("<II", baud_rate, 0)
            )
            log.print("Changed.")
            self._set_port_baudrate(baud)
            time.sleep(0.05)  # get rid of garbage sent during baud rate change
            self.flush_input()
        else:
            ESPLoader.change_baud(self, baud)

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > self.EFUSE_MAX_KEY:
            raise FatalError(
                f"Valid key block numbers must be in range 0-{self.EFUSE_MAX_KEY}"
            )

        reg, shift = [
            (self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
            (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
            (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
            (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
            (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
            (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT),
        ][key_block]
        return (self.read_reg(reg) >> shift) & 0x1F

    def is_flash_encryption_key_valid(self):
        # Need to see an AES-128 key
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        return (
            self.read_reg(self.EFUSE_FORCE_USE_KEY_MANAGER_KEY_REG)
            >> self.EFUSE_FORCE_USE_KEY_MANAGER_KEY_SHIFT
        ) & self.FORCE_USE_KEY_MANAGER_VAL_XTS_AES_KEY

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 29))):
            raise FatalError("SPI Pin numbers must be in the range 0-28.")
        if any([v for v in spi_connection if v in [13, 14]]):
            log.warning(
                "GPIO pins 13 and 14 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )

    def watchdog_reset(self):
        # Watchdog reset disabled in parent (ESP32-C6) ROM, re-enable it
        ESP32C3ROM.watchdog_reset(self)


class ESP32C5StubLoader(StubMixin, ESP32C5ROM):
    """Stub loader for ESP32-C5, runs on top of ROM."""

    pass


ESP32C5ROM.STUB_CLASS = ESP32C5StubLoader
