# SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from typing import Dict

from .esp32c6 import ESP32C6ROM


class ESP32C61ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-C61"
    IMAGE_CHIP_ID = 20

    UART_DATE_REG_ADDR = 0x60000000 + 0x7C

    EFUSE_BASE = 0x600B4800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 0
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 4
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY2_SHIFT = 8
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY3_SHIFT = 12
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY4_SHIFT = 16
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY5_SHIFT = 20

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x030
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 23

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x034
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 26

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
        [0x4004AC00, 0x40050000, "DROM_MASK"],
        [0x40000000, 0x4004AC00, "IROM_MASK"],
        [0x42000000, 0x44000000, "IROM"],
        [0x40800000, 0x40860000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0x77D850C4

    EFUSE_MAX_KEY = 5
    KEY_PURPOSES: Dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",
        2: "XTS_AES_256_KEY_1",
        3: "XTS_AES_256_KEY_2",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
        12: "KM_INIT_KEY",
        13: "XTS_AES_256_KEY_1_PSRAM",
        14: "XTS_AES_256_KEY_2_PSRAM",
        15: "XTS_AES_128_KEY_PSRAM",
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
            0: "ESP32-C61",
        }.get(self.get_pkg_version(), "unknown ESP32-C61")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["WiFi 6", "BT 5"]

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        base_mac = struct.pack(">II", mac1, mac0)[2:]
        # BASE MAC: 60:55:f9:f7:2c:a2
        macs = {
            "BASE_MAC": tuple(base_mac),
        }
        return macs.get(mac_type, None)


class ESP32C61StubLoader(ESP32C61ROM):
    """Access class for ESP32C61 stub loader, runs on top of ROM.

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
        self.cache = rom_loader.cache
        self.flush_input()  # resets _slip_reader


ESP32C61ROM.STUB_CLASS = ESP32C61StubLoader
