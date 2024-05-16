# SPDX-FileCopyrightText: 2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct

from .esp32c3 import ESP32C3ROM
from ..util import FatalError, NotImplementedInROMError


class ESP32C6ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C6"
    IMAGE_CHIP_ID = 13

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42800000
    DROM_MAP_START = 0x42800000
    DROM_MAP_END = 0x43000000

    BOOTLOADER_FLASH_OFFSET = 0x0

    # Magic value for ESP32C6
    CHIP_DETECT_MAGIC_VALUE = [0x2CE0806F]

    SPI_REG_BASE = 0x60003000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    UART_DATE_REG_ADDR = 0x60000000 + 0x7C

    EFUSE_BASE = 0x600B0800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    PURPOSE_VAL_XTS_AES128_KEY = 4

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    UARTDEV_BUF_NO = 0x4087F580  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 3  # The above var when USB-JTAG/Serial is used

    DR_REG_LP_WDT_BASE = 0x600B1C00
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_RWDT_CONFIG0_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0018  # LP_WDT_RWDT_WPROTECT_REG

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x001C  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    FLASH_FREQUENCY = {
        "80m": 0x0,  # workaround for wrong mspi HS div value in ROM
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42800000, 0x43000000, "DROM"],
        [0x40800000, 0x40880000, "DRAM"],
        [0x40800000, 0x40880000, "BYTE_ACCESSIBLE"],
        [0x4004AC00, 0x40050000, "DROM_MASK"],
        [0x40000000, 0x4004AC00, "IROM_MASK"],
        [0x42000000, 0x42800000, "IROM"],
        [0x40800000, 0x40880000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0x540DDF62

    def get_pkg_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x07

    def get_minor_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x0F

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 22) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C6 (QFN40)",
            1: "ESP32-C6FH4 (QFN32)",
        }.get(self.get_pkg_version(), "unknown ESP32-C6")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["WiFi 6", "BT 5", "IEEE802.15.4"]

    def get_crystal_freq(self):
        # ESP32C6 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-C6"
        )

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        base_mac = struct.pack(">II", mac1, mac0)[2:]
        ext_mac = struct.pack(">H", (mac1 >> 16) & 0xFFFF)
        eui64 = base_mac[0:3] + ext_mac + base_mac[3:6]
        # BASE MAC: 60:55:f9:f7:2c:a2
        # EUI64 MAC: 60:55:f9:ff:fe:f7:2c:a2
        # EXT_MAC: ff:fe
        macs = {
            "BASE_MAC": tuple(base_mac),
            "EUI64": tuple(eui64),
            "MAC_EXT": tuple(ext_mac),
        }
        return macs.get(mac_type, None)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-C6

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

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
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see an AES-128 key
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        return any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes)

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 31))):
            raise FatalError("SPI Pin numbers must be in the range 0-30.")
        if any([v for v in spi_connection if v in [12, 13]]):
            print(
                "WARNING: GPIO pins 12 and 13 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )


class ESP32C6StubLoader(ESP32C6ROM):
    """Access class for ESP32C6 stub loader, runs on top of ROM.

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


ESP32C6ROM.STUB_CLASS = ESP32C6StubLoader
