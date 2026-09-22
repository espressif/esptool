# SPDX-FileCopyrightText: 2024-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from ..loader import StubMixin
from .esp32h2 import ESP32H2ROM


class ESP32H21ROM(ESP32H2ROM):
    CHIP_NAME = "ESP32-H21"
    IMAGE_CHIP_ID = 25

    USB_OTG_SUPPORTED = False
    USB_SERIAL_JTAG_SUPPORTED = True
    WATCHDOG_RESET_SUPPORTED = False
    SECURITY_INFO_SUPPORTED = True
    CUSTOM_SPI_FLASH_PINS_SUPPORTED = False
    USES_MAGIC_VALUE = False

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x43000000
    DROM_MAP_START = 0x42000000
    DROM_MAP_END = 0x43000000

    UART_DATE_REG_ADDR = 0x60000000 + 0x8C

    FLASH_FREQUENCY = {
        "48m": 0xF,
        "24m": 0x0,
    }

    PCR_SYSCLK_CONF_REG = 0x6009610C
    PCR_SYSCLK_XTAL_FREQ_V = 0x7F << 24
    PCR_SYSCLK_XTAL_FREQ_S = 24

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42000000, 0x43000000, "DROM"],
        [0x40800000, 0x40850000, "DRAM"],
        [0x40800000, 0x40850000, "BYTE_ACCESSIBLE"],
        [0x40000000, 0x40020000, "DROM_MASK"],
        [0x40000000, 0x40020000, "IROM_MASK"],
        [0x42000000, 0x43000000, "IROM"],
        [0x40800000, 0x40850000, "IRAM"],
        [0x50000000, 0x50001000, "RTC_IRAM"],
        [0x50000000, 0x50001000, "RTC_DRAM"],
        [0x40800000, 0x40850000, "MEM_INTERNAL"],
    ]

    UF2_FAMILY_ID = 0xB6DD00AF

    DR_REG_LP_WDT_BASE = 0x600B1C00
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_RWDT_CONFIG0_REG
    RTC_CNTL_WDTCONFIG1_REG = DR_REG_LP_WDT_BASE + 0x0004  # LP_WDT_RWDT_CONFIG1_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x001C  # LP_WDT_RWDT_WPROTECT_REG
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0024  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    EFUSE_BASE = 0x600B4000
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

    KEY_PURPOSES: dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",
        2: "RESERVED",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
    }

    def get_pkg_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 11) & 0x07

    def get_minor_chip_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 4) & 0x0F

    def get_major_chip_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 8) & 0x03

    def get_flash_cap(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x07

    def get_flash_vendor(self):
        num_word = 3
        vendor_id = (
            self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 27
        ) & 0x07
        return {1: "FM", 2: "XMC"}.get(vendor_id, "")

    def get_temp(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 30) & 0x03

    def get_chip_description(self):
        chip_name = "ESP32-H21"
        chip_name += {0: "N", 1: "H"}.get(self.get_temp(), "?")
        chip_name += {0: "", 1: "F4", 2: "F2"}.get(self.get_flash_cap(), "F?")

        if "?" in chip_name:
            chip_name = "Unknown " + chip_name
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["BT 5 (LE)", "IEEE802.15.4", "Single Core", "96MHz"]

        flash = {
            0: None,
            1: "Embedded Flash 4MB",
            2: "Embedded Flash 2MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if flash is not None:
            features += [flash + f" ({self.get_flash_vendor()})"]
        return features

    def get_crystal_freq(self):
        # ESP32H21 XTAL is fixed to 32MHz
        return 32


class ESP32H21StubLoader(StubMixin, ESP32H21ROM):
    """Stub loader for ESP32-H21, runs on top of ROM."""

    pass


ESP32H21ROM.STUB_CLASS = ESP32H21StubLoader
