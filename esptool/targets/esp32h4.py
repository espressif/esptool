# SPDX-FileCopyrightText: 2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct

from ..loader import ESPLoader, StubMixin
from ..util import FatalError
from .esp32c3 import ESP32C3ROM


class ESP32H4ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-H4"
    IMAGE_CHIP_ID = 28

    USB_OTG_SUPPORTED = False
    USB_SERIAL_JTAG_SUPPORTED = True
    WATCHDOG_RESET_SUPPORTED = False
    SECURITY_INFO_SUPPORTED = True
    CUSTOM_SPI_FLASH_PINS_SUPPORTED = False
    USES_MAGIC_VALUE = False

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x44000000
    DROM_MAP_START = 0x42000000
    DROM_MAP_END = 0x44000000

    BOOTLOADER_FLASH_OFFSET = 0x2000

    SPI_REG_BASE = 0x60099000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    UART_CLKDIV_REG = 0x60012000 + 0x14
    UART_DATE_REG_ADDR = 0x60012000 + 0x8C

    EFUSE_BASE = 0x600B1800
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 0
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 5
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY2_SHIFT = 10
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY3_SHIFT = 15
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY4_SHIFT = 20
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY5_SHIFT = 25

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 14

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x030
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 23

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 5

    EFUSE_FORCE_USE_KM_KEY_REG = EFUSE_BASE + 0x038
    EFUSE_FORCE_USE_KM_KEY_MASK = 0xF << 19

    EFUSE_FORCE_USE_KEY_MANAGER_KEY_REG = EFUSE_BASE + 0x038
    EFUSE_FORCE_USE_KEY_MANAGER_KEY_SHIFT = 19
    FORCE_USE_KEY_MANAGER_VAL_XTS_AES_KEY = 2

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    DR_REG_TIMG_BASE = 0x60090000
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_TIMG_BASE + 0x48  # TIMG_WDTCONFIG0_REG
    RTC_CNTL_WDTCONFIG1_REG = DR_REG_TIMG_BASE + 0x4C  # TIMG_WDTCONFIG1_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_TIMG_BASE + 0x64  # TIMG_WDTWPROTECT_REG

    DR_REG_LP_WDT_BASE = 0x600B5400
    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0024  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    PCR_SYSCLK_CONF_REG = 0x60094114
    PCR_SYSCLK_XTAL_FREQ_V = 0x7F << 24
    PCR_SYSCLK_XTAL_FREQ_S = 24

    # Labels are wrong: the 2nd stage bootloader uses a 64 MHz source, so 0xF runs at
    # 64 MHz and 0x0 at 32 MHz. Kept because ESP-IDF remaps 64M/32M to 48m/24m.
    FLASH_FREQUENCY = {
        "48m": 0xF,
        "24m": 0x0,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42000000, 0x44000000, "DROM"],
        [0x40810000, 0x40860000, "DRAM"],
        [0x40810000, 0x40860000, "BYTE_ACCESSIBLE"],
        [0x40000000, 0x40020000, "DROM_MASK"],
        [0x40000000, 0x40020000, "IROM_MASK"],
        [0x42000000, 0x44000000, "IROM"],
        [0x40810000, 0x40860000, "IRAM"],
        [0x40810000, 0x40860000, "MEM_INTERNAL"],
    ]

    UF2_FAMILY_ID = 0x9E0BAA8A

    KEY_PURPOSES: dict[int, str] = {
        0: "USER/EMPTY",
        1: "ECDSA_KEY",  # ECDSA_KEY_P256 (NIST P-256)
        2: "XTS_AES_256_KEY_FLASH_1",
        3: "XTS_AES_256_KEY_FLASH_2",
        4: "XTS_AES_128_KEY",
        5: "HMAC_DOWN_ALL",
        6: "HMAC_DOWN_JTAG",
        7: "HMAC_DOWN_DIGITAL_SIGNATURE",
        8: "HMAC_UP",
        9: "SECURE_BOOT_DIGEST0",
        10: "SECURE_BOOT_DIGEST1",
        11: "SECURE_BOOT_DIGEST2",
        12: "KM_INIT_KEY",
        13: "XTS_AES_256_KEY_PSRAM_1",
        14: "XTS_AES_256_KEY_PSRAM_2",
        15: "XTS_AES_128_KEY_PSRAM",
        16: "ECDSA_KEY_P192",
        17: "ECDSA_KEY_P384_L",
        18: "ECDSA_KEY_P384_H",
    }

    def get_pkg_version(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 12) & 0x07

    def get_flash_cap(self):
        # FLASH_CAP spans BLOCK1 words 3 and 4.
        word3 = self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * 3))
        word4 = self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * 4))
        return ((word3 >> 31) | ((word4 & 0x03) << 1)) & 0x07

    def get_flash_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 2) & 0x07
        return {1: "FM", 2: "XMC", 3: "PY"}.get(vendor_id, "")

    def get_psram_cap(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 5) & 0x07

    def get_psram_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 8) & 0x03
        return {1: "AP"}.get(vendor_id, "")

    def get_temp(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 10) & 0x03

    def get_minor_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x0F

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 22) & 0x03

    def get_chip_description(self):
        # ESP32-H4 + temperature + in-package flash + PSRAM
        chip_name = "ESP32-H4"
        chip_name += {1: "H"}.get(self.get_temp(), "?")
        flash = {0: "", 1: "F4"}.get(self.get_flash_cap(), "F?")
        if flash == "F4" and self.get_flash_vendor() == "PY":
            flash = "FL4"
        chip_name += flash
        chip_name += {0: "", 1: "R8", 2: "R2"}.get(self.get_psram_cap(), "R?")

        if "?" in chip_name:
            chip_name = "Unknown " + chip_name

        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["BT 5 (LE)", "IEEE802.15.4", "Dual Core", "96MHz"]

        flash_version = {
            0: "No Embedded Flash",
            1: "Embedded Flash 4MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if self.get_flash_cap() == 1:
            flash_version += f" ({self.get_flash_vendor()})"
        features += [flash_version]

        psram_version = {
            0: "No Embedded PSRAM",
            1: "Embedded PSRAM 8MB",
            2: "Embedded PSRAM 2MB",
        }.get(self.get_psram_cap(), "Unknown Embedded PSRAM")
        if self.get_psram_cap() in (1, 2):
            psram_version += f" ({self.get_psram_vendor()})"
        features += [psram_version]

        return features

    def get_crystal_freq(self):
        # ESP32H4 XTAL is fixed to 32MHz
        return 32

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)

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
        return None  # doesn't exist on ESP32-H4

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
        return (self.read_reg(reg) >> shift) & 0x1F

    def uses_key_manager_for_flash_encryption(self):
        return bool(
            (
                self.read_reg(self.EFUSE_FORCE_USE_KEY_MANAGER_KEY_REG)
                >> self.EFUSE_FORCE_USE_KEY_MANAGER_KEY_SHIFT
            )
            & self.FORCE_USE_KEY_MANAGER_VAL_XTS_AES_KEY
        )

    def is_flash_encryption_key_valid(self):
        # Need to see an AES-128 key or both AES-256 flash key halves.
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        if any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        ):
            return True

        return self.uses_key_manager_for_flash_encryption()

    # Watchdog reset is not supported on ESP32-H4
    def watchdog_reset(self):
        ESPLoader.watchdog_reset(self)


class ESP32H4StubLoader(StubMixin, ESP32H4ROM):
    """Stub loader for ESP32-H4, runs on top of ROM."""

    pass


ESP32H4ROM.STUB_CLASS = ESP32H4StubLoader
