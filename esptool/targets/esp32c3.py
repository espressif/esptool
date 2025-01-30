# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from time import sleep
from typing import Dict

from .esp32 import ESP32ROM
from ..loader import ESPLoader, StubMixin
from ..logger import log
from ..util import FatalError, NotImplementedInROMError


class ESP32C3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-C3"
    IMAGE_CHIP_ID = 5

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42800000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3C800000

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

    USES_MAGIC_VALUE = False

    BOOTLOADER_FLASH_OFFSET = 0x0

    UART_DATE_REG_ADDR = 0x60000000 + 0x7C

    UART_CLKDIV_REG = 0x60000014

    EFUSE_BASE = 0x60008800
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

    UARTDEV_BUF_NO = 0x3FCDF07C  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 3  # The above var when USB-JTAG/Serial is used

    RTCCNTL_BASE_REG = 0x60008000
    RTC_CNTL_SWD_CONF_REG = RTCCNTL_BASE_REG + 0x00AC
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 31
    RTC_CNTL_SWD_WPROTECT_REG = RTCCNTL_BASE_REG + 0x00B0
    RTC_CNTL_SWD_WKEY = 0x8F1D312A

    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0090
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x0094
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00A8
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3C000000, 0x3C800000, "DROM"],
        [0x3FC80000, 0x3FCE0000, "DRAM"],
        [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
        [0x3FF00000, 0x3FF20000, "DROM_MASK"],
        [0x40000000, 0x40060000, "IROM_MASK"],
        [0x42000000, 0x42800000, "IROM"],
        [0x4037C000, 0x403E0000, "IRAM"],
        [0x50000000, 0x50002000, "RTC_IRAM"],
        [0x50000000, 0x50002000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0xD42BA06C

    EFUSE_MAX_KEY = 5
    KEY_PURPOSES: Dict[int, str] = {
        0: "USER/EMPTY",
        1: "RESERVED",
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
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x07

    def get_minor_chip_version(self):
        hi_num_word = 5
        hi = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * hi_num_word)) >> 23) & 0x01
        low_num_word = 3
        low = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * low_num_word)) >> 18) & 0x07
        return (hi << 3) + low

    def get_major_chip_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x03

    def get_flash_cap(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 27) & 0x07

    def get_flash_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07
        return {1: "XMC", 2: "GD", 3: "FM", 4: "TT", 5: "ZBIT"}.get(vendor_id, "")

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C3 (QFN32)",
            1: "ESP8685 (QFN28)",
            2: "ESP32-C3 AZ (QFN32)",
            3: "ESP8686 (QFN24)",
        }.get(self.get_pkg_version(), "unknown ESP32-C3")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["WiFi", "BLE"]

        flash = {
            0: None,
            1: "Embedded Flash 4MB",
            2: "Embedded Flash 2MB",
            3: "Embedded Flash 1MB",
            4: "Embedded Flash 8MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if flash is not None:
            features += [flash + f" ({self.get_flash_vendor()})"]
        return features

    def get_crystal_freq(self):
        # ESP32C3 XTAL is fixed to 40MHz
        return 40

    def get_flash_voltage(self):
        pass  # not supported on ESP32-C3

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-C3"
        )

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-C3

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

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)

    def uses_usb_jtag_serial(self):
        """
        Check the UARTDEV_BUF_NO register to see if USB-JTAG/Serial is being used
        """
        if self.secure_download_mode:
            return False  # Can't detect USB-JTAG/Serial in secure download mode
        return self.get_uart_no() == self.UARTDEV_BUF_NO_USB_JTAG_SERIAL

    def disable_watchdogs(self):
        # When USB-JTAG/Serial is used, the RTC WDT and SWD watchdog are not reset
        # and can then reset the board during flashing. Disable or autofeed them.
        if self.uses_usb_jtag_serial():
            # Disable RTC WDT
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)
            self.write_reg(self.RTC_CNTL_WDTCONFIG0_REG, 0)
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)

            # Automatically feed SWD
            self.write_reg(self.RTC_CNTL_SWD_WPROTECT_REG, self.RTC_CNTL_SWD_WKEY)
            self.write_reg(
                self.RTC_CNTL_SWD_CONF_REG,
                self.read_reg(self.RTC_CNTL_SWD_CONF_REG)
                | self.RTC_CNTL_SWD_AUTO_FEED_EN,
            )
            self.write_reg(self.RTC_CNTL_SWD_WPROTECT_REG, 0)

    def _post_connect(self):
        if not self.sync_stub_detected:  # Don't run if stub is reused
            self.disable_watchdogs()

    def watchdog_reset(self):
        log.print("Hard resetting with a watchdog...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 2000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock
        sleep(0.5)  # wait for reset to take effect

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 22))):
            raise FatalError("SPI Pin numbers must be in the range 0-21.")
        if any([v for v in spi_connection if v in [18, 19]]):
            log.warning(
                "GPIO pins 18 and 19 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )


class ESP32C3StubLoader(StubMixin, ESP32C3ROM):
    """Stub loader for ESP32-C3, runs on top of ROM."""

    pass


ESP32C3ROM.STUB_CLASS = ESP32C3StubLoader
