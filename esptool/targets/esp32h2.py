# SPDX-FileCopyrightText: 2024 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Dict

from .esp32c6 import ESP32C6ROM
from ..loader import ESPLoader
from ..util import FatalError


class ESP32H2ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-H2"
    IMAGE_CHIP_ID = 16

    DR_REG_LP_WDT_BASE = 0x600B1C00
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_RWDT_CONFIG0_REG
    RTC_CNTL_WDTCONFIG1_REG = DR_REG_LP_WDT_BASE + 0x0004  # LP_WDT_RWDT_CONFIG1_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x001C  # LP_WDT_RWDT_WPROTECT_REG

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0024  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    UARTDEV_BUF_NO = 0x4084FEFC  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 3  # The above var when USB-JTAG/Serial is used

    FLASH_FREQUENCY = {
        "48m": 0xF,
        "24m": 0x0,
        "16m": 0x1,
        "12m": 0x2,
    }

    UF2_FAMILY_ID = 0x332726F6

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
    }

    def get_pkg_version(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07

    def get_minor_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x07

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x03

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-H2",
        }.get(self.get_pkg_version(), "unknown ESP32-H2")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["BLE", "IEEE802.15.4"]

    def get_crystal_freq(self):
        # ESP32H2 XTAL is fixed to 32MHz
        return 32

    # Watchdog reset is not supported on ESP32-H2
    def watchdog_reset(self):
        ESPLoader.watchdog_reset(self)

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 28))):
            raise FatalError("SPI Pin numbers must be in the range 0-27.")
        if any([v for v in spi_connection if v in [26, 27]]):
            print(
                "WARNING: GPIO pins 26 and 27 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )


class ESP32H2StubLoader(ESP32H2ROM):
    """Access class for ESP32H2 stub loader, runs on top of ROM.

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


ESP32H2ROM.STUB_CLASS = ESP32H2StubLoader
