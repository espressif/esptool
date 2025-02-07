# SPDX-FileCopyrightText: 2024-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later


from .esp32h2 import ESP32H2ROM
from ..loader import StubMixin
from ..logger import log
from ..util import FatalError


class ESP32H21ROM(ESP32H2ROM):
    CHIP_NAME = "ESP32-H21"
    IMAGE_CHIP_ID = 25

    UF2_FAMILY_ID = 0xB6DD00AF

    DR_REG_LP_WDT_BASE = 0x600B1C00
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_RWDT_CONFIG0_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x001C  # LP_WDT_RWDT_WPROTECT_REG

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x0020  # LP_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0024  # LP_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # LP_WDT_SWD_WKEY, same as WDT key in this case

    def get_pkg_version(self):
        return 0

    def get_minor_chip_version(self):
        return 0

    def get_major_chip_version(self):
        return 0

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-H21",
        }.get(self.get_pkg_version(), "unknown ESP32-H21")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["BLE", "IEEE802.15.4"]

    def get_crystal_freq(self):
        # ESP32H21 XTAL is fixed to 32MHz
        return 32

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 28))):
            raise FatalError("SPI Pin numbers must be in the range 0-27.")
        if any([v for v in spi_connection if v in [26, 27]]):
            log.warning(
                "GPIO pins 26 and 27 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )


class ESP32H21StubLoader(StubMixin, ESP32H21ROM):
    """Stub loader for ESP32-H21, runs on top of ROM."""

    pass


ESP32H21ROM.STUB_CLASS = ESP32H21StubLoader
