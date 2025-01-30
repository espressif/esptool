# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from ..loader import ESPLoader, StubMixin
from ..util import FatalError, NotSupportedError


class ESP8266ROM(ESPLoader):
    """Access class for ESP8266 ROM bootloader"""

    CHIP_NAME = "ESP8266"
    IS_STUB = False

    MAGIC_VALUE = 0xFFF0C101

    # OTP ROM addresses
    ESP_OTP_MAC0 = 0x3FF00050
    ESP_OTP_MAC1 = 0x3FF00054
    ESP_OTP_MAC3 = 0x3FF0005C

    SPI_REG_BASE = 0x60000200
    SPI_USR_OFFS = 0x1C
    SPI_USR1_OFFS = 0x20
    SPI_USR2_OFFS = 0x24
    SPI_MOSI_DLEN_OFFS = None
    SPI_MISO_DLEN_OFFS = None
    SPI_W0_OFFS = 0x40

    UART_CLKDIV_REG = 0x60000014

    XTAL_CLK_DIVIDER = 2

    FLASH_SIZES = {
        "512KB": 0x00,
        "256KB": 0x10,
        "1MB": 0x20,
        "2MB": 0x30,
        "4MB": 0x40,
        "2MB-c1": 0x50,
        "4MB-c1": 0x60,
        "8MB": 0x80,
        "16MB": 0x90,
    }

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "26m": 0x1,
        "20m": 0x2,
    }

    BOOTLOADER_FLASH_OFFSET = 0

    MEMORY_MAP = [
        [0x3FF00000, 0x3FF00010, "DPORT"],
        [0x3FFE8000, 0x40000000, "DRAM"],
        [0x40100000, 0x40108000, "IRAM"],
        [0x40201010, 0x402E1010, "IROM"],
    ]

    UF2_FAMILY_ID = 0x7EAB61ED

    def get_efuses(self):
        # Return the 128 bits of ESP8266 efuse as a single Python integer
        result = self.read_reg(0x3FF0005C) << 96
        result |= self.read_reg(0x3FF00058) << 64
        result |= self.read_reg(0x3FF00054) << 32
        result |= self.read_reg(0x3FF00050)
        return result

    def _get_flash_size(self, efuses):
        # rX_Y = EFUSE_DATA_OUTX[Y]
        r0_4 = (efuses & (1 << 4)) != 0
        r3_25 = (efuses & (1 << 121)) != 0
        r3_26 = (efuses & (1 << 122)) != 0
        r3_27 = (efuses & (1 << 123)) != 0

        if r0_4 and not r3_25:
            if not r3_27 and not r3_26:
                return 1
            elif not r3_27 and r3_26:
                return 2
        if not r0_4 and r3_25:
            if not r3_27 and not r3_26:
                return 2
            elif not r3_27 and r3_26:
                return 4
        return -1

    def get_chip_description(self):
        efuses = self.get_efuses()
        is_8285 = (
            efuses & ((1 << 4) | 1 << 80)
        ) != 0  # One or the other efuse bit is set for ESP8285
        if is_8285:
            flash_size = self._get_flash_size(efuses)
            max_temp = (
                efuses & (1 << 5)
            ) != 0  # This efuse bit identifies the max flash temperature
            chip_name = {
                1: "ESP8285H08" if max_temp else "ESP8285N08",
                2: "ESP8285H16" if max_temp else "ESP8285N16",
            }.get(flash_size, "ESP8285")
            return chip_name
        return "ESP8266EX"

    def get_chip_features(self):
        features = ["WiFi"]
        if "ESP8285" in self.get_chip_description():
            features += ["Embedded Flash"]
        return features

    def flash_spi_attach(self, hspi_arg):
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_spi_attach(hspi_arg)
        else:
            # ESP8266 ROM has no flash_spi_attach command in serial protocol,
            # but flash_begin will do it
            self.flash_begin(0, 0)

    def flash_set_parameters(self, size):
        # not implemented in ROM, but OK to silently skip for ROM
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_set_parameters(size)

    def chip_id(self):
        """
        Read Chip ID from efuse - the equivalent of the SDK system_get_chip_id() func
        """
        id0 = self.read_reg(self.ESP_OTP_MAC0)
        id1 = self.read_reg(self.ESP_OTP_MAC1)
        return (id0 >> 24) | ((id1 & 0xFFFFFF) << 8)

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from OTP ROM"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.ESP_OTP_MAC0)
        mac1 = self.read_reg(self.ESP_OTP_MAC1)
        mac3 = self.read_reg(self.ESP_OTP_MAC3)
        if mac3 != 0:
            oui = ((mac3 >> 16) & 0xFF, (mac3 >> 8) & 0xFF, mac3 & 0xFF)
        elif ((mac1 >> 16) & 0xFF) == 0:
            oui = (0x18, 0xFE, 0x34)
        elif ((mac1 >> 16) & 0xFF) == 1:
            oui = (0xAC, 0xD0, 0x74)
        else:
            raise FatalError("Unknown OUI")
        return oui + ((mac1 >> 8) & 0xFF, mac1 & 0xFF, (mac0 >> 24) & 0xFF)

    def get_erase_size(self, offset, size):
        """Calculate an erase size given a specific size in bytes.

        Provides a workaround for the bootloader erase bug."""

        sectors_per_block = 16
        sector_size = self.FLASH_SECTOR_SIZE
        num_sectors = (size + sector_size - 1) // sector_size
        start_sector = offset // sector_size

        head_sectors = sectors_per_block - (start_sector % sectors_per_block)
        if num_sectors < head_sectors:
            head_sectors = num_sectors

        if num_sectors < 2 * head_sectors:
            return (num_sectors + 1) // 2 * sector_size
        else:
            return (num_sectors - head_sectors) * sector_size

    def get_flash_voltage(self):
        pass  # not supported on ESP8266

    def override_vddsdio(self, new_voltage):
        raise NotSupportedError(self, "Overriding VDDSDIO")

    def check_spi_connection(self, spi_connection):
        raise NotSupportedError(self, "Setting --spi-connection")

    def get_secure_boot_enabled(self):
        return False  # ESP8266 doesn't have security features


class ESP8266StubLoader(StubMixin, ESP8266ROM):
    """Stub loader for ESP8266, runs on top of ROM."""

    def get_erase_size(self, offset, size):
        return size  # stub doesn't have same size bug as ROM loader


ESP8266ROM.STUB_CLASS = ESP8266StubLoader
