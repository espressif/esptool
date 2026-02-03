# SPDX-FileCopyrightText: 2026 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct

from .esp32 import ESP32ROM
from ..loader import ESPLoader, StubMixin
from ..logger import log
from ..util import FatalError, NotSupportedError


class ESP32E22ROM(ESP32ROM):
    CHIP_NAME = "ESP32-E22"
    IMAGE_CHIP_ID = 31

    IROM_MAP_START = 0x3C000000
    IROM_MAP_END = 0x40000000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x40000000

    BOOTLOADER_FLASH_OFFSET = 0x0

    UART_DATE_REG_ADDR = 0xC3102000 + 0x8C
    UART_CLKDIV_REG = 0xC3102000 + 0x14

    EFUSE_BASE = 0xC4008000
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    SPI_REG_BASE = 0xC3003000  # SPIMEM1
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

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

    # TODO Fields are not present in efuse table.
    # EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    # EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20
    # EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    # EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    USES_MAGIC_VALUE = False

    UARTDEV_BUF_NO = 0x3111B700  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_OTG = 3  # The above var when USB-OTG is used

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0xC310D000
    GPIO_STRAP_SPI_BOOT_MASK = 1 << 3  # Not download mode
    RTC_CNTL_OPTION1_REG = 0x3F408128
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3C000000, 0x40000000, "DROM"],
        [0x31000000, 0x31200000, "DRAM"],
        [0x31000000, 0x31200000, "BYTE_ACCESSIBLE"],
        [0x30000000, 0x30120000, "DROM_MASK"],
        [0x30000000, 0x30120000, "IROM_MASK"],
        [0x3C000000, 0x40000000, "IROM"],
        [0x30FE0000, 0x31200000, "IRAM"],
        [0xC0000000, 0xC0008000, "RTC_IRAM"],
        [0xC0000000, 0xC0008000, "RTC_DRAM"],
        # [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    KEY_PURPOSES: dict[int, str] = {
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
    }

    def get_pkg_version(self):
        # TODO: It is not yet allocated in efuse table.
        return 0

    def get_minor_chip_version(self):
        # TODO: It is not yet allocated in efuse table.
        return 0

    def get_major_chip_version(self):
        # TODO: It is not yet allocated in efuse table.
        return 0

    def get_encrypted_download_disabled(self):
        # TODO: DIS_DOWNLOAD_MANUAL_ENCRYPT is not yet allocated in efuse table.
        return 0

    def get_flash_encryption_enabled(self):
        # TODO: SPI_BOOT_CRYPT_CNT is not yet allocated in efuse table.
        return 0

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-E22",
        }.get(self.get_pkg_version(), "unknown ESP32-E22")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return [
            "Wi-Fi 6E (tri-band, 2x2 MU-MIMO)",
            "BT 5.4 (LE) + Classic",
            "Dual Core",
            "500MHz",
        ]

    def get_crystal_freq(self):
        return ESPLoader.get_crystal_freq(self)

    def get_flash_voltage(self):
        pass  # not supported on ESP32-E22

    def override_vddsdio(self, new_voltage):
        raise NotSupportedError(self, "Overriding VDDSDIO")

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-E22

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

    def get_secure_boot_v1_enabled(self):
        # Secure Boot V1 is only supported on ESP32, not on ESP32-E22
        return False

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

    def is_flash_encryption_key_valid(self):  # TODO: FE exists?
        # Need to see either an AES-128 key or two AES-256 keys
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        )

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)

    def uses_usb_otg(self):
        """
        Check the UARTDEV_BUF_NO register to see if USB-OTG console is being used
        """
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        return self.get_uart_no() == self.UARTDEV_BUF_NO_USB_OTG

    def check_spi_connection(self, spi_connection):  # TODO: Check pins
        if not set(spi_connection).issubset(set(range(0, 53))):
            raise FatalError("SPI Pin numbers must be in the range 0-52.")
        if any([v for v in spi_connection if v in [18, 19]]):
            log.warning(
                "GPIO pins 18 and 19 are used by USB-OTG, "
                "consider using other pins for SPI flash connection."
            )

    # Watchdog reset is not supported on ESP32-E22
    def watchdog_reset(self):
        ESPLoader.watchdog_reset(self)

    def hard_reset(self):
        uses_usb_otg = self.uses_usb_otg()
        if uses_usb_otg:
            # Check the strapping register to see if we can perform a watchdog reset
            strap_reg = self.read_reg(self.GPIO_STRAP_REG)
            force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
            if (
                strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0  # GPIO0 low
                and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0
            ):
                self.watchdog_reset()
                return

        ESPLoader.hard_reset(self)


class ESP32E22StubLoader(StubMixin, ESP32E22ROM):
    """Stub loader for ESP32-E22, runs on top of ROM."""

    def __init__(self, rom_loader):
        super().__init__(rom_loader)  # Initialize the mixin
        if rom_loader.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
            self.FLASH_WRITE_SIZE = self.USB_RAM_BLOCK


ESP32E22ROM.STUB_CLASS = ESP32E22StubLoader
