# SPDX-FileCopyrightText: 2024-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from time import sleep

from .esp32 import ESP32ROM
from ..loader import ESPLoader, StubMixin
from ..logger import log
from ..util import FatalError, NotSupportedError


class ESP32P4ROM(ESP32ROM):
    CHIP_NAME = "ESP32-P4"
    IMAGE_CHIP_ID = 18

    IROM_MAP_START = 0x40000000
    IROM_MAP_END = 0x4C000000
    DROM_MAP_START = 0x40000000
    DROM_MAP_END = 0x4C000000

    BOOTLOADER_FLASH_OFFSET = 0x2000  # First 2 sectors are reserved for FE purposes

    UART_DATE_REG_ADDR = 0x500CA000 + 0x8C

    EFUSE_BASE = 0x5012D000
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    MAC_EFUSE_REG = EFUSE_BASE + 0x044

    SPI_REG_BASE = 0x5008D000  # SPIMEM1
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

    USES_MAGIC_VALUE = False

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_FORCE_USE_KEY_MANAGER_KEY_REG = EFUSE_BASE + 0x34
    EFUSE_FORCE_USE_KEY_MANAGER_KEY_SHIFT = 9
    FORCE_USE_KEY_MANAGER_VAL_XTS_AES_KEY = 2

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

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x500E0038
    GPIO_STRAP_SPI_BOOT_MASK = 0x8  # Not download mode
    RTC_CNTL_OPTION1_REG = 0x50110008
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x4  # Is download mode forced over USB?

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    @property
    def UARTDEV_BUF_NO(self):
        """Variable .bss.UartDev.buff_uart_no in ROM .bss
        which indicates the port in use.
        """
        BUF_UART_NO_OFFSET = 24

        BSS_UART_DEV_ADDR = 0x4FF3FEB0 if self.get_chip_revision() < 300 else 0x4FFBFEB0
        return BSS_UART_DEV_ADDR + BUF_UART_NO_OFFSET

    # The value from UARTDEV_BUF_NO when USB-OTG is used
    UARTDEV_BUF_NO_USB_OTG = 5

    # The value from UARTDEV_BUF_NO when USB-JTAG/Serial is used
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 6

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x40000000, 0x4C000000, "DROM"],
        [0x4FF00000, 0x4FFA0000, "DRAM"],
        [0x4FF00000, 0x4FFA0000, "BYTE_ACCESSIBLE"],
        [0x4FC00000, 0x4FC20000, "DROM_MASK"],
        [0x4FC00000, 0x4FC20000, "IROM_MASK"],
        [0x40000000, 0x4C000000, "IROM"],
        [0x4FF00000, 0x4FFA0000, "IRAM"],
        [0x50108000, 0x50110000, "RTC_IRAM"],
        [0x50108000, 0x50110000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0x3D308E94

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

    DR_REG_LP_WDT_BASE = 0x50116000
    RTC_CNTL_WDTCONFIG0_REG = DR_REG_LP_WDT_BASE + 0x0  # LP_WDT_CONFIG0_REG
    RTC_CNTL_WDTCONFIG1_REG = DR_REG_LP_WDT_BASE + 0x0004  # LP_WDT_CONFIG1_REG
    RTC_CNTL_WDTWPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0018  # LP_WDT_WPROTECT_REG
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    RTC_CNTL_SWD_CONF_REG = DR_REG_LP_WDT_BASE + 0x001C  # RTC_WDT_SWD_CONFIG_REG
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 18
    RTC_CNTL_SWD_WPROTECT_REG = DR_REG_LP_WDT_BASE + 0x0020  # RTC_WDT_SWD_WPROTECT_REG
    RTC_CNTL_SWD_WKEY = 0x50D83AA1  # RTC_WDT_SWD_WKEY, same as WDT key in this case

    def get_pkg_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 20) & 0x07

    def get_minor_chip_version(self):
        num_word = 2
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_major_chip_version(self):
        num_word = 2
        word = self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word))
        return (((word >> 23) & 1) << 2) | ((word >> 4) & 0x03)

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-P4",
        }.get(self.get_pkg_version(), "Unknown ESP32-P4")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["Dual Core + LP Core", "400MHz"]

    def get_crystal_freq(self):
        # ESP32P4 XTAL is fixed to 40MHz
        return 40

    def get_flash_voltage(self):
        raise NotSupportedError(self, "Reading flash voltage")

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
        return None  # doesn't exist on ESP32-P4

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
        # Need to see either an AES-128 key or two AES-256 keys
        purposes = [
            self.get_key_block_purpose(b) for b in range(self.EFUSE_MAX_KEY + 1)
        ]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        if any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        ):
            return True

        return (
            self.read_reg(self.EFUSE_FORCE_USE_KEY_MANAGER_KEY_REG)
            >> self.EFUSE_FORCE_USE_KEY_MANAGER_KEY_SHIFT
        ) & self.FORCE_USE_KEY_MANAGER_VAL_XTS_AES_KEY

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)

    def _post_connect(self):
        if self.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
        if not self.sync_stub_detected:  # Don't run if stub is reused
            self.disable_watchdogs()

    def uses_usb_otg(self):
        """
        Check the UARTDEV_BUF_NO register to see if USB-OTG console is being used
        """
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        return self.get_uart_no() == self.UARTDEV_BUF_NO_USB_OTG

    def uses_usb_jtag_serial(self):
        """
        Check the UARTDEV_BUF_NO register to see if USB-JTAG/Serial is being used
        """
        if self.secure_download_mode:
            return False  # can't detect USB-JTAG/Serial in secure download mode
        return self.get_uart_no() == self.UARTDEV_BUF_NO_USB_JTAG_SERIAL

    def disable_watchdogs(self):
        # When USB-JTAG/Serial is used, the RTC WDT and SWD watchdog are not reset
        # and can then reset the board during flashing. Disable them.
        if self.uses_usb_jtag_serial():
            # Disable RTC WDT
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_SWD_WKEY)
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

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 55))):
            raise FatalError("SPI Pin numbers must be in the range 0-54.")
        if any([v for v in spi_connection if v in [24, 25]]):
            log.warning(
                "GPIO pins 24 and 25 are used by USB-Serial/JTAG, "
                "consider using other pins for SPI flash connection."
            )

    def watchdog_reset(self):
        log.print("Hard resetting with a watchdog...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 2000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock
        sleep(0.5)  # wait for reset to take effect

    def hard_reset(self):
        if self.uses_usb_otg():
            self.watchdog_reset()
        else:
            ESPLoader.hard_reset(self)


class ESP32P4StubLoader(StubMixin, ESP32P4ROM):
    """Stub loader for ESP32-P4, runs on top of ROM."""

    def __init__(self, rom_loader):
        super().__init__(rom_loader)  # Initialize the mixin
        if rom_loader.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
            self.FLASH_WRITE_SIZE = self.USB_RAM_BLOCK

    def stub_json_name(self):
        if self.get_chip_revision() < 300:
            return "esp32p4rc1.json"
        return "esp32p4.json"


ESP32P4ROM.STUB_CLASS = ESP32P4StubLoader
