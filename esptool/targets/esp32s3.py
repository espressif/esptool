# SPDX-FileCopyrightText: 2014-2024 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from typing import Dict

from .esp32 import ESP32ROM
from ..loader import ESPLoader
from ..util import FatalError, NotImplementedInROMError


class ESP32S3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S3"

    IMAGE_CHIP_ID = 9

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x44000000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3E000000

    UART_DATE_REG_ADDR = 0x60000080

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

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    # todo: use espefuse APIs to get this info
    EFUSE_BASE = 0x60007000  # BLOCK0 read base address
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x44
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x5C
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

    EFUSE_RD_REPEAT_DATA3_REG = EFUSE_BASE + 0x3C
    EFUSE_RD_REPEAT_DATA3_REG_FLASH_TYPE_MASK = 1 << 9

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    UARTDEV_BUF_NO = 0x3FCEF14C  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_OTG = 3  # The above var when USB-OTG is used
    UARTDEV_BUF_NO_USB_JTAG_SERIAL = 4  # The above var when USB-JTAG/Serial is used

    RTCCNTL_BASE_REG = 0x60008000
    RTC_CNTL_SWD_CONF_REG = RTCCNTL_BASE_REG + 0x00B4
    RTC_CNTL_SWD_AUTO_FEED_EN = 1 << 31
    RTC_CNTL_SWD_WPROTECT_REG = RTCCNTL_BASE_REG + 0x00B8
    RTC_CNTL_SWD_WKEY = 0x8F1D312A

    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0098
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x009C
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00B0
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x60004038
    GPIO_STRAP_SPI_BOOT_MASK = 1 << 3  # Not download mode
    GPIO_STRAP_VDDSPI_MASK = 1 << 4
    RTC_CNTL_OPTION1_REG = 0x6000812C
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

    UART_CLKDIV_REG = 0x60000014

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3C000000, 0x3D000000, "DROM"],
        [0x3D000000, 0x3E000000, "EXTRAM_DATA"],
        [0x600FE000, 0x60100000, "RTC_DRAM"],
        [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
        [0x3FC88000, 0x403E2000, "MEM_INTERNAL"],
        [0x3FC88000, 0x3FD00000, "DRAM"],
        [0x40000000, 0x4001A100, "IROM_MASK"],
        [0x40370000, 0x403E0000, "IRAM"],
        [0x600FE000, 0x60100000, "RTC_IRAM"],
        [0x42000000, 0x42800000, "IROM"],
        [0x50000000, 0x50002000, "RTC_DATA"],
    ]

    EFUSE_VDD_SPI_REG = EFUSE_BASE + 0x34
    VDD_SPI_XPD = 1 << 4
    VDD_SPI_TIEH = 1 << 5
    VDD_SPI_FORCE = 1 << 6

    UF2_FAMILY_ID = 0xC47E5767

    EFUSE_MAX_KEY = 5
    KEY_PURPOSES: Dict[int, str] = {
        0: "USER/EMPTY",
        1: "RESERVED",
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
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x07

    def is_eco0(self, minor_raw):
        # Workaround: The major version field was allocated to other purposes
        # when block version is v1.1.
        # Luckily only chip v0.0 have this kind of block version and efuse usage.
        return (
            (minor_raw & 0x7) == 0
            and self.get_blk_version_major() == 1
            and self.get_blk_version_minor() == 1
        )

    def get_minor_chip_version(self):
        minor_raw = self.get_raw_minor_chip_version()
        if self.is_eco0(minor_raw):
            return 0
        return minor_raw

    def get_raw_minor_chip_version(self):
        hi_num_word = 5
        hi = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * hi_num_word)) >> 23) & 0x01
        low_num_word = 3
        low = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * low_num_word)) >> 18) & 0x07
        return (hi << 3) + low

    def get_blk_version_major(self):
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 0) & 0x03

    def get_blk_version_minor(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x07

    def get_major_chip_version(self):
        minor_raw = self.get_raw_minor_chip_version()
        if self.is_eco0(minor_raw):
            return 0
        return self.get_raw_major_chip_version()

    def get_raw_major_chip_version(self):
        num_word = 5
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 24) & 0x03

    def get_chip_description(self):
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        pkg_version = self.get_pkg_version()

        chip_name = {
            0: "ESP32-S3 (QFN56)",
            1: "ESP32-S3-PICO-1 (LGA56)",
        }.get(pkg_version, "unknown ESP32-S3")

        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_flash_cap(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 27) & 0x07

    def get_flash_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x07
        return {1: "XMC", 2: "GD", 3: "FM", 4: "TT", 5: "BY"}.get(vendor_id, "")

    def get_psram_cap(self):
        num_word = 4
        psram_cap = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 3) & 0x03
        num_word = 5
        psram_cap_hi_bit = (
            self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 19
        ) & 0x01
        return (psram_cap_hi_bit << 2) | psram_cap

    def get_psram_vendor(self):
        num_word = 4
        vendor_id = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 7) & 0x03
        return {1: "AP_3v3", 2: "AP_1v8"}.get(vendor_id, "")

    def get_chip_features(self):
        features = ["WiFi", "BLE"]

        flash = {
            0: None,
            1: "Embedded Flash 8MB",
            2: "Embedded Flash 4MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        if flash is not None:
            features += [flash + f" ({self.get_flash_vendor()})"]

        psram = {
            0: None,
            1: "Embedded PSRAM 8MB",
            2: "Embedded PSRAM 2MB",
            3: "Embedded PSRAM 16MB",
            4: "Embedded PSRAM 4MB",
        }.get(self.get_psram_cap(), "Unknown Embedded PSRAM")
        if psram is not None:
            features += [psram + f" ({self.get_psram_vendor()})"]

        return features

    def get_crystal_freq(self):
        # ESP32S3 XTAL is fixed to 40MHz
        return 40

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-S3

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

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        )

    def get_secure_boot_enabled(self):
        return (
            self.read_reg(self.EFUSE_SECURE_BOOT_EN_REG)
            & self.EFUSE_SECURE_BOOT_EN_MASK
        )

    def _get_rtc_cntl_flash_voltage(self):
        return None  # not supported on ESP32-S3

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-S3"
        )

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        return tuple(bitstring)

    def flash_type(self):
        return (
            1
            if self.read_reg(self.EFUSE_RD_REPEAT_DATA3_REG)
            & self.EFUSE_RD_REPEAT_DATA3_REG_FLASH_TYPE_MASK
            else 0
        )

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
        if self.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
        if not self.sync_stub_detected:  # Don't run if stub is reused
            self.disable_watchdogs()

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock

    def hard_reset(self):
        try:
            # Clear force download boot mode to avoid the chip being stuck in download mode after reset
            # workaround for issue: https://github.com/espressif/arduino-esp32/issues/6762
            self.write_reg(
                self.RTC_CNTL_OPTION1_REG, 0, self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK
            )
        except Exception:
            # Skip if response was not valid and proceed to reset; e.g. when monitoring while resetting
            pass
        uses_usb_otg = self.uses_usb_otg()
        if uses_usb_otg or self.uses_usb_jtag_serial():
            # Check the strapping register to see if we can perform RTC WDT reset
            strap_reg = self.read_reg(self.GPIO_STRAP_REG)
            force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
            if (
                strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0  # GPIO0 low
                and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0
            ):
                self.rtc_wdt_reset()
                return

        ESPLoader.hard_reset(self, uses_usb_otg)

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)

    def check_spi_connection(self, spi_connection):
        if not set(spi_connection).issubset(set(range(0, 22)) | set(range(26, 49))):
            raise FatalError("SPI Pin numbers must be in the range 0-21, or 26-48.")
        if spi_connection[3] > 46:  # hd_gpio_num must be <= SPI_GPIO_NUM_LIMIT (46)
            raise FatalError("SPI HD Pin number must be <= 46.")
        if any([v for v in spi_connection if v in [19, 20]]):
            print(
                "WARNING: GPIO pins 19 and 20 are used by USB-Serial/JTAG and USB-OTG, "
                "consider using other pins for SPI flash connection."
            )


class ESP32S3StubLoader(ESP32S3ROM):
    """Access class for ESP32S3 stub loader, runs on top of ROM.

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

        if rom_loader.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
            self.FLASH_WRITE_SIZE = self.USB_RAM_BLOCK


ESP32S3ROM.STUB_CLASS = ESP32S3StubLoader
