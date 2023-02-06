# SPDX-FileCopyrightText: 2014-2023 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import struct

from .esp32 import ESP32ROM
from ..loader import ESPLoader
from ..reset import HardReset
from ..util import FatalError, NotImplementedInROMError


class ESP32S3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S3"

    IMAGE_CHIP_ID = 9

    CHIP_DETECT_MAGIC_VALUE = [0x9]

    FPGA_SLOW_BOOT = False

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

    RTC_CNTL_WDT_WKEY = 0x50D83AA1
    RTCCNTL_BASE_REG = 0x60008000
    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0090
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00B0

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x60004038
    GPIO_STRAP_SPI_BOOT_MASK = 0x8  # Not download mode
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
        return f"{self.CHIP_NAME} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        return ["WiFi", "BLE"]

    def get_crystal_freq(self):
        # ESP32S3 XTAL is fixed to 40MHz
        return 40

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-S3

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > 5:
            raise FatalError("Valid key block numbers must be in range 0-5")

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
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

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

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-S3"
        )

    def read_mac(self):
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

    def disable_rtc_watchdog(self):
        # When USB-JTAG/Serial is used, the RTC watchdog is not reset
        # and can then reset the board during flashing. Disable it.
        if self.uses_usb_jtag_serial():
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)
            self.write_reg(self.RTC_CNTL_WDTCONFIG0_REG, 0)
            self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)

    def _post_connect(self):
        if self.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
        if not self.sync_stub_detected:  # Don't run if stub is reused
            self.disable_rtc_watchdog()

    def _check_if_can_reset(self):
        """
        Check the strapping register to see if we can reset out of download mode.
        """
        if os.getenv("ESPTOOL_TESTING") is not None:
            print("ESPTOOL_TESTING is set, ignoring strapping mode check")
            # Esptool tests over USB-OTG run with GPIO0 strapped low,
            # don't complain in this case.
            return
        strap_reg = self.read_reg(self.GPIO_STRAP_REG)
        force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
        if (
            strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0
            and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0
        ):
            print(
                "WARNING: {} chip was placed into download mode using GPIO0.\n"
                "esptool.py can not exit the download mode over USB. "
                "To run the app, reset the chip manually.\n"
                "To suppress this note, set --after option to 'no_reset'.".format(
                    self.get_chip_description()
                )
            )
            raise SystemExit(1)

    def hard_reset(self):
        uses_usb_otg = self.uses_usb_otg()
        if uses_usb_otg:
            self._check_if_can_reset()

        print("Hard resetting via RTS pin...")
        HardReset(self._port, uses_usb_otg)()

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)


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
