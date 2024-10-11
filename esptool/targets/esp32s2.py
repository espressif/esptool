# SPDX-FileCopyrightText: 2014-2024 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
from typing import Dict

from .esp32 import ESP32ROM
from ..loader import ESPLoader
from ..util import FatalError, NotImplementedInROMError


class ESP32S2ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S2"
    IMAGE_CHIP_ID = 2

    IROM_MAP_START = 0x40080000
    IROM_MAP_END = 0x40B80000
    DROM_MAP_START = 0x3F000000
    DROM_MAP_END = 0x3F3F0000

    CHIP_DETECT_MAGIC_VALUE = [0x000007C6]

    SPI_REG_BASE = 0x3F402000
    SPI_USR_OFFS = 0x18
    SPI_USR1_OFFS = 0x1C
    SPI_USR2_OFFS = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    SPI_ADDR_REG_MSB = False

    MAC_EFUSE_REG = 0x3F41A044  # ESP32-S2 has special block for MAC efuses

    UART_CLKDIV_REG = 0x3F400014

    SUPPORTS_ENCRYPTED_FLASH = True

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    # todo: use espefuse APIs to get this info
    EFUSE_BASE = 0x3F41A000
    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address
    EFUSE_BLOCK1_ADDR = EFUSE_BASE + 0x044
    EFUSE_BLOCK2_ADDR = EFUSE_BASE + 0x05C

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
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 19

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_BASE + 0x034
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7 << 18

    EFUSE_SECURE_BOOT_EN_REG = EFUSE_BASE + 0x038
    EFUSE_SECURE_BOOT_EN_MASK = 1 << 20

    EFUSE_RD_REPEAT_DATA3_REG = EFUSE_BASE + 0x3C
    EFUSE_RD_REPEAT_DATA3_REG_FLASH_TYPE_MASK = 1 << 9

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    UARTDEV_BUF_NO = 0x3FFFFD14  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB_OTG = 2  # Value of the above indicating that USB-OTG is in use

    USB_RAM_BLOCK = 0x800  # Max block size USB-OTG is used

    GPIO_STRAP_REG = 0x3F404038
    GPIO_STRAP_SPI_BOOT_MASK = 1 << 3  # Not download mode
    GPIO_STRAP_VDDSPI_MASK = 1 << 4
    RTC_CNTL_OPTION1_REG = 0x3F408128
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

    RTCCNTL_BASE_REG = 0x3F408000
    RTC_CNTL_WDTCONFIG0_REG = RTCCNTL_BASE_REG + 0x0094
    RTC_CNTL_WDTCONFIG1_REG = RTCCNTL_BASE_REG + 0x0098
    RTC_CNTL_WDTWPROTECT_REG = RTCCNTL_BASE_REG + 0x00AC
    RTC_CNTL_WDT_WKEY = 0x50D83AA1

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3F000000, 0x3FF80000, "DROM"],
        [0x3F500000, 0x3FF80000, "EXTRAM_DATA"],
        [0x3FF9E000, 0x3FFA0000, "RTC_DRAM"],
        [0x3FF9E000, 0x40000000, "BYTE_ACCESSIBLE"],
        [0x3FF9E000, 0x40072000, "MEM_INTERNAL"],
        [0x3FFB0000, 0x40000000, "DRAM"],
        [0x40000000, 0x4001A100, "IROM_MASK"],
        [0x40020000, 0x40070000, "IRAM"],
        [0x40070000, 0x40072000, "RTC_IRAM"],
        [0x40080000, 0x40800000, "IROM"],
        [0x50000000, 0x50002000, "RTC_DATA"],
    ]

    EFUSE_VDD_SPI_REG = EFUSE_BASE + 0x34
    VDD_SPI_XPD = 1 << 4
    VDD_SPI_TIEH = 1 << 5
    VDD_SPI_FORCE = 1 << 6

    UF2_FAMILY_ID = 0xBFDD4EEE

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
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 0) & 0x0F

    def get_minor_chip_version(self):
        hi_num_word = 3
        hi = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * hi_num_word)) >> 20) & 0x01
        low_num_word = 4
        low = (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * low_num_word)) >> 4) & 0x07
        return (hi << 3) + low

    def get_major_chip_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 18) & 0x03

    def get_flash_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 21) & 0x0F

    def get_flash_cap(self):
        return self.get_flash_version()

    def get_psram_version(self):
        num_word = 3
        return (self.read_reg(self.EFUSE_BLOCK1_ADDR + (4 * num_word)) >> 28) & 0x0F

    def get_psram_cap(self):
        return self.get_psram_version()

    def get_block2_version(self):
        # BLK_VERSION_MINOR
        num_word = 4
        return (self.read_reg(self.EFUSE_BLOCK2_ADDR + (4 * num_word)) >> 4) & 0x07

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-S2",
            1: "ESP32-S2FH2",
            2: "ESP32-S2FH4",
            102: "ESP32-S2FNR2",
            100: "ESP32-S2R2",
        }.get(
            self.get_flash_cap() + self.get_psram_cap() * 100,
            "unknown ESP32-S2",
        )
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["WiFi"]

        if self.secure_download_mode:
            features += ["Secure Download Mode Enabled"]

        flash_version = {
            0: "No Embedded Flash",
            1: "Embedded Flash 2MB",
            2: "Embedded Flash 4MB",
        }.get(self.get_flash_cap(), "Unknown Embedded Flash")
        features += [flash_version]

        psram_version = {
            0: "No Embedded PSRAM",
            1: "Embedded PSRAM 2MB",
            2: "Embedded PSRAM 4MB",
        }.get(self.get_psram_cap(), "Unknown Embedded PSRAM")
        features += [psram_version]

        block2_version = {
            0: "No calibration in BLK2 of efuse",
            1: "ADC and temperature sensor calibration in BLK2 of efuse V1",
            2: "ADC and temperature sensor calibration in BLK2 of efuse V2",
        }.get(self.get_block2_version(), "Unknown Calibration in BLK2")
        features += [block2_version]

        return features

    def get_crystal_freq(self):
        # ESP32-S2 XTAL is fixed to 40MHz
        return 40

    def _get_rtc_cntl_flash_voltage(self):
        return None  # not supported on ESP32-S2

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError(
            "VDD_SDIO overrides are not supported for ESP32-S2"
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

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-S2

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

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) and any(
            p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes
        )

    def uses_usb_otg(self):
        """
        Check the UARTDEV_BUF_NO register to see if USB-OTG console is being used
        """
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        return self.get_uart_no() == self.UARTDEV_BUF_NO_USB_OTG

    def _post_connect(self):
        if self.uses_usb_otg():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK

    def rtc_wdt_reset(self):
        print("Hard resetting with RTC WDT...")
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, self.RTC_CNTL_WDT_WKEY)  # unlock
        self.write_reg(self.RTC_CNTL_WDTCONFIG1_REG, 5000)  # set WDT timeout
        self.write_reg(
            self.RTC_CNTL_WDTCONFIG0_REG, (1 << 31) | (5 << 28) | (1 << 8) | 2
        )  # enable WDT
        self.write_reg(self.RTC_CNTL_WDTWPROTECT_REG, 0)  # lock

    def hard_reset(self):
        uses_usb_otg = self.uses_usb_otg()
        if uses_usb_otg:
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
        if not set(spi_connection).issubset(set(range(0, 22)) | set(range(26, 47))):
            raise FatalError("SPI Pin numbers must be in the range 0-21, or 26-46.")
        if any([v for v in spi_connection if v in [19, 20]]):
            print(
                "WARNING: GPIO pins 19 and 20 are used by USB-OTG, "
                "consider using other pins for SPI flash connection."
            )


class ESP32S2StubLoader(ESP32S2ROM):
    """Access class for ESP32-S2 stub loader, runs on top of ROM.

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


ESP32S2ROM.STUB_CLASS = ESP32S2StubLoader
