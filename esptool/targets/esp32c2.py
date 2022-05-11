# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

from .esp32c3 import ESP32C3ROM
from ..stub_flasher import ESP32C2StubCode


class ESP32C2ROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C2"
    IMAGE_CHIP_ID = 12

    STUB_CODE = ESP32C2StubCode

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42400000
    DROM_MAP_START = 0x3C000000
    DROM_MAP_END = 0x3C400000

    # Magic value for ESP32C2 ECO0 and ECO1 respectively
    CHIP_DETECT_MAGIC_VALUE = [0x6F51306F, 0x7C41A06F]

    EFUSE_BASE = 0x60008800
    MAC_EFUSE_REG = EFUSE_BASE + 0x040

    FLASH_FREQUENCY = {
        "60m": 0xF,
        "30m": 0x0,
        "20m": 0x1,
        "15m": 0x2,
    }

    def get_pkg_version(self):
        num_word = 3
        block1_addr = self.EFUSE_BASE + 0x044
        word3 = self.read_reg(block1_addr + (4 * num_word))
        pkg_version = (word3 >> 21) & 0x0F
        return pkg_version

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C2",
        }.get(self.get_pkg_version(), "unknown ESP32-C2")
        chip_revision = self.get_chip_revision()

        return "%s (revision %d)" % (chip_name, chip_revision)

    def get_chip_revision(self):
        si = self.get_security_info()
        return si["api_version"]

    def _post_connect(self):
        # ESP32C2 ECO0 is no longer supported by the flasher stub
        if self.get_chip_revision() == 0:
            self.stub_is_disabled = True
            self.IS_STUB = False


class ESP32C2StubLoader(ESP32C2ROM):
    """Access class for ESP32C2 stub loader, runs on top of ROM.

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
        self.flush_input()  # resets _slip_reader


ESP32C2ROM.STUB_CLASS = ESP32C2StubLoader
