# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

from .esp32s3 import ESP32S3ROM
from ..stub_flasher import ESP32S3BETA2StubCode


class ESP32S3BETA2ROM(ESP32S3ROM):
    CHIP_NAME = "ESP32-S3(beta2)"
    IMAGE_CHIP_ID = 4

    CHIP_DETECT_MAGIC_VALUE = [0xEB004136]

    STUB_CODE = ESP32S3BETA2StubCode

    EFUSE_BASE = 0x6001A000  # BLOCK0 read base address

    def get_chip_description(self):
        return "ESP32-S3(beta2)"


class ESP32S3BETA2StubLoader(ESP32S3BETA2ROM):
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
        self.flush_input()  # resets _slip_reader


ESP32S3BETA2ROM.STUB_CLASS = ESP32S3BETA2StubLoader
