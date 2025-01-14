# SPDX-FileCopyrightText: 2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from .esp32s3 import ESP32S3ROM
from ..loader import StubMixin


class ESP32S3BETA2ROM(ESP32S3ROM):
    CHIP_NAME = "ESP32-S3(beta2)"
    IMAGE_CHIP_ID = 4

    EFUSE_BASE = 0x6001A000  # BLOCK0 read base address


class ESP32S3BETA2StubLoader(StubMixin, ESP32S3BETA2ROM):
    """Stub loader for ESP32-S3(beta2), runs on top of ROM."""

    pass


ESP32S3BETA2ROM.STUB_CLASS = ESP32S3BETA2StubLoader
