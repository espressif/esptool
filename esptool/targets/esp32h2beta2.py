# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from .esp32h2beta1 import ESP32H2BETA1ROM


class ESP32H2BETA2ROM(ESP32H2BETA1ROM):
    CHIP_NAME = "ESP32-H2(beta2)"
    IMAGE_CHIP_ID = 14

    CHIP_DETECT_MAGIC_VALUE = [0x6881B06F]

    def get_chip_description(self):
        chip_name = {
            1: "ESP32-H2(beta2)",
        }.get(self.get_pkg_version(), "unknown ESP32-H2")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"


class ESP32H2BETA2StubLoader(ESP32H2BETA2ROM):
    """Access class for ESP32H2BETA2 stub loader, runs on top of ROM.

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


ESP32H2BETA2ROM.STUB_CLASS = ESP32H2BETA2StubLoader
