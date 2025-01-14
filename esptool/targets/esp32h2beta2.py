# SPDX-FileCopyrightText: 2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from .esp32h2beta1 import ESP32H2BETA1ROM
from ..loader import StubMixin


class ESP32H2BETA2ROM(ESP32H2BETA1ROM):
    CHIP_NAME = "ESP32-H2(beta2)"
    IMAGE_CHIP_ID = 14

    def get_chip_description(self):
        chip_name = {
            1: "ESP32-H2(beta2)",
        }.get(self.get_pkg_version(), "unknown ESP32-H2")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"


class ESP32H2BETA2StubLoader(StubMixin, ESP32H2BETA2ROM):
    """Stub loader for ESP32-H2(beta2), runs on top of ROM."""

    pass


ESP32H2BETA2ROM.STUB_CLASS = ESP32H2BETA2StubLoader
