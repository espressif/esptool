# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from .esp32c3 import ESP32C3ROM


class ESP32C6BETAROM(ESP32C3ROM):
    CHIP_NAME = "ESP32-C6(beta)"
    IMAGE_CHIP_ID = 7

    CHIP_DETECT_MAGIC_VALUE = [0x0DA1806F]

    UART_DATE_REG_ADDR = 0x00000500

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C6",
        }.get(self.get_pkg_version(), "unknown ESP32-C6")
        chip_revision = self.get_chip_revision()

        return "%s (revision %d)" % (chip_name, chip_revision)
