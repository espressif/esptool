# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import time
from typing import Dict

from .esp32c6 import ESP32C6ROM
from ..loader import ESPLoader


class ESP32C5BETA3ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-C5(beta3)"
    IMAGE_CHIP_ID = 17

    IROM_MAP_START = 0x41000000
    IROM_MAP_END = 0x41800000
    DROM_MAP_START = 0x41000000
    DROM_MAP_END = 0x41800000

    # Magic value for ESP32C5(beta3)
    CHIP_DETECT_MAGIC_VALUE = [0xE10D8082]

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x41800000, 0x42000000, "DROM"],
        [0x40800000, 0x40880000, "DRAM"],
        [0x40800000, 0x40880000, "BYTE_ACCESSIBLE"],
        [0x4004A000, 0x40050000, "DROM_MASK"],
        [0x40000000, 0x4004A000, "IROM_MASK"],
        [0x41000000, 0x41800000, "IROM"],
        [0x40800000, 0x40880000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    EFUSE_MAX_KEY = 5
    KEY_PURPOSES: Dict[int, str] = {
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

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C5 beta3 (QFN40)",
        }.get(self.get_pkg_version(), "unknown ESP32-C5 beta3")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_crystal_freq(self):
        # The crystal detection algorithm of ESP32/ESP8266
        # works for ESP32-C5 beta3 as well.
        return ESPLoader.get_crystal_freq(self)

    def change_baud(self, baud):
        rom_with_48M_XTAL = not self.IS_STUB and self.get_crystal_freq() == 48
        if rom_with_48M_XTAL:
            # The code is copied over from ESPLoader.change_baud().
            # Probably this is just a temporary solution until the next chip revision.

            # The ROM code thinks it uses a 40 MHz XTAL. Recompute the baud rate
            # in order to trick the ROM code to set the correct baud rate for
            # a 48 MHz XTAL.
            false_rom_baud = baud * 40 // 48

            print(f"Changing baud rate to {baud}")
            self.command(
                self.ESP_CHANGE_BAUDRATE, struct.pack("<II", false_rom_baud, 0)
            )
            print("Changed.")
            self._set_port_baudrate(baud)
            time.sleep(0.05)  # get rid of garbage sent during baud rate change
            self.flush_input()
        else:
            ESPLoader.change_baud(self, baud)


class ESP32C5BETA3StubLoader(ESP32C5BETA3ROM):
    """Access class for ESP32C5BETA3 stub loader, runs on top of ROM.

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


ESP32C5BETA3ROM.STUB_CLASS = ESP32C5BETA3StubLoader
