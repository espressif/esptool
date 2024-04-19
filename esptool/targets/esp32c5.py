# SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import time

from .esp32c6 import ESP32C6ROM
from ..loader import ESPLoader


class ESP32C5ROM(ESP32C6ROM):
    CHIP_NAME = "ESP32-C5"
    IMAGE_CHIP_ID = 23

    EFUSE_BASE = 0x600B4800

    IROM_MAP_START = 0x42000000
    IROM_MAP_END = 0x42800000
    DROM_MAP_START = 0x42800000
    DROM_MAP_END = 0x43000000

    PCR_SYSCLK_CONF_REG = 0x60096110
    PCR_SYSCLK_XTAL_FREQ_V = 0x7F << 24
    PCR_SYSCLK_XTAL_FREQ_S = 24

    # Magic value for ESP32C5
    CHIP_DETECT_MAGIC_VALUE = [0x8082C5DC]

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "20m": 0x2,
    }

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x42800000, 0x43000000, "DROM"],
        [0x40800000, 0x40860000, "DRAM"],
        [0x40800000, 0x40860000, "BYTE_ACCESSIBLE"],
        [0x4003A000, 0x40040000, "DROM_MASK"],
        [0x40000000, 0x4003A000, "IROM_MASK"],
        [0x42000000, 0x42800000, "IROM"],
        [0x40800000, 0x40860000, "IRAM"],
        [0x50000000, 0x50004000, "RTC_IRAM"],
        [0x50000000, 0x50004000, "RTC_DRAM"],
        [0x600FE000, 0x60100000, "MEM_INTERNAL2"],
    ]

    UF2_FAMILY_ID = 0xF71C0343

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C5",
        }.get(self.get_pkg_version(), "unknown ESP32-C5")
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_crystal_freq(self):
        # The crystal detection algorithm of ESP32/ESP8266
        # works for ESP32-C5 as well.
        return ESPLoader.get_crystal_freq(self)

    def get_crystal_freq_rom_expect(self):
        return (
            self.read_reg(self.PCR_SYSCLK_CONF_REG) & self.PCR_SYSCLK_XTAL_FREQ_V
        ) >> self.PCR_SYSCLK_XTAL_FREQ_S

    def change_baud(self, baud):
        if not self.IS_STUB:
            crystal_freq_rom_expect = self.get_crystal_freq_rom_expect()
            crystal_freq_detect = self.get_crystal_freq()
            print(
                f"ROM expects crystal freq: {crystal_freq_rom_expect} MHz, detected {crystal_freq_detect} MHz"
            )
            baud_rate = baud
            # If detect the XTAL is 48MHz, but the ROM code expects it to be 40MHz
            if crystal_freq_detect == 48 and crystal_freq_rom_expect == 40:
                baud_rate = baud * 40 // 48
            # If detect the XTAL is 40MHz, but the ROM code expects it to be 48MHz
            elif crystal_freq_detect == 40 and crystal_freq_rom_expect == 48:
                baud_rate = baud * 48 // 40
            else:
                ESPLoader.change_baud(self, baud_rate)
                return

            print(f"Changing baud rate to {baud_rate}")
            self.command(self.ESP_CHANGE_BAUDRATE, struct.pack("<II", baud_rate, 0))
            print("Changed.")
            self._set_port_baudrate(baud)
            time.sleep(0.05)  # get rid of garbage sent during baud rate change
            self.flush_input()
        else:
            ESPLoader.change_baud(self, baud)


# TODO: [ESP32C5] ESPTOOL-825, IDF-8631 support stub flasher
