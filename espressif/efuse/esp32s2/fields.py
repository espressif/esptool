#!/usr/bin/env python
# This file describes eFuses for ESP32S2 chip
#
# Copyright (C) 2020 Espressif Systems (Shanghai) PTE LTD
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.
from __future__ import division, print_function

import reedsolo
import struct
import time
import esptool
from .. import base_fields
from .. import util


class EfuseBlock(base_fields.EfuseBlockBase):
    def len_of_burn_unit(self):
        # The writing register window is 8 registers for any blocks.
        # len in bytes
        return 8 * 4

    def __init__(self, parent, param, skip_read=False):
        parent.read_coding_scheme()
        super(EfuseBlock, self).__init__(parent, param, skip_read=skip_read)

    def apply_coding_scheme(self):
        data = self.get_raw(from_read=False)[::-1]
        if len(data) < self.len_of_burn_unit():
            add_empty_bytes = self.len_of_burn_unit() - len(data)
            data = data + (b'\x00' * add_empty_bytes)
        if self.get_coding_scheme() == self.parent.CODING_SCHEME_RS:
            # takes 32 bytes
            # apply RS encoding
            rs = reedsolo.RSCodec(12)
            # 32 byte of data + 12 bytes RS
            encoded_data = rs.encode([x for x in data])
            words = struct.unpack("<" + "I" * 11, encoded_data)
            # returns 11 words (8 words of data + 3 words of RS coding)
        else:
            # takes 32 bytes
            words = struct.unpack("<" + ("I" * (len(data) // 4)), data)
            # returns 8 words
        return words


class EspEfuses(base_fields.EspEfusesBase):
    """
    Wrapper object to manage the efuse fields in a connected ESP bootloader
    """

    DR_REG_EFUSE_BASE       = 0x3f41A000
    EFUSE_PGM_DATA0_REG     = DR_REG_EFUSE_BASE
    EFUSE_CHECK_VALUE0_REG  = DR_REG_EFUSE_BASE + 0x020
    EFUSE_CLK_REG           = DR_REG_EFUSE_BASE + 0x1c8
    EFUSE_CONF_REG          = DR_REG_EFUSE_BASE + 0x1cc
    EFUSE_STATUS_REG        = DR_REG_EFUSE_BASE + 0x1d0
    EFUSE_CMD_REG           = DR_REG_EFUSE_BASE + 0x1d4
    EFUSE_RD_RS_ERR0_REG    = DR_REG_EFUSE_BASE + 0x194
    EFUSE_RD_RS_ERR1_REG    = DR_REG_EFUSE_BASE + 0x198
    EFUSE_WRITE_OP_CODE     = 0x5A5A
    EFUSE_READ_OP_CODE      = 0x5AA5
    EFUSE_PGM_CMD           = 1 << 1
    EFUSE_READ_CMD          = 1 << 0
    EFUSE_BURN_TIMEOUT      = 0.250  # seconds

    BLOCK_ERRORS = [
        # error reg,            err_num,    fail_bit
        (None,                  None,       None),  # BLOCK0
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 0,     3),     # MAC_SPI_8M_0
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 4,     7),     # BLOCK_SYS_DATA
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 8,     11),    # BLOCK_USR_DATA
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 12,    15),    # BLOCK_KEY0
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 16,    19),    # BLOCK_KEY1
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 20,    23),    # BLOCK_KEY2
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 24,    27),    # BLOCK_KEY3
        (EFUSE_RD_RS_ERR0_REG,  0x7 << 28,    31),    # BLOCK_KEY4
        (EFUSE_RD_RS_ERR1_REG,  0x7 << 0,     3),     # BLOCK_KEY5
        (EFUSE_RD_RS_ERR1_REG,  0x7 << 4,     7),     # BLOCK_SYS_DATA2
    ]

    # List of efuse blocks
    # Name, Alias, Index, Read address, Write address, Write protect bit, Read protect bit, Len,         key_purpose
    _BLOCKS = [
        ("BLOCK0",          None,      0,  DR_REG_EFUSE_BASE + 0x02C, EFUSE_PGM_DATA0_REG, None, None, 6, None),
        ("MAC_SPI_8M_0",    "BLOCK1",  1,  DR_REG_EFUSE_BASE + 0x044, EFUSE_PGM_DATA0_REG, 20,   None, 6, None),
        ("BLOCK_SYS_DATA",  "BLOCK2",  2,  DR_REG_EFUSE_BASE + 0x05C, EFUSE_PGM_DATA0_REG, 21,   None, 8, None),
        ("BLOCK_USR_DATA",  "BLOCK3",  3,  DR_REG_EFUSE_BASE + 0x07C, EFUSE_PGM_DATA0_REG, 22,   None, 8, None),
        ("BLOCK_KEY0",      "BLOCK4",  4,  DR_REG_EFUSE_BASE + 0x09C, EFUSE_PGM_DATA0_REG, 23,   0,    8, "KEY_PURPOSE_0"),
        ("BLOCK_KEY1",      "BLOCK5",  5,  DR_REG_EFUSE_BASE + 0x0BC, EFUSE_PGM_DATA0_REG, 24,   1,    8, "KEY_PURPOSE_1"),
        ("BLOCK_KEY2",      "BLOCK6",  6,  DR_REG_EFUSE_BASE + 0x0DC, EFUSE_PGM_DATA0_REG, 25,   2,    8, "KEY_PURPOSE_2"),
        ("BLOCK_KEY3",      "BLOCK7",  7,  DR_REG_EFUSE_BASE + 0x0FC, EFUSE_PGM_DATA0_REG, 26,   3,    8, "KEY_PURPOSE_3"),
        ("BLOCK_KEY4",      "BLOCK8",  8,  DR_REG_EFUSE_BASE + 0x11C, EFUSE_PGM_DATA0_REG, 27,   4,    8, "KEY_PURPOSE_4"),
        ("BLOCK_KEY5",      "BLOCK9",  9,  DR_REG_EFUSE_BASE + 0x13C, EFUSE_PGM_DATA0_REG, 28,   5,    8, "KEY_PURPOSE_5"),
        ("BLOCK_SYS_DATA2", "BLOCK10", 10, DR_REG_EFUSE_BASE + 0x15C, EFUSE_PGM_DATA0_REG, 29,   6,    8, None),
    ]

    BURN_BLOCK_DATA_NAMES = []
    for block in _BLOCKS:
        if block[0]:
            BURN_BLOCK_DATA_NAMES.append(block[0])
        if block[1]:
            BURN_BLOCK_DATA_NAMES.append(block[1])

    BLOCKS_FOR_KEYS = []
    for block in _BLOCKS:
        if block[8]:
            if block[0]:
                BLOCKS_FOR_KEYS.append(block[0])
            if block[1]:
                BLOCKS_FOR_KEYS.append(block[1])

    # List of efuse fields from TRM the chapter eFuse Controller.
    #     Name,                  Category,  Block, Word, Mask, Write protect bit, Read protect bit, Type, Description)
    _EFUSES = [
        #
        # Table 51: Parameters in BLOCK0
        # Name                           Category Block Word Pos Type:len   WR_DIS RD_DIS Class        Description                Dictionary
        ("WR_DIS",                       "efuse",    0,  0,  0,  "uint:32",  None, None, None,         "Disables programming of individual eFuses", None),
        ("RD_DIS",                       "efuse",    0,  1,  0,  "uint:7",   0,    None, None,         "Disables software reading from BLOCK4-10", None),
        ("DIS_RTC_RAM_BOOT",             "config",   0,  1,  7,  "bool",     1,    None, None,         "Disables boot from RTC RAM", None),
        ("DIS_ICACHE",                   "config",   0,  1,  8,  "bool",     2,    None, None,         "Disables ICache", None),
        ("DIS_DCACHE",                   "config",   0,  1,  9,  "bool",     2,    None, None,         "Disables DCache", None),
        ("DIS_DOWNLOAD_ICACHE",          "config",   0,  1,  10, "bool",     2,    None, None,         "Disables Icache when SoC is in Download mode", None),
        ("DIS_DOWNLOAD_DCACHE",          "config",   0,  1,  11, "bool",     2,    None, None,         "Disables Dcache when SoC is in Download mode", None),
        ("DIS_FORCE_DOWNLOAD",           "config",   0,  1,  12, "bool",     2,    None, None,         "Disables forcing chip into Download mode", None),
        ("DIS_USB",                  "usb config",   0,  1,  13, "bool",     2,    None, None,         "Disables the USB OTG hardware", None),
        ("DIS_CAN",                      "config",   0,  1,  14, "bool",     2,    None, None,         "Disables the TWAI Controller hardware", None),
        ("DIS_BOOT_REMAP",               "config",   0,  1,  15, "bool",     2,    None, None,         "Disables capability to Remap RAM to ROM address space",
                                                                                                       None),
        ("SOFT_DIS_JTAG",                "security", 0,  1,  17, "bool",     2,    None, None,         "Software disables JTAG. When software disabled, " +
                                                                                                       "JTAG can be activated temporarily by HMAC peripheral",
                                                                                                       None),
        ("HARD_DIS_JTAG",                "security", 0,  1,  18, "bool",     2,    None, None,         "Hardware disables JTAG permanently", None),
        ("DIS_DOWNLOAD_MANUAL_ENCRYPT",  "security", 0,  1,  19, "bool",     2,    None, None,         "Disables flash encryption when in download boot modes",
                                                                                                       None),
        ("USB_EXCHG_PINS",           "usb config",   0,  1,  24, "bool",     30,   None, None,         "Exchanges USB D+ and D- pins", None),
        ("EXT_PHY_ENABLE",           "usb config",   0,  1,  25, "bool",     30,   None, None,         "Enables external USB PHY", None),
        ("USB_FORCE_NOPERSIST",      "usb config",   0,  1,  26, "bool",     30,   None, None,         "Forces to set USB BVALID to 1", None),
        ("BLOCK0_VERSION",             "identity",   0,  1,  27, "uint:2",   30,   None, None,         "BLOCK0 efuse version", None),
        ("VDD_SPI_FORCE",        "VDD_SPI config",   0,  2,  6,  "bool",     3,    None, None,         "Force using VDD_SPI_XPD and VDD_SPI_TIEH " +
                                                                                                       "to configure VDD_SPI LDO", None),
        ("VDD_SPI_XPD",          "VDD_SPI config",   0,  2,  4,  "bool",     3,    None, None,         "The VDD_SPI regulator is powered on", None),
        ("VDD_SPI_TIEH",         "VDD_SPI config",   0,  2,  5,  "bool",     3,    None, None,         "The VDD_SPI power supply voltage at reset",
                                                                                                       {0:"Connect to 1.8V LDO", 1:"Connect to VDD3P3_RTC_IO"}),
        ("WDT_DELAY_SEL",            "WDT config",   0,  2,  16, "bool",     3,    None, None,         "Selects RTC WDT timeout threshold at startup", None),
        ("SPI_BOOT_CRYPT_CNT",           "security", 0,  2,  18, "uint:3",   4,    None, None,         "Enables encryption and decryption, when an SPI boot " +
                                                                                                       "mode is set. Enabled when 1 or 3 bits are set," +
                                                                                                       "disabled otherwise",
                                                                                                       {0:"Disable", 1:"Enable", 3:"Disable", 7:"Enable"}),
        ("SECURE_BOOT_KEY_REVOKE0",      "security", 0,  2, 21,  "bool",     5,    None, None,         "If set, revokes use of secure boot key digest 0", None),
        ("SECURE_BOOT_KEY_REVOKE1",      "security", 0,  2, 22,  "bool",     6,    None, None,         "If set, revokes use of secure boot key digest 1", None),
        ("SECURE_BOOT_KEY_REVOKE2",      "security", 0,  2, 23,  "bool",     7,    None, None,         "If set, revokes use of secure boot key digest 2", None),
        ("KEY_PURPOSE_0",                "security", 0,  2, 24,  "uint:4",   8,    None, "keypurpose", "KEY0 purpose", None),
        ("KEY_PURPOSE_1",                "security", 0,  2, 28,  "uint:4",   9,    None, "keypurpose", "KEY1 purpose", None),
        ("KEY_PURPOSE_2",                "security", 0,  3, 0,   "uint:4",   10,   None, "keypurpose", "KEY2 purpose", None),
        ("KEY_PURPOSE_3",                "security", 0,  3, 4,   "uint:4",   11,   None, "keypurpose", "KEY3 purpose", None),
        ("KEY_PURPOSE_4",                "security", 0,  3, 8,   "uint:4",   12,   None, "keypurpose", "KEY4 purpose", None),
        ("KEY_PURPOSE_5",                "security", 0,  3, 12,  "uint:4",   13,   None, "keypurpose", "KEY5 purpose", None),
        ("SECURE_BOOT_EN",               "security", 0,  3, 20,  "bool",     15,   None, None,         "Enables secure boot", None),
        ("SECURE_BOOT_AGGRESSIVE_REVOKE","security", 0,  3, 21,  "bool",     16,   None, None,         "Enables aggressive secure boot key revocation mode",
                                                                                                       None),
        ("FLASH_TPUW",                   "config",   0,  3, 28,  "uint:4",   18,   None, None,         "Configures flash startup delay after SoC power-up, " +
                                                                                                       "unit is (ms/2). When the value is 15, delay is 7.5 ms",
                                                                                                       None),
        ("DIS_DOWNLOAD_MODE",            "security", 0,  4, 0,   "bool",     18,   None, None,         "Disables all Download boot modes", None),
        ("DIS_LEGACY_SPI_BOOT",          "config",   0,  4, 1,   "bool",     18,   None, None,         "Disables Legacy SPI boot mode", None),
        ("UART_PRINT_CHANNEL",           "config",   0,  4, 2,   "bool",     18,   None, None,         "Selects the default UART for printing boot msg",
                                                                                                       {0:"UART0", 1:"UART1"}),
        ("DIS_USB_DOWNLOAD_MODE",        "config",   0,  4, 4,   "bool",     18,   None, None,         "Disables use of USB in UART download boot mode", None),
        ("ENABLE_SECURITY_DOWNLOAD",    "security",  0,  4, 5,   "bool",     18,   None, None,         "Enables secure UART download mode " +
                                                                                                       "(read/write flash only)", None),
        ("UART_PRINT_CONTROL",           "config",   0,  4, 6,   "uint:2",   18,   None, None,         "Sets the default UART boot message output mode",
                                                                                                       {0:"Enabled", 1:"Enable when GPIO 46 is low at reset",
                                                                                                        2:"Enable when GPIO 46 is high at rest", 3:"Disabled"}),
        ("PIN_POWER_SELECTION",  "VDD_SPI config",   0,  4, 8,   "bool",     18,   None, None,         "Sets default power supply for GPIO33..37, " +
                                                                                                       "set when SPI flash is initialized",
                                                                                                       {0:"VDD3P3_CPU", 1:"VDD_SPI"}),
        ("FLASH_TYPE",                   "config",   0,  4, 9,   "bool",     18,   None, None,         "Selects SPI flash type",
                                                                                                       {0:"4 data lines", 1:"8 data lines"}),
        ("FORCE_SEND_RESUME",            "config",   0,  4, 10,  "bool",     18,   None, None,         "Forces ROM code to send an SPI flash resume command " +
                                                                                                       "during SPI boot", None),
        ("SECURE_VERSION",             "identity",   0,  4, 11,  "uint:16",  18,   None, "bitcount",   "Secure version (used by ESP-IDF anti-rollback feature)",
                                                                                                       None),
        #
        # Table 53: Parameters in BLOCK1-10
        # Name                          Category  Block Word Pos  Type:len WR_DIS RD_DIS Class         Description                Dictionary
        ("MAC",                        "identity",   1,  0, 0,   "bytes:6",  20,   None, "mac",        "Factory MAC Address", None),
        ("SPI_PAD_CONFIG_CLK",   "spi_pad_config",   1,  1, 16,  "uint:6",   20,   None, None,         "SPI CLK pad", None),
        ("SPI_PAD_CONFIG_Q",     "spi_pad_config",   1,  1, 22,  "uint:6",   20,   None, None,         "SPI Q (D1) pad", None),
        ("SPI_PAD_CONFIG_D",     "spi_pad_config",   1,  1, 28,  "uint:6",   20,   None, None,         "SPI D (D0) pad", None),
        ("SPI_PAD_CONFIG_CS",    "spi_pad_config",   1,  2, 2,   "uint:6",   20,   None, None,         "SPI CS pad", None),
        ("SPI_PAD_CONFIG_HD",    "spi_pad_config",   1,  2, 8,   "uint:6",   20,   None, None,         "SPI HD (D3) pad", None),
        ("SPI_PAD_CONFIG_WP",    "spi_pad_config",   1,  2, 14,  "uint:6",   20,   None, None,         "SPI WP (D2) pad", None),
        ("SPI_PAD_CONFIG_DQS",   "spi_pad_config",   1,  2, 20,  "uint:6",   20,   None, None,         "SPI DQS pad", None),
        ("SPI_PAD_CONFIG_D4",    "spi_pad_config",   1,  2, 26,  "uint:6",   20,   None, None,         "SPI D4 pad", None),
        ("SPI_PAD_CONFIG_D5",    "spi_pad_config",   1,  3, 0,   "uint:6",   20,   None, None,         "SPI D5 pad", None),
        ("SPI_PAD_CONFIG_D6",    "spi_pad_config",   1,  3, 6,   "uint:6",   20,   None, None,         "SPI D6 pad", None),
        ("SPI_PAD_CONFIG_D7",    "spi_pad_config",   1,  3, 12,  "uint:6",   20,   None, None,         "SPI D7 pad", None),
        ("WAFER_VERSION",              "identity",   1,  3, 18,  "uint:3",   20,   None, None,         "WAFER version", {0:"A"}),
        ("PKG_VERSION",                "identity",   1,  3, 21,  "uint:4",   20,   None, None,         "Package version",
                                                                                                       {0:"ESP32-S2, QFN 7x7 56 pins",
                                                                                                        1:"ESP32-S2FH16, QFN 7x7 56 pins, Flash 16Mb t=105C",
                                                                                                        2:"ESP32-S2FH32, QFN 7x7 56 pins, Flash 32Mb t=105C"}),
        ("BLOCK1_VERSION",             "identity",   1,  3, 25,  "uint:3",   20,   None, None,         "BLOCK1 efuse version", None),
        ('OPTIONAL_UNIQUE_ID',         "identity",   2,  0, 0,   "bytes:16", 21,   None, "keyblock",   "Optional unique 128-bit ID", None),
        ('BLOCK2_VERSION',             "identity",   2,  4, 4,   "uint:3",   21,   None, None,         "Version of BLOCK2",
                                                                                                       {0:"No calibration", 1:"With calibration"}),
    ]

    _KEYBLOCKS = [
        # Name                      Category      Block Word Pos Type:len  WR_DIS RD_DIS Class         Description                Dictionary
        ('BLOCK_USR_DATA',               "config",   3,  0, 0,   "bytes:32", 22,   None, None,         "User data", None),
        ('BLOCK_KEY0',                   "security", 4,  0, 0,   "bytes:32", 23,   0,    "keyblock",   "Encryption key0 or user data", None),
        ('BLOCK_KEY1',                   "security", 5,  0, 0,   "bytes:32", 24,   1,    "keyblock",   "Encryption key1 or user data", None),
        ('BLOCK_KEY2',                   "security", 6,  0, 0,   "bytes:32", 25,   2,    "keyblock",   "Encryption key2 or user data", None),
        ('BLOCK_KEY3',                   "security", 7,  0, 0,   "bytes:32", 26,   3,    "keyblock",   "Encryption key3 or user data", None),
        ('BLOCK_KEY4',                   "security", 8,  0, 0,   "bytes:32", 27,   4,    "keyblock",   "Encryption key4 or user data", None),
        ('BLOCK_KEY5',                   "security", 9,  0, 0,   "bytes:32", 28,   5,    "keyblock",   "Encryption key5 or user data", None),
        ('BLOCK_SYS_DATA2',              "security", 10, 0, 0,   "bytes:32", 29,   6,    None,         "System data (part 2)", None),
    ]

    # if BLOCK2_VERSION is 1, these efuse fields are in BLOCK2
    _BLOCK2_CALIBRATION_EFUSES = [
        # Name                      Category      Block Word Pos Type:len  WR_DIS RD_DIS Class         Description                Dictionary
        ('TEMP_SENSOR_CAL',         "calibration",   2,  4, 7,   "uint:9",   21,   None, "t_sensor",   "Temperature calibration", None),
        ('ADC1_MODE0_D2',           "calibration",   2,  4, 16,  "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 1", None),
        ('ADC1_MODE1_D2',           "calibration",   2,  4, 24,  "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 2", None),
        ('ADC1_MODE2_D2',           "calibration",   2,  5, 0,   "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 3", None),
        ('ADC1_MODE3_D2',           "calibration",   2,  5, 8,   "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 4", None),
        ('ADC2_MODE0_D2',           "calibration",   2,  5, 16,  "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 5", None),
        ('ADC2_MODE1_D2',           "calibration",   2,  5, 24,  "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 6", None),
        ('ADC2_MODE2_D2',           "calibration",   2,  6, 0,   "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 7", None),
        ('ADC2_MODE3_D2',           "calibration",   2,  6, 8,   "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 8", None),
        ('ADC1_MODE0_D1',           "calibration",   2,  6, 16,  "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 9", None),
        ('ADC1_MODE1_D1',           "calibration",   2,  6, 22,  "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 10", None),
        ('ADC1_MODE2_D1',           "calibration",   2,  6, 28,  "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 11", None),
        ('ADC1_MODE3_D1',           "calibration",   2,  7, 2,   "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 12", None),
        ('ADC2_MODE0_D1',           "calibration",   2,  7, 8,   "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 13", None),
        ('ADC2_MODE1_D1',           "calibration",   2,  7, 14,  "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 14", None),
        ('ADC2_MODE2_D1',           "calibration",   2,  7, 20,  "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 15", None),
        ('ADC2_MODE3_D1',           "calibration",   2,  7, 26,  "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 16", None),
    ]

    debug = False
    do_not_confirm = False

    def __init__(self, esp, skip_connect=False, debug=False, do_not_confirm=False):
        self._esp = esp
        self.debug = debug
        self.do_not_confirm = do_not_confirm
        if esp is not None and type(esp) is not esptool.ESP32S2ROM:
            raise esptool.FatalError("The eFuse module describes ESP32S2 chip. Check the chip setting for esptool, it gives '%s' name." % (esp.CHIP_NAME))
        self.blocks = [EfuseBlock(self, block, skip_read=skip_connect) for block in self._BLOCKS]
        self.efuses = [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._EFUSES]
        self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._KEYBLOCKS]
        if skip_connect:
            self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._BLOCK2_CALIBRATION_EFUSES]
        else:
            if self["BLOCK2_VERSION"].get() == 1:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._BLOCK2_CALIBRATION_EFUSES]

    def __getitem__(self, efuse_name):
        """ Return the efuse field with the given name """
        for e in self.efuses:
            if efuse_name == e.name:
                return e
        new_fields = False
        for efuse in self._BLOCK2_CALIBRATION_EFUSES:
            if efuse[0] == efuse_name:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._BLOCK2_CALIBRATION_EFUSES]
                new_fields = True
        if new_fields:
            for e in self.efuses:
                if efuse_name == e.name:
                    return e
        raise KeyError

    def read_coding_scheme(self):
        self.coding_scheme = self.CODING_SCHEME_RS

    def print_status_regs(self):
        print("")
        print("RD_RS_ERR0_REG 0x%08x RD_RS_ERR1_REG 0x%08x" % (
              self.read_reg(self.EFUSE_RD_RS_ERR0_REG),
              self.read_reg(self.EFUSE_RD_RS_ERR1_REG)))

    def get_block_errors(self, block_num):
        """ Returns (error count, failure boolean flag) """
        read_reg, err_num_mask, fail_bit_mask = self.BLOCK_ERRORS[block_num]
        if read_reg is None:
            return 0, False
        reg_value = self.read_reg(read_reg)
        err_num_shift = esptool._mask_to_shift(err_num_mask)
        err_num_val = (reg_value & err_num_mask) >> err_num_shift
        fail_bit_val = (reg_value & (1 << fail_bit_mask)) != 0
        return err_num_val, fail_bit_val

    def efuse_controller_setup(self):
        self.set_efuse_timing()
        self.clear_pgm_registers()
        self.wait_efuse_idle()

    def write_efuses(self, block):
        self.efuse_program(block)
        return self.get_coding_scheme_warnings()

    def clear_pgm_registers(self):
        self.wait_efuse_idle()
        for r in range(self.EFUSE_PGM_DATA0_REG, self.EFUSE_PGM_DATA0_REG + 32, 4):
            self.write_reg(r, 0)

    def wait_efuse_idle(self):
        deadline = time.time() + self.EFUSE_BURN_TIMEOUT
        while time.time() < deadline:
            # if self.read_reg(self.EFUSE_CMD_REG) == 0:
            if self.read_reg(self.EFUSE_STATUS_REG) & 0x7 == 1:
                return
        raise esptool.FatalError("Timed out waiting for Efuse controller command to complete")

    def efuse_program(self, block):
        self.wait_efuse_idle()
        self.write_reg(self.EFUSE_CONF_REG, self.EFUSE_WRITE_OP_CODE)
        self.write_reg(self.EFUSE_CMD_REG, self.EFUSE_PGM_CMD | (block << 2))
        self.wait_efuse_idle()
        self.clear_pgm_registers()
        self.efuse_read()

    def efuse_read(self):
        self.wait_efuse_idle()
        self.write_reg(self.EFUSE_CONF_REG, self.EFUSE_READ_OP_CODE)
        # need to add a delay after triggering EFUSE_READ_CMD, as ROM loader checks some
        # efuse registers after each command is completed
        self.write_reg(self.EFUSE_CMD_REG, self.EFUSE_READ_CMD, delay_after_us=1000)
        self.wait_efuse_idle()

    def set_efuse_timing(self):
        """ Set timing registers for burning efuses """
        # print("Configuring efuse timing...")
        # EFUSE_DATE_REG = 0x3f4101FC
        # print("eFuse Controller (version control register): %0x" % self.read_reg(EFUSE_DATE_REG))

        EFUSE_DAC_CONF_REG = self.DR_REG_EFUSE_BASE + 0x1e8
        EFUSE_DAC_CLK_DIV_S = 0
        EFUSE_DAC_CLK_DIV_M = 0xFF << EFUSE_DAC_CLK_DIV_S

        EFUSE_RD_TIM_CONF_REG = self.DR_REG_EFUSE_BASE + 0x1EC
        # EFUSE_TSUR_A_S = 16
        # EFUSE_TSUR_A_M = 0xFF << EFUSE_TSUR_A_S
        EFUSE_TRD_S = 8
        EFUSE_TRD_M = 0xFF << EFUSE_TRD_S
        EFUSE_THR_A_S = 0
        EFUSE_THR_A_M = 0xFF << EFUSE_THR_A_S

        EFUSE_WR_TIM_CONF0_REG = self.DR_REG_EFUSE_BASE + 0x1F0
        EFUSE_TPGM_S = 16
        EFUSE_TPGM_M = 0xFFFF << EFUSE_TPGM_S
        EFUSE_TPGM_INACTIVE_S = 8
        EFUSE_TPGM_INACTIVE_M = 0xFF << EFUSE_TPGM_INACTIVE_S
        EFUSE_THP_A_S = 0
        EFUSE_THP_A_M = 0xFF << EFUSE_THP_A_S

        EFUSE_WR_TIM_CONF1_REG = self.DR_REG_EFUSE_BASE + 0x1F4
        EFUSE_PWR_ON_NUM_S = 8
        EFUSE_PWR_ON_NUM_M = 0xFFFF << EFUSE_PWR_ON_NUM_S
        EFUSE_TSUP_A_S = 0
        EFUSE_TSUP_A_M = 0xFF << EFUSE_TSUP_A_S

        EFUSE_WR_TIM_CONF2_REG = self.DR_REG_EFUSE_BASE + 0x1F8
        EFUSE_PWR_OFF_NUM_S = 0
        EFUSE_PWR_OFF_NUM_M = 0xFFFF << EFUSE_PWR_OFF_NUM_S

        # Configure clock
        apb_freq = self._esp.get_crystal_freq()
        EFUSE_PROGRAMMING_TIMING_PARAMETERS = {
            # APB Frequency: ( EFUSE_TSUP_A, EFUSE_TPGM, EFUSE_THP_A, EFUSE_TPGM_INACTIVE )
            # Taken from TRM chapter "eFuse Controller": eFuse-Programming Timing
            80: (0x2, 0x320, 0x2, 0x4),
            40: (0x1, 0x190, 0x1, 0x2),
            20: (0x1, 0xC8,  0x1, 0x1),
        }
        EFUSE_TSUP_A, EFUSE_TPGM, EFUSE_THP_A, EFUSE_TPGM_INACTIVE = EFUSE_PROGRAMMING_TIMING_PARAMETERS[apb_freq]
        self.write_reg(EFUSE_WR_TIM_CONF1_REG, EFUSE_TSUP_A << EFUSE_TSUP_A_S, EFUSE_TSUP_A_M)
        self.write_reg(EFUSE_WR_TIM_CONF0_REG, EFUSE_TPGM << EFUSE_TPGM_S, EFUSE_TPGM_M)
        self.write_reg(EFUSE_WR_TIM_CONF0_REG, EFUSE_THP_A << EFUSE_THP_A_S, EFUSE_THP_A_M)
        self.write_reg(EFUSE_WR_TIM_CONF0_REG, EFUSE_TPGM_INACTIVE << EFUSE_TPGM_INACTIVE_S, EFUSE_TPGM_INACTIVE_M)

        VDDQ_TIMING_PARAMETERS = {
            # APB Frequency: ( EFUSE_DAC_CLK_DIV, EFUSE_PWR_ON_NUM, EFUSE_PWR_OFF_NUM )
            # Taken from TRM chapter "eFuse Controller": eFuse VDDQ Timing Setting
            80: (0xA0, 0xA200, 0x100),
            40: (0x50, 0x5100, 0x80),
            20: (0x28, 0x2880, 0x40),
        }
        EFUSE_DAC_CLK_DIV, EFUSE_PWR_ON_NUM, EFUSE_PWR_OFF_NUM = VDDQ_TIMING_PARAMETERS[apb_freq]
        self.write_reg(EFUSE_DAC_CONF_REG, EFUSE_DAC_CLK_DIV << EFUSE_DAC_CLK_DIV_S, EFUSE_DAC_CLK_DIV_M)
        self.write_reg(EFUSE_WR_TIM_CONF1_REG, EFUSE_PWR_ON_NUM << EFUSE_PWR_ON_NUM_S, EFUSE_PWR_ON_NUM_M)
        self.write_reg(EFUSE_WR_TIM_CONF2_REG, EFUSE_PWR_OFF_NUM << EFUSE_PWR_OFF_NUM_S, EFUSE_PWR_OFF_NUM_M)

        EFUSE_READING_PARAMETERS = {
            # APB Frequency: ( EFUSE_TSUR_A, EFUSE_TRD, EFUSE_THR_A )
            # Taken from TRM chapter "eFuse Controller": eFuse-Read Timing
            80: (0x2, 0x4, 0x2),
            40: (0x1, 0x2, 0x1),
            20: (0x1, 0x1, 0x1),
        }
        EFUSE_TSUR_A, EFUSE_TRD, EFUSE_THR_A = EFUSE_READING_PARAMETERS[apb_freq]
        # setting EFUSE_TSUR_A = 1 or 2 makes efuses unreadable. Need to check it with Dig team.
        # self.write_reg(EFUSE_RD_TIM_CONF_REG, EFUSE_TSUR_A << EFUSE_TSUR_A_S, EFUSE_TSUR_A_M)
        self.write_reg(EFUSE_RD_TIM_CONF_REG, EFUSE_TRD << EFUSE_TRD_S, EFUSE_TRD_M)
        self.write_reg(EFUSE_RD_TIM_CONF_REG, EFUSE_THR_A << EFUSE_THR_A_S, EFUSE_THR_A_M)

    def get_coding_scheme_warnings(self):
        """ Check if the coding scheme has detected any errors.
        Meaningless for default coding scheme (0)
        """
        warning = False
        for block in self.blocks:
            errs, fail = self.get_block_errors(block.id)
            if errs != 0 or fail:
                print("Block %d has ERRORS:%d FAIL:%d" % (block.id, errs, fail))
                warning = True
        return warning

    def summary(self):
        if self["VDD_SPI_FORCE"].get() == 0:
            output = "Flash voltage (VDD_SPI) determined by GPIO45 on reset (GPIO45=High: VDD_SPI pin is powered from internal 1.8V LDO\n"
            output += "GPIO45=Low or NC: VDD_SPI pin is powered directly from VDD3P3_RTC_IO via resistor Rspi. Typically this voltage is 3.3 V)."
        elif self["VDD_SPI_XPD"].get() == 0:
            output = "Flash voltage (VDD_SPI) internal regulator disabled by efuse."
        elif self["VDD_SPI_TIEH"].get() == 0:
            output = "Flash voltage (VDD_SPI) set to 1.8V by efuse."
        else:
            output = "Flash voltage (VDD_SPI) set to 3.3V by efuse."
        return output


class EfuseField(base_fields.EfuseFieldBase):
    @staticmethod
    def from_tuple(parent, efuse_tuple, category):
        return {
            "mac":          EfuseMacField,
            "keypurpose":   EfuseKeyPurposeField,
            "t_sensor":     EfuseTempSensor,
            "adc_tp":       EfuseAdcPointCalibration,
        }.get(category, EfuseField)(parent, *efuse_tuple)

    def get_info(self):
        output = "%s (BLOCK%d)" % (self.name, self.block)
        if self.efuse_class == "keyblock":
            err_msg = "0 errors"
            errs, fail = self.parent.get_block_errors(self.block)
            if errs != 0 or fail:
                err_msg = "ERRORS:%d FAIL:%d" % (errs, fail)
            output += "(%s):" % err_msg
            name = self.parent.blocks[self.block].key_purpose_name
            if name is not None:
                output += "\n  Purpose: %s\n " % (self.parent[name].get())
        return output


class EfuseTempSensor(EfuseField):
    def get(self, from_read=True):
        value = self.get_bitstring(from_read)
        sig = -1 if value[0] else 1
        return sig * value[1:].uint * 0.1


class EfuseAdcPointCalibration(EfuseField):
    def get(self, from_read=True):
        STEP_SIZE = 4
        value = self.get_bitstring(from_read)
        sig = -1 if value[0] else 1
        return sig * value[1:].uint * STEP_SIZE


class EfuseMacField(EfuseField):
    def check(self):
        errs, fail = self.parent.get_block_errors(self.block)
        if errs != 0 or fail:
            output = "Block%d has ERRORS:%d FAIL:%d" % (self.block, errs, fail)
        else:
            output = "OK"
        return "(" + output + ")"

    def get(self, from_read=True):
        return "%s: %s" % (util.hexify(self.get_raw(from_read), ":"), self.check())

    def burn(self, new_value):
        # Writing the BLOCK1 (MAC_SPI_8M_0) default MAC is not sensible, as it's written in the factory.
        raise esptool.FatalError("Writing Factory MAC address is not supported")


class EfuseKeyPurposeField(EfuseField):
    KEY_PURPOSES = [
        ("USER",                         0,  None,       None,      "no_need_rd_protect"),   # User purposes (software-only use)
        ("RESERVED",                     1,  None,       None,      "no_need_rd_protect"),   # Reserved
        ("XTS_AES_256_KEY_1",            2,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_256_KEY_1 (flash/PSRAM encryption)
        ("XTS_AES_256_KEY_2",            3,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_256_KEY_2 (flash/PSRAM encryption)
        ("XTS_AES_128_KEY",              4,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_128_KEY (flash/PSRAM encryption)
        ("HMAC_DOWN_ALL",                5,  None,       None,      "need_rd_protect"),      # HMAC Downstream mode
        ("HMAC_DOWN_JTAG",               6,  None,       None,      "need_rd_protect"),      # JTAG soft enable key (uses HMAC Downstream mode)
        ("HMAC_DOWN_DIGITAL_SIGNATURE",  7,  None,       None,      "need_rd_protect"),      # Digital Signature peripheral key (uses HMAC Downstream mode)
        ("HMAC_UP",                      8,  None,       None,      "need_rd_protect"),      # HMAC Upstream mode
        ("SECURE_BOOT_DIGEST0",          9,  "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST0 (Secure Boot key digest)
        ("SECURE_BOOT_DIGEST1",          10, "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST1 (Secure Boot key digest)
        ("SECURE_BOOT_DIGEST2",          11, "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST2 (Secure Boot key digest)
    ]

    KEY_PURPOSES_NAME = [name[0] for name in KEY_PURPOSES]
    DIGEST_KEY_PURPOSES = [name[0] for name in KEY_PURPOSES if name[2] == "DIGEST"]

    def check_format(self, new_value_str):
        # str convert to int: "XTS_AES_128_KEY" - > str(4)
        # if int: 4 -> str(4)
        raw_val = new_value_str
        for purpose_name in self.KEY_PURPOSES:
            if purpose_name[0] == new_value_str:
                raw_val = str(purpose_name[1])
                break
        return raw_val

    def need_reverse(self, new_key_purpose):
        for key in self.KEY_PURPOSES:
            if key[0] == new_key_purpose:
                return True if key[3] == "Reverse" else False
        return None

    def need_rd_protect(self, new_key_purpose):
        for key in self.KEY_PURPOSES:
            if key[0] == new_key_purpose:
                return True if key[4] == "need_rd_protect" else False
        return None

    def get(self, from_read=True):
        try:
            return self.KEY_PURPOSES[self.get_raw(from_read)][0]
        except IndexError:
            return " "

    def save(self, new_value):
        raw_val = new_value
        for purpose_name in self.KEY_PURPOSES:
            if purpose_name[0] == new_value:
                raw_val = purpose_name[1]
                break
        return super(EfuseKeyPurposeField, self).save(raw_val)
