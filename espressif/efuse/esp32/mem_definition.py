#!/usr/bin/env python
# This file describes eFuses fields and registers for ESP32 chip
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

from ..mem_definition_base import EfuseBlocksBase, EfuseFieldsBase, EfuseRegistersBase


class EfuseDefineRegisters(EfuseRegistersBase):

    EFUSE_MEM_SIZE = (0x011C + 4)

    # EFUSE registers & command/conf values
    DR_REG_EFUSE_BASE   = 0x3ff5A000
    EFUSE_REG_CONF      = DR_REG_EFUSE_BASE + 0x0FC
    EFUSE_CONF_WRITE    = 0x5A5A
    EFUSE_CONF_READ     = 0x5AA5
    EFUSE_REG_CMD       = DR_REG_EFUSE_BASE + 0x104
    EFUSE_CMD_OP_MASK   = 0x3
    EFUSE_CMD_WRITE     = 0x2
    EFUSE_CMD_READ      = 0x1

    # 3/4 Coding scheme warnings registers
    EFUSE_REG_DEC_STATUS        = DR_REG_EFUSE_BASE + 0x11C
    EFUSE_REG_DEC_STATUS_MASK   = 0xFFF

    # Coding Scheme
    EFUSE_CODING_SCHEME_WORD    = 6
    EFUSE_CODING_SCHEME_MASK    = 0x3

    # Efuse clock control
    EFUSE_DAC_CONF_REG      = DR_REG_EFUSE_BASE + 0x118
    EFUSE_CLK_REG           = DR_REG_EFUSE_BASE + 0x0F8
    EFUSE_DAC_CLK_DIV_MASK  = 0xFF
    EFUSE_CLK_SEL0_MASK     = 0x00FF
    EFUSE_CLK_SEL1_MASK     = 0xFF00

    EFUSE_CLK_SETTINGS = {
        # APB freq: clk_sel0, clk_sel1, dac_clk_div
        # Taken from TRM chapter "eFuse Controller": Timing Configuration
        26: (250, 255, 52),
        40: (160, 255, 80),
        80: (80, 128, 100),  # this is here for completeness only as esptool never sets an 80MHz APB clock
    }


class EfuseDefineBlocks(EfuseBlocksBase):

    __base_regs = EfuseDefineRegisters.DR_REG_EFUSE_BASE
    # List of efuse blocks
    BLOCKS = [
        # Name, Alias, Index, Read address, Write address, Write protect bit, Read protect bit, Len, key_purpose
        ("BLOCK0",    [],                                     0, __base_regs + 0x000, __base_regs + 0x01C, None, None, 7, None),
        ("BLOCK1",    ["flash_encryption"],                   1, __base_regs + 0x038, __base_regs + 0x098, 7,    0,    8, None),
        ("BLOCK2",    ["secure_boot_v1", "secure_boot_v2"],   2, __base_regs + 0x058, __base_regs + 0x0B8, 8,    1,    8, None),
        ("BLOCK3",    [],                                     3, __base_regs + 0x078, __base_regs + 0x0D8, 9,    2,    8, None),
    ]

    def get_burn_block_data_names(self):
        list_of_names = []
        for block in self.BLOCKS:
            blk = self.get(block)
            if blk.name:
                list_of_names.append(blk.name)
        return list_of_names


class EfuseDefineFields(EfuseFieldsBase):

    # Lists of efuse fields
    EFUSES = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('WR_DIS',               "efuse",       0, 0, 0,   "uint:16",   1,    None, None,       "Efuse write disable mask", None),
        ('RD_DIS',               "efuse",       0, 0, 16,  "uint:4",    0,    None, None,       "Efuse read disable mask", None),
        ('CODING_SCHEME',        "efuse",       0, 6, 0,   "uint:2",    10,   3,    None,       "Efuse variable block length scheme",
            {0: "NONE (BLK1-3 len=256 bits)",
             1: "3/4 (BLK1-3 len=192 bits)",
             2: "REPEAT (BLK1-3 len=128 bits) not supported",
             3: "NONE (BLK1-3 len=256 bits)"}),
        ('KEY_STATUS',           "efuse",       0, 6, 10,  "bool",      10,   3,    None,       "Usage of efuse block 3 (reserved)", None),
        ('MAC',                  "identity",    0, 1, 0,   "bytes:6",   3,    None, "mac",      "Factory MAC Address", None),
        ('MAC_CRC',              "identity",    0, 2, 16,  "uint:8",    3,    None, None,       "CRC8 for factory MAC address", None),
        ('CHIP_VER_REV1',        "identity",    0, 3, 15,  "bool",      3,    None, None,       "Silicon Revision 1", None),
        ('CHIP_VER_REV2',        "identity",    0, 5, 20,  "bool",      6,    None, None,       "Silicon Revision 2", None),
        ('CHIP_VERSION',         "identity",    0, 3, 12,  "uint:2",    3,    None, None,       "Reserved for future chip versions", None),
        ('CHIP_PACKAGE',         "identity",    0, 3, 9,   "uint:3",    3,    None, None,       "Chip package identifier", None),
        ('XPD_SDIO_FORCE',       "config",      0, 4, 16,  "bool",      5,    None, None,       "Ignore MTDI pin (GPIO12) for VDD_SDIO on reset", None),
        ('XPD_SDIO_REG',         "config",      0, 4, 14,  "bool",      5,    None, None,       "If XPD_SDIO_FORCE, enable VDD_SDIO reg on reset", None),
        ('XPD_SDIO_TIEH',        "config",      0, 4, 15,  "bool",      5,    None, None,       "If XPD_SDIO_FORCE & XPD_SDIO_REG",
         {1: "3.3V",
          0: "1.8V"}),
        ('CLK8M_FREQ',           "config",      0, 4, 0,   "uint:8",    None, None, None,       "8MHz clock freq override", None),
        ('SPI_PAD_CONFIG_CLK',   "config",      0, 5, 0,   "uint:5",    6,    None, "spipin",   "Override SD_CLK pad (GPIO6/SPICLK)", None),
        ('SPI_PAD_CONFIG_Q',     "config",      0, 5, 5,   "uint:5",    6,    None, "spipin",   "Override SD_DATA_0 pad (GPIO7/SPIQ)", None),
        ('SPI_PAD_CONFIG_D',     "config",      0, 5, 10,  "uint:5",    6,    None, "spipin",   "Override SD_DATA_1 pad (GPIO8/SPID)", None),
        ('SPI_PAD_CONFIG_HD',    "config",      0, 3, 4,   "uint:5",    6,    None, "spipin",   "Override SD_DATA_2 pad (GPIO9/SPIHD)", None),
        ('SPI_PAD_CONFIG_CS0',   "config",      0, 5, 15,  "uint:5",    6,    None, "spipin",   "Override SD_CMD pad (GPIO11/SPICS0)", None),
        ('DISABLE_SDIO_HOST',    "config",      0, 6, 3,   "bool",      None, None, None,       "Disable SDIO host", None),
        ('FLASH_CRYPT_CNT',      "security",    0, 0, 20,  "uint:7",    2,    None, "bitcount", "Flash encryption mode counter", None),
        ('UART_DOWNLOAD_DIS',    "security",    0, 0, 27,  "bool",      2,    None, None,       "Disable UART download mode (ESP32 rev3 only)", None),
        ('FLASH_CRYPT_CONFIG',    "security",   0, 5, 28,  "uint:4",    10,   3,    None,       "Flash encryption config (key tweak bits)", None),
        ('CONSOLE_DEBUG_DISABLE', "security",   0, 6, 2,   "bool",      15,   None, None,       "Disable ROM BASIC interpreter fallback", None),
        ('ABS_DONE_0',           "security",    0, 6, 4,   "bool",      12,   None, None,       "Secure boot V1 is enabled for bootloader image", None),
        ('ABS_DONE_1',           "security",    0, 6, 5,   "bool",      13,   None, None,       "Secure boot V2 is enabled for bootloader image", None),
        ('JTAG_DISABLE',         "security",    0, 6, 6,   "bool",      14,   None, None,       "Disable JTAG", None),
        ('DISABLE_DL_ENCRYPT',   "security",    0, 6, 7,   "bool",      15,   None, None,       "Disable flash encryption in UART bootloader", None),
        ('DISABLE_DL_DECRYPT',   "security",    0, 6, 8,   "bool",      15,   None, None,       "Disable flash decryption in UART bootloader", None),
        ('DISABLE_DL_CACHE',     "security",    0, 6, 9,   "bool",      15,   None, None,       "Disable flash cache in UART bootloader", None),
        ('BLK3_PART_RESERVE',    "calibration", 0, 3, 14,  "bool",      10,   3,    None,       "BLOCK3 partially served for ADC calibration data", None),
        ('ADC_VREF',             "calibration", 0, 4, 8,   "uint:5",    0,    None, "vref",     "Voltage reference calibration", None),
        ('MAC_VERSION',          "identity",    3, 5, 24,  "uint:8",    9,    2,    None,       "Version of the MAC field",
         {1: "Custom MAC in BLOCK3"}),
    ]

    # if MAC_VERSION is set "1", these efuse fields are in BLOCK3:
    CUSTOM_MAC = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('CUSTOM_MAC',           "identity",    3, 0, 8,   "bytes:6",   9,    2,   "mac",       "Custom MAC", None),
        ('CUSTOM_MAC_CRC',       "identity",    3, 0, 0,   "uint:8",    9,    2,    None,       "CRC of custom MAC", None),
    ]

    # The len of fields depends on coding scheme: for CODING_SCHEME_NONE
    KEYBLOCKS_256 = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('BLOCK1',                 "security",    1, 0, 0,   "bytes:32", 7,    0,    "keyblock", "Flash encryption key", None),
        ('BLOCK2',                 "security",    2, 0, 0,   "bytes:32", 8,    1,    "keyblock", "Secure boot key", None),
        ('BLOCK3',                 "security",    3, 0, 0,   "bytes:32", 9,    2,    "keyblock", "Variable Block 3", None),
    ]

    # The len of fields depends on coding scheme: for CODING_SCHEME_34
    KEYBLOCKS_192 = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('BLOCK1',                 "security",    1, 0, 0,   "bytes:24", 7,    0,    "keyblock", "Flash encryption key", None),
        ('BLOCK2',                 "security",    2, 0, 0,   "bytes:24", 8,    1,    "keyblock", "Secure boot key", None),
        ('BLOCK3',                 "security",    3, 0, 0,   "bytes:24", 9,    2,    "keyblock", "Variable Block 3", None),
    ]

    # if BLK3_PART_RESERVE is set, these efuse fields are in BLOCK3:
    ADC_CALIBRATION = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('ADC1_TP_LOW',          "calibration", 3, 3, 0,   "uint:7",    9,    2,    "adc_tp",   "ADC1 150mV reading", None),
        ('ADC1_TP_HIGH',         "calibration", 3, 3, 7,   "uint:9",    9,    2,    "adc_tp",   "ADC1 850mV reading", None),
        ('ADC2_TP_LOW',          "calibration", 3, 3, 16,  "uint:7",    9,    2,    "adc_tp",   "ADC2 150mV reading", None),
        ('ADC2_TP_HIGH',         "calibration", 3, 3, 23,  "uint:9",    9,    2,    "adc_tp",   "ADC2 850mV reading", None),
    ]
