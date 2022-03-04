#!/usr/bin/env python
#
# This file describes eFuses fields and registers for ESP32-C2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

from ..mem_definition_base import EfuseBlocksBase, EfuseFieldsBase, EfuseRegistersBase


# fmt: off
class EfuseDefineRegisters(EfuseRegistersBase):

    EFUSE_MEM_SIZE = (0x01FC + 4)

    # EFUSE registers & command/conf values
    DR_REG_EFUSE_BASE       = 0x60008800
    EFUSE_PGM_DATA0_REG     = DR_REG_EFUSE_BASE
    EFUSE_PGM_CHECK_VALUE0_REG  = DR_REG_EFUSE_BASE + 0x020
    EFUSE_CLK_REG           = DR_REG_EFUSE_BASE + 0x88
    EFUSE_CONF_REG          = DR_REG_EFUSE_BASE + 0x8C
    EFUSE_STATUS_REG        = DR_REG_EFUSE_BASE + 0x90
    EFUSE_CMD_REG           = DR_REG_EFUSE_BASE + 0x94
    EFUSE_RD_REPEAT_ERR_REG = DR_REG_EFUSE_BASE + 0x80
    EFUSE_RD_RS_ERR_REG     = DR_REG_EFUSE_BASE + 0x84
    EFUSE_WRITE_OP_CODE     = 0x5A5A
    EFUSE_READ_OP_CODE      = 0x5AA5
    EFUSE_PGM_CMD_MASK      = 0x3
    EFUSE_PGM_CMD           = 0x2
    EFUSE_READ_CMD          = 0x1

    BLOCK_ERRORS = [
        # error_reg,                err_num_mask, err_num_offs,     fail_bit
        (EFUSE_RD_REPEAT_ERR_REG,   None,         None,             None),  # BLOCK0
        (EFUSE_RD_RS_ERR_REG,       0x7,          0,                3),     # BLOCK1
        (EFUSE_RD_RS_ERR_REG,       0x7,          4,                7),     # BLOCK2
        (EFUSE_RD_RS_ERR_REG,       0x7,          8,                11),    # BLOCK3
    ]

    EFUSE_WR_TIM_CONF2_REG = DR_REG_EFUSE_BASE + 0x118
    EFUSE_PWR_OFF_NUM_S = 0
    EFUSE_PWR_OFF_NUM_M = 0xFFFF << EFUSE_PWR_OFF_NUM_S


class EfuseDefineBlocks(EfuseBlocksBase):

    __base_rd_regs = EfuseDefineRegisters.DR_REG_EFUSE_BASE
    __base_wr_regs = EfuseDefineRegisters.EFUSE_PGM_DATA0_REG
    # List of efuse blocks
    BLOCKS = [
        # Name,             Alias,     Index,  Read address,           Write address,  Write protect bit, Read protect bit, Len, key_purpose
        ("BLOCK0",          ["BLOCK0"],  0,  __base_rd_regs + 0x02C, __base_wr_regs,   None,              None,             2,   None),
        ("BLOCK1",          ["BLOCK1"],  1,  __base_rd_regs + 0x034, __base_wr_regs,      5,              None,             3,   None),
        ("BLOCK2",          ["BLOCK2"],  2,  __base_rd_regs + 0x040, __base_wr_regs,      6,              None,             8,   None),
        ("BLOCK_KEY0",      ["BLOCK3"],  3,  __base_rd_regs + 0x060, __base_wr_regs,      7,              [0, 1],           8,   None),
    ]

    def get_burn_block_data_names(self):
        list_of_names = []
        for block in self.BLOCKS:
            blk = self.get(block)
            if blk.name:
                list_of_names.append(blk.name)
            if blk.alias:
                for alias in blk.alias:
                    list_of_names.append(alias)
        return list_of_names

    def get_blocks_for_keys(self):
        return ['BLOCK_KEY0']


class EfuseDefineFields(EfuseFieldsBase):

    # List of efuse fields from TRM the chapter eFuse Controller.
    EFUSES = [
        #
        # Parameters in BLOCK0
        # Name                           Category Block Word Pos Type:len   WR_DIS RD_DIS Class        Description                Dictionary
        ("WR_DIS",                       "efuse",    0,  0,  0,  "uint:8",   None, None, None,         "Disables programming of individual eFuses", None),
        ("RD_DIS",                       "efuse",    0,  1,  0,  "uint:2",   0,    None, None,         "Disables software reading from BLOCK3", None),
        ("WDT_DELAY_SEL",           "WDT config",    0,  1,  2,  "uint:2",   1,    None, None,         "RTC WDT timeout threshold", None),
        ("DIS_PAD_JTAG",           "jtag config",    0,  1,  4,    "bool",   1,    None, None,         "Permanently disable JTAG access via pads"
                                                                                                       "USB JTAG is controlled separately", None),
        ("DIS_DOWNLOAD_ICACHE",       "security",    0,  1,  5,    "bool",   1,    None, None,         "Disables iCache in download mode", None),
        ("DIS_DOWNLOAD_MANUAL_ENCRYPT", "security",  0,  1,  6,    "bool",   2,    None, None,         "Disables flash encryption in Download boot modes",
                                                                                                       None),
        ("SPI_BOOT_CRYPT_CNT",          "security",  0,  1,  7,  "uint:3",   2,    None, None,         "Enables encryption and decryption, when an SPI boot"
                                                                                                       "mode is set. Enabled when 1 or 3 bits are set,"
                                                                                                       "disabled otherwise",
                                                                                                       {0: "Disable",
                                                                                                        1: "Enable",
                                                                                                        3: "Disable",
                                                                                                        7: "Enable"}),
        ("XTS_KEY_LENGTH_256",          "security",  0,  1,  10,   "bool",   2,    None, None,         "Flash encryption key length",
                                                                                                       {0: "128 bits key",
                                                                                                        1: "256 bits key"}),
        ("UART_PRINT_CONTROL",          "config",    0,  1,  11, "uint:2",   3,    None, None,         "Set UART boot message output mode",
                                                                                                       {0: "Force print",
                                                                                                        1: "Low-level print controlled by GPIO 8",
                                                                                                        3: "High-level print controlled by GPIO 8",
                                                                                                        7: "Print force disabled"}),
        ("FORCE_SEND_RESUME",           "config",    0,  1,  13,   "bool",   3,    None, None,         "Force ROM code to send a resume cmd during SPI boot",
                                                                                                       None),
        ("DIS_DOWNLOAD_MODE",           "security",  0,  1,  14,   "bool",   3,    None, None,         "Disables all Download boot modes", None),
        ("DIS_DIRECT_BOOT",             "config",    0,  1,  15,   "bool",   3,    None, None,         "Disable direct_boot mode", None),
        ("ENABLE_SECURITY_DOWNLOAD",   "security",   0,  1,  16,   "bool",   3,    None, None,         "Enables secure UART download mode "
                                                                                                       "(read/write flash only)", None),
        ("FLASH_TPUW",               "flash config", 0,  1,  17, "uint:4",   3,    None, None,         "Configures flash startup delay after SoC power-up, "
                                                                                                       "unit is (ms/2). When the value is 15, delay is 7.5 ms",
                                                                                                       None),
        ("SECURE_BOOT_EN",              "security",  0,  1,  21, "bool",     2,    None, None,         "Configures secure boot", None),
        ("SECURE_VERSION",              "identity",  0,  1,  22, "uint:4",   4,    None, "bitcount",   "Secure version (anti-rollback feature)", None),
        ("CUSTOM_MAC_USED",             "identity",  0,  1,  26, "bool",     4,    None, None,         "Enable CUSTOM_MAC programming", None),

        #
        # Parameters in BLOCK1
        # Name                          Category  Block Word Pos  Type:len WR_DIS RD_DIS Class         Description                Dictionary
        ("CUSTOM_MAC",                 "identity",   1,  0,  0,  "bytes:6",  5,    None, 'mac',        "Custom MAC addr", None),

        #
        # Parameters in BLOCK2
        # Name                          Category  Block Word Pos  Type:len WR_DIS RD_DIS Class         Description                Dictionary
        ("MAC",                        "identity",   2,  0,  0,  "bytes:6",  6,    None, 'mac',        "Factory MAC Address", None),
        ("WAFER_VERSION",              "identity",   2,  1,  16,  "uint:3",  6,    None, None,         "WAFER version",
                                                                                                       {0: "(revision 0)",
                                                                                                        1: "(revision 1)"}),
        ("PKG_VERSION",                "identity",   2,  1,  19,  "uint:3",  6,    None, None,         "Package version",
                                                                                                       {0: "ESP32-C2"}),
        ("BLOCK2_VERSION",             "identity",   2,  1,  22,  "uint:3",  6,    None, None,         "Version of BLOCK2",
                                                                                                       {0: "No calibration", 1: "With calibration"}),

        ("RF_REF_I_BIAS_CONFIG",             "rf",   2,  1,  25,  "uint:3",  6,    None, None,         "", None),
        ("LDO_VOL_BIAS_CONFIG_LOW",         "ldo",   2,  1,  29,  "uint:3",  6,    None, None,         "", None),
        ("LDO_VOL_BIAS_CONFIG_HIGH",        "ldo",   2,  2,   0,  "uint:27", 6,    None, None,         "", None),
        ("PVT_LOW",                         "pvt",   2,  2,  27,  "uint:5",  6,    None, None,         "", None),
        ("PVT_HIGH",                        "pvt",   2,  3,   0,  "uint:10", 6,    None, None,         "", None),
        ("ADC_CALIBRATION_0",         "adc_calib",   2,  3,  10,  "uint:22", 6,    None, None,         "", None),
        ("ADC_CALIBRATION_1",         "adc_calib",   2,  4,   0,  "uint:32", 6,    None, None,         "", None),
        ("ADC_CALIBRATION_2",         "adc_calib",   2,  5,   0,  "uint:32", 6,    None, None,         "", None),
    ]

    KEYBLOCKS = [
        # Name           Category      Block Word Pos Type:len  WR_DIS RD_DIS Class         Description                Dictionary
        ('BLOCK_KEY0',         "security", 3,  0, 0,  "bytes:32", 7, [0, 1], "keyblock", "BLOCK_KEY0 - 256-bits. 256-bit key of Flash Encryption", None),
        ('BLOCK_KEY0_LOW_128', "security", 3,  0, 0,  "bytes:16", 7, 0,      "keyblock", "BLOCK_KEY0 - lower 128-bits. 128-bit key of Flash Encryption", None),
        ('BLOCK_KEY0_HI_128',  "security", 3,  4, 0,  "bytes:16", 7, 1,      "keyblock", "BLOCK_KEY0 - higher 128-bits. 128-bits key of Secure Boot.", None),
    ]

    # if BLOCK2_VERSION is 1, these efuse fields are in BLOCK2
    BLOCK2_CALIBRATION_EFUSES = [
        # Name                      Category      Block Word Pos Type:len  WR_DIS RD_DIS Class         Description                Dictionary
    ]
# fmt: on
