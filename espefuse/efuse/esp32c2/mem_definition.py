# This file describes eFuses fields and registers for ESP32-C2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import os

import yaml

from ..mem_definition_base import (
    EfuseBlocksBase,
    EfuseFieldsBase,
    EfuseRegistersBase,
)


class EfuseDefineRegisters(EfuseRegistersBase):
    EFUSE_MEM_SIZE = 0x01FC + 4

    # EFUSE registers & command/conf values
    DR_REG_EFUSE_BASE = 0x60008800
    EFUSE_PGM_DATA0_REG = DR_REG_EFUSE_BASE
    EFUSE_PGM_CHECK_VALUE0_REG = DR_REG_EFUSE_BASE + 0x020
    EFUSE_CLK_REG = DR_REG_EFUSE_BASE + 0x88
    EFUSE_CONF_REG = DR_REG_EFUSE_BASE + 0x8C
    EFUSE_STATUS_REG = DR_REG_EFUSE_BASE + 0x90
    EFUSE_CMD_REG = DR_REG_EFUSE_BASE + 0x94
    EFUSE_RD_REPEAT_ERR_REG = DR_REG_EFUSE_BASE + 0x80
    EFUSE_RD_RS_ERR_REG = DR_REG_EFUSE_BASE + 0x84
    EFUSE_WRITE_OP_CODE = 0x5A5A
    EFUSE_READ_OP_CODE = 0x5AA5
    EFUSE_PGM_CMD_MASK = 0x3
    EFUSE_PGM_CMD = 0x2
    EFUSE_READ_CMD = 0x1

    BLOCK_ERRORS = [
        # error_reg,                err_num_mask, err_num_offs,     fail_bit
        (EFUSE_RD_REPEAT_ERR_REG, None, None, None),  # BLOCK0
        (EFUSE_RD_RS_ERR_REG, 0x7, 0, 3),  # BLOCK1
        (EFUSE_RD_RS_ERR_REG, 0x7, 4, 7),  # BLOCK2
        (EFUSE_RD_RS_ERR_REG, 0x7, 8, 11),  # BLOCK3
    ]

    EFUSE_WR_TIM_CONF2_REG = DR_REG_EFUSE_BASE + 0x118
    EFUSE_PWR_OFF_NUM_S = 0
    EFUSE_PWR_OFF_NUM_M = 0xFFFF << EFUSE_PWR_OFF_NUM_S

    EFUSE_WR_TIM_CONF0_REG = DR_REG_EFUSE_BASE + 0x110
    EFUSE_TPGM_INACTIVE_S = 8
    EFUSE_TPGM_INACTIVE_M = 0xFF << EFUSE_TPGM_INACTIVE_S

    EFUSE_WR_TIM_CONF1_REG = DR_REG_EFUSE_BASE + 0x114
    EFUSE_PWR_ON_NUM_S = 8
    EFUSE_PWR_ON_NUM_M = 0x0000FFFF << EFUSE_PWR_ON_NUM_S

    EFUSE_DAC_CONF_REG = DR_REG_EFUSE_BASE + 0x108
    EFUSE_DAC_CLK_DIV_S = 0
    EFUSE_DAC_CLK_DIV_M = 0xFF << EFUSE_DAC_CLK_DIV_S

    # EFUSE_DAC_CONF_REG
    EFUSE_DAC_NUM_S = 9
    EFUSE_DAC_NUM_M = 0xFF << EFUSE_DAC_NUM_S


class EfuseDefineBlocks(EfuseBlocksBase):
    __base_rd_regs = EfuseDefineRegisters.DR_REG_EFUSE_BASE
    __base_wr_regs = EfuseDefineRegisters.EFUSE_PGM_DATA0_REG
    # List of efuse blocks
    # fmt: off
    BLOCKS = [
        # Name,             Alias,     Index,  Read address,           Write address,  Write protect bit, Read protect bit, Len, key_purpose
        ("BLOCK0",          ["BLOCK0"],  0,  __base_rd_regs + 0x02C, __base_wr_regs,   None,              None,             2,   None),
        ("BLOCK1",          ["BLOCK1"],  1,  __base_rd_regs + 0x034, __base_wr_regs,      5,              None,             3,   None),
        ("BLOCK2",          ["BLOCK2"],  2,  __base_rd_regs + 0x040, __base_wr_regs,      6,              None,             8,   None),
        ("BLOCK_KEY0",      ["BLOCK3"],  3,  __base_rd_regs + 0x060, __base_wr_regs,      7,              [0, 1],           8,   None),
    ]
    # fmt: on

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
        return ["BLOCK_KEY0"]


class EfuseDefineFields(EfuseFieldsBase):
    def __init__(self) -> None:
        # List of efuse fields from TRM the chapter eFuse Controller.
        self.EFUSES = []

        self.KEYBLOCKS = []

        # if BLK_VERSION_MINOR is 1, these efuse fields are in BLOCK2
        self.BLOCK2_CALIBRATION_EFUSES = []

        dir_name = os.path.dirname(os.path.abspath(__file__))
        dir_name, file_name = os.path.split(dir_name)
        file_name = file_name + ".yaml"
        dir_name, _ = os.path.split(dir_name)
        efuse_file = os.path.join(dir_name, "efuse_defs", file_name)
        with open(f"{efuse_file}", "r") as r_file:
            e_desc = yaml.safe_load(r_file)
        super().__init__(e_desc)

        for i, efuse in enumerate(self.ALL_EFUSES):
            if efuse.name in ["BLOCK_KEY0"]:
                self.KEYBLOCKS.append(efuse)
                BLOCK_KEY0_LOW_128 = copy.deepcopy(efuse)
                BLOCK_KEY0_LOW_128.name = "BLOCK_KEY0_LOW_128"
                BLOCK_KEY0_LOW_128.type = "bytes:16"
                BLOCK_KEY0_LOW_128.bit_len = 16 * 8
                BLOCK_KEY0_LOW_128.description = (
                    "BLOCK_KEY0 - lower 128-bits. 128-bit key of Flash Encryption"
                )
                BLOCK_KEY0_LOW_128.read_disable_bit = efuse.read_disable_bit[0]
                self.KEYBLOCKS.append(BLOCK_KEY0_LOW_128)
                BLOCK_KEY0_HI_128 = copy.deepcopy(efuse)
                BLOCK_KEY0_HI_128.name = "BLOCK_KEY0_HI_128"
                BLOCK_KEY0_HI_128.word = 4
                BLOCK_KEY0_HI_128.type = "bytes:16"
                BLOCK_KEY0_HI_128.bit_len = 16 * 8
                BLOCK_KEY0_HI_128.description = (
                    "BLOCK_KEY0 - higher 128-bits. 128-bits key of Secure Boot"
                )
                BLOCK_KEY0_HI_128.read_disable_bit = efuse.read_disable_bit[1]
                self.KEYBLOCKS.append(BLOCK_KEY0_HI_128)
                self.ALL_EFUSES[i] = None

            elif efuse.category == "calibration":
                self.BLOCK2_CALIBRATION_EFUSES.append(efuse)
                self.ALL_EFUSES[i] = None

        for efuse in self.ALL_EFUSES:
            if efuse is not None:
                self.EFUSES.append(efuse)

        self.ALL_EFUSES = []
