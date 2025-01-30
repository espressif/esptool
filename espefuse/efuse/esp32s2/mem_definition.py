# This file describes eFuses fields and registers for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os

import yaml

from ..mem_definition_base import (
    EfuseBlocksBase,
    EfuseFieldsBase,
    EfuseRegistersBase,
    Field,
)


class EfuseDefineRegisters(EfuseRegistersBase):
    EFUSE_MEM_SIZE = 0x01FC + 4

    # EFUSE registers & command/conf values
    DR_REG_EFUSE_BASE = 0x3F41A000
    EFUSE_PGM_DATA0_REG = DR_REG_EFUSE_BASE
    EFUSE_CHECK_VALUE0_REG = DR_REG_EFUSE_BASE + 0x020
    EFUSE_CLK_REG = DR_REG_EFUSE_BASE + 0x1C8
    EFUSE_CONF_REG = DR_REG_EFUSE_BASE + 0x1CC
    EFUSE_STATUS_REG = DR_REG_EFUSE_BASE + 0x1D0
    EFUSE_CMD_REG = DR_REG_EFUSE_BASE + 0x1D4
    EFUSE_RD_RS_ERR0_REG = DR_REG_EFUSE_BASE + 0x194
    EFUSE_RD_RS_ERR1_REG = DR_REG_EFUSE_BASE + 0x198
    EFUSE_RD_REPEAT_ERR0_REG = DR_REG_EFUSE_BASE + 0x17C
    EFUSE_RD_REPEAT_ERR1_REG = DR_REG_EFUSE_BASE + 0x180
    EFUSE_RD_REPEAT_ERR2_REG = DR_REG_EFUSE_BASE + 0x184
    EFUSE_RD_REPEAT_ERR3_REG = DR_REG_EFUSE_BASE + 0x188
    EFUSE_RD_REPEAT_ERR4_REG = DR_REG_EFUSE_BASE + 0x18C
    EFUSE_DAC_CONF_REG = DR_REG_EFUSE_BASE + 0x1E8
    EFUSE_RD_TIM_CONF_REG = DR_REG_EFUSE_BASE + 0x1EC
    EFUSE_WR_TIM_CONF1_REG = DR_REG_EFUSE_BASE + 0x1F4
    EFUSE_WR_TIM_CONF2_REG = DR_REG_EFUSE_BASE + 0x1F8
    EFUSE_DATE_REG = DR_REG_EFUSE_BASE + 0x1FC
    EFUSE_WRITE_OP_CODE = 0x5A5A
    EFUSE_READ_OP_CODE = 0x5AA5
    EFUSE_PGM_CMD_MASK = 0x3
    EFUSE_PGM_CMD = 0x2
    EFUSE_READ_CMD = 0x1

    BLOCK_ERRORS = [
        # error_reg,               err_num_mask, err_num_offs,     fail_bit
        (EFUSE_RD_REPEAT_ERR0_REG, None, None, None),  # BLOCK0
        (EFUSE_RD_RS_ERR0_REG, 0x7, 0, 3),  # MAC_SPI_8M_0
        (EFUSE_RD_RS_ERR0_REG, 0x7, 4, 7),  # BLOCK_SYS_DATA
        (EFUSE_RD_RS_ERR0_REG, 0x7, 8, 11),  # BLOCK_USR_DATA
        (EFUSE_RD_RS_ERR0_REG, 0x7, 12, 15),  # BLOCK_KEY0
        (EFUSE_RD_RS_ERR0_REG, 0x7, 16, 19),  # BLOCK_KEY1
        (EFUSE_RD_RS_ERR0_REG, 0x7, 20, 23),  # BLOCK_KEY2
        (EFUSE_RD_RS_ERR0_REG, 0x7, 24, 27),  # BLOCK_KEY3
        (EFUSE_RD_RS_ERR0_REG, 0x7, 28, 31),  # BLOCK_KEY4
        (EFUSE_RD_RS_ERR1_REG, 0x7, 0, 3),  # BLOCK_KEY5
        (EFUSE_RD_RS_ERR1_REG, 0x7, 4, 7),  # BLOCK_SYS_DATA2
    ]

    EFUSE_DAC_CONF_REG = DR_REG_EFUSE_BASE + 0x1E8
    EFUSE_DAC_CLK_DIV_S = 0
    EFUSE_DAC_CLK_DIV_M = 0xFF << EFUSE_DAC_CLK_DIV_S

    EFUSE_RD_TIM_CONF_REG = DR_REG_EFUSE_BASE + 0x1EC
    EFUSE_TSUR_A_S = 16
    EFUSE_TSUR_A_M = 0xFF << EFUSE_TSUR_A_S
    EFUSE_TRD_S = 8
    EFUSE_TRD_M = 0xFF << EFUSE_TRD_S
    EFUSE_THR_A_S = 0
    EFUSE_THR_A_M = 0xFF << EFUSE_THR_A_S

    EFUSE_WR_TIM_CONF0_REG = DR_REG_EFUSE_BASE + 0x1F0
    EFUSE_TPGM_S = 16
    EFUSE_TPGM_M = 0xFFFF << EFUSE_TPGM_S
    EFUSE_TPGM_INACTIVE_S = 8
    EFUSE_TPGM_INACTIVE_M = 0xFF << EFUSE_TPGM_INACTIVE_S
    EFUSE_THP_A_S = 0
    EFUSE_THP_A_M = 0xFF << EFUSE_THP_A_S

    # EFUSE_WR_TIM_CONF1_REG
    EFUSE_PWR_ON_NUM_S = 8
    EFUSE_PWR_ON_NUM_M = 0xFFFF << EFUSE_PWR_ON_NUM_S
    EFUSE_TSUP_A_S = 0
    EFUSE_TSUP_A_M = 0xFF << EFUSE_TSUP_A_S

    # EFUSE_WR_TIM_CONF2_REG
    EFUSE_PWR_OFF_NUM_S = 0
    EFUSE_PWR_OFF_NUM_M = 0xFFFF << EFUSE_PWR_OFF_NUM_S

    # Configure clock
    EFUSE_PROGRAMMING_TIMING_PARAMETERS = {
        # APB Frequency: ( EFUSE_TSUP_A, EFUSE_TPGM, EFUSE_THP_A, EFUSE_TPGM_INACTIVE )
        # Taken from TRM chapter "eFuse Controller": eFuse-Programming Timing
        80: (0x2, 0x320, 0x2, 0x4),
        40: (0x1, 0x190, 0x1, 0x2),
        20: (0x1, 0xC8, 0x1, 0x1),
    }

    VDDQ_TIMING_PARAMETERS = {
        # APB Frequency: ( EFUSE_DAC_CLK_DIV, EFUSE_PWR_ON_NUM, EFUSE_PWR_OFF_NUM )
        # Taken from TRM chapter "eFuse Controller": eFuse VDDQ Timing Setting
        80: (0xA0, 0xA200, 0x100),
        40: (0x50, 0x5100, 0x80),
        20: (0x28, 0x2880, 0x40),
    }

    EFUSE_READING_PARAMETERS = {
        # APB Frequency: ( EFUSE_TSUR_A, EFUSE_TRD, EFUSE_THR_A )
        # Taken from TRM chapter "eFuse Controller": eFuse-Read Timing
        80: (0x2, 0x4, 0x2),
        40: (0x1, 0x2, 0x1),
        20: (0x1, 0x1, 0x1),
    }


class EfuseDefineBlocks(EfuseBlocksBase):
    __base_rd_regs = EfuseDefineRegisters.DR_REG_EFUSE_BASE
    __base_wr_regs = EfuseDefineRegisters.EFUSE_PGM_DATA0_REG
    # List of efuse blocks
    # fmt: off
    BLOCKS = [
        # Name,             Alias,   Index,  Read address,                           Write address,   Write protect bit, Read protect bit, Len, key_purpose
        ("BLOCK0",          [],          0,  __base_rd_regs + 0x02C, __base_wr_regs, None, None, 6, None),
        ("MAC_SPI_8M_0",    ["BLOCK1"],  1,  __base_rd_regs + 0x044, __base_wr_regs, 20,   None, 6, None),
        ("BLOCK_SYS_DATA",  ["BLOCK2"],  2,  __base_rd_regs + 0x05C, __base_wr_regs, 21,   None, 8, None),
        ("BLOCK_USR_DATA",  ["BLOCK3"],  3,  __base_rd_regs + 0x07C, __base_wr_regs, 22,   None, 8, None),
        ("BLOCK_KEY0",      ["BLOCK4"],  4,  __base_rd_regs + 0x09C, __base_wr_regs, 23,   0,    8, "KEY_PURPOSE_0"),
        ("BLOCK_KEY1",      ["BLOCK5"],  5,  __base_rd_regs + 0x0BC, __base_wr_regs, 24,   1,    8, "KEY_PURPOSE_1"),
        ("BLOCK_KEY2",      ["BLOCK6"],  6,  __base_rd_regs + 0x0DC, __base_wr_regs, 25,   2,    8, "KEY_PURPOSE_2"),
        ("BLOCK_KEY3",      ["BLOCK7"],  7,  __base_rd_regs + 0x0FC, __base_wr_regs, 26,   3,    8, "KEY_PURPOSE_3"),
        ("BLOCK_KEY4",      ["BLOCK8"],  8,  __base_rd_regs + 0x11C, __base_wr_regs, 27,   4,    8, "KEY_PURPOSE_4"),
        ("BLOCK_KEY5",      ["BLOCK9"],  9,  __base_rd_regs + 0x13C, __base_wr_regs, 28,   5,    8, "KEY_PURPOSE_5"),
        ("BLOCK_SYS_DATA2", ["BLOCK10"], 10, __base_rd_regs + 0x15C, __base_wr_regs, 29,   6,    8, None),
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


class EfuseDefineFields(EfuseFieldsBase):
    def __init__(self, extend_efuse_table) -> None:
        # List of efuse fields from TRM the chapter eFuse Controller.
        self.EFUSES = []
        self.KEYBLOCKS = []
        self.BLOCK2_CALIBRATION_EFUSES = []
        self.CALC = []

        dir_name = os.path.dirname(os.path.abspath(__file__))
        dir_name, file_name = os.path.split(dir_name)
        file_name = file_name + ".yaml"
        dir_name, _ = os.path.split(dir_name)
        efuse_file = os.path.join(dir_name, "efuse_defs", file_name)
        with open(f"{efuse_file}", "r") as r_file:
            e_desc = yaml.safe_load(r_file)
        super().__init__(e_desc, extend_efuse_table)

        for i, efuse in enumerate(self.ALL_EFUSES):
            if efuse.name in [
                "BLOCK_USR_DATA",
                "BLOCK_KEY0",
                "BLOCK_KEY1",
                "BLOCK_KEY2",
                "BLOCK_KEY3",
                "BLOCK_KEY4",
                "BLOCK_KEY5",
                "BLOCK_SYS_DATA2",
            ]:
                if efuse.name == "BLOCK_USR_DATA":
                    efuse.bit_len = 256
                    efuse.type = "bytes:32"
                self.KEYBLOCKS.append(efuse)
                self.ALL_EFUSES[i] = None

            elif efuse.category == "calibration":
                self.BLOCK2_CALIBRATION_EFUSES.append(efuse)
                self.ALL_EFUSES[i] = None

        f = Field()
        f.name = "WAFER_VERSION_MINOR"
        f.block = 0
        f.bit_len = 4
        f.type = f"uint:{f.bit_len}"
        f.category = "identity"
        f.class_type = "wafer"
        f.description = "calc WAFER VERSION MINOR = WAFER_VERSION_MINOR_HI << 3 + WAFER_VERSION_MINOR_LO (read only)"
        self.CALC.append(f)

        for efuse in self.ALL_EFUSES:
            if efuse is not None:
                self.EFUSES.append(efuse)

        self.ALL_EFUSES = []
