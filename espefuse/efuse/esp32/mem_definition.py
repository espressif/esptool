# This file describes eFuses fields and registers for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import os

import yaml

from ..mem_definition_base import (
    EfuseBlocksBase,
    EfuseFieldsBase,
    EfuseRegistersBase,
    Field,
)


class EfuseDefineRegisters(EfuseRegistersBase):
    EFUSE_MEM_SIZE = 0x011C + 4

    # EFUSE registers & command/conf values
    DR_REG_EFUSE_BASE = 0x3FF5A000
    EFUSE_REG_CONF = DR_REG_EFUSE_BASE + 0x0FC
    EFUSE_CONF_WRITE = 0x5A5A
    EFUSE_CONF_READ = 0x5AA5
    EFUSE_REG_CMD = DR_REG_EFUSE_BASE + 0x104
    EFUSE_CMD_OP_MASK = 0x3
    EFUSE_CMD_WRITE = 0x2
    EFUSE_CMD_READ = 0x1

    # 3/4 Coding scheme warnings registers
    EFUSE_REG_DEC_STATUS = DR_REG_EFUSE_BASE + 0x11C
    EFUSE_REG_DEC_STATUS_MASK = 0xFFF

    # Coding Scheme
    EFUSE_CODING_SCHEME_WORD = 6
    EFUSE_CODING_SCHEME_MASK = 0x3

    # Efuse clock control
    EFUSE_DAC_CONF_REG = DR_REG_EFUSE_BASE + 0x118
    EFUSE_CLK_REG = DR_REG_EFUSE_BASE + 0x0F8
    EFUSE_DAC_CLK_DIV_MASK = 0xFF
    EFUSE_CLK_SEL0_MASK = 0x00FF
    EFUSE_CLK_SEL1_MASK = 0xFF00

    EFUSE_CLK_SETTINGS = {
        # APB freq: clk_sel0, clk_sel1, dac_clk_div
        # Taken from TRM chapter "eFuse Controller": Timing Configuration
        # 80 is here for completeness only as esptool never sets an 80MHz APB clock
        26: (250, 255, 52),
        40: (160, 255, 80),
        80: (80, 128, 100),
    }

    DR_REG_SYSCON_BASE = 0x3FF66000
    APB_CTL_DATE_ADDR = DR_REG_SYSCON_BASE + 0x7C
    APB_CTL_DATE_V = 0x1
    APB_CTL_DATE_S = 31

    EFUSE_BLK0_RDATA3_REG = DR_REG_EFUSE_BASE + 0x00C
    EFUSE_RD_CHIP_VER_REV1 = 1 << 15

    EFUSE_BLK0_RDATA5_REG = DR_REG_EFUSE_BASE + 0x014
    EFUSE_RD_CHIP_VER_REV2 = 1 << 20


class EfuseDefineBlocks(EfuseBlocksBase):
    __base_regs = EfuseDefineRegisters.DR_REG_EFUSE_BASE
    # List of efuse blocks
    # fmt: off
    BLOCKS = [
        # Name, Alias, Index, Read address, Write address, Write protect bit, Read protect bit, Len, key_purpose
        ("BLOCK0",    [],                                     0, __base_regs + 0x000, __base_regs + 0x01C, None, None, 7, None),
        ("BLOCK1",    ["flash_encryption"],                   1, __base_regs + 0x038, __base_regs + 0x098, 7,    0,    8, None),
        ("BLOCK2",    ["secure_boot_v1", "secure_boot_v2"],   2, __base_regs + 0x058, __base_regs + 0x0B8, 8,    1,    8, None),
        ("BLOCK3",    [],                                     3, __base_regs + 0x078, __base_regs + 0x0D8, 9,    2,    8, None),
    ]
    # fmt: on

    def get_burn_block_data_names(self):
        list_of_names = []
        for block in self.BLOCKS:
            blk = self.get(block)
            if blk.name:
                list_of_names.append(blk.name)
        return list_of_names


class EfuseDefineFields(EfuseFieldsBase):
    def __init__(self) -> None:
        self.EFUSES = []
        # if MAC_VERSION is set "1", these efuse fields are in BLOCK3:
        self.CUSTOM_MAC = []
        # The len of fields depends on coding scheme: for CODING_SCHEME_NONE
        self.KEYBLOCKS_256 = []
        # The len of fields depends on coding scheme: for CODING_SCHEME_34
        self.KEYBLOCKS_192 = []
        # if BLK3_PART_RESERVE is set, these efuse fields are in BLOCK3:
        self.ADC_CALIBRATION = []

        self.CALC = []

        dir_name = os.path.dirname(os.path.abspath(__file__))
        dir_name, file_name = os.path.split(dir_name)
        file_name = file_name + ".yaml"
        dir_name, _ = os.path.split(dir_name)
        efuse_file = os.path.join(dir_name, "efuse_defs", file_name)
        with open(f"{efuse_file}", "r") as r_file:
            e_desc = yaml.safe_load(r_file)
        super().__init__(e_desc)

        for i, efuse in enumerate(self.ALL_EFUSES):
            if efuse.name == "BLOCK1" or efuse.name == "BLOCK2":
                self.KEYBLOCKS_256.append(efuse)
                BLOCK = copy.deepcopy(efuse)
                BLOCK.type = "bytes:24"
                BLOCK.bit_len = 24 * 8
                self.KEYBLOCKS_192.append(BLOCK)
                self.ALL_EFUSES[i] = None

            elif efuse.name == "MAC_VERSION":
                # A field from BLOCK3, It is used as a template
                BLOCK3 = copy.deepcopy(efuse)
                BLOCK3.name = "BLOCK3"
                BLOCK3.block = 3
                BLOCK3.word = 0
                BLOCK3.pos = 0
                BLOCK3.bit_len = 32 * 8
                BLOCK3.type = "bytes:32"
                BLOCK3.category = "security"
                BLOCK3.class_type = "keyblock"
                BLOCK3.description = "Variable Block 3"
                self.KEYBLOCKS_256.append(BLOCK3)

                BLOCK3 = copy.deepcopy(BLOCK3)
                BLOCK3.type = "bytes:24"
                BLOCK3.bit_len = 24 * 8
                self.KEYBLOCKS_192.append(BLOCK3)

            elif efuse.category == "calibration" and efuse.block == 3:
                self.ADC_CALIBRATION.append(efuse)
                self.ALL_EFUSES[i] = None

            elif efuse.name in ["CUSTOM_MAC_CRC", "CUSTOM_MAC"]:
                self.CUSTOM_MAC.append(efuse)
                self.ALL_EFUSES[i] = None

            elif efuse.category == "spi pad":
                efuse.class_type = "spipin"

        f = Field()
        f.name = "WAFER_VERSION_MAJOR"
        f.block = 0
        f.bit_len = 3
        f.type = f"uint:{f.bit_len}"
        f.category = "identity"
        f.class_type = "wafer"
        f.description = "calc WAFER VERSION MAJOR from CHIP_VER_REV1 and CHIP_VER_REV2 and apb_ctl_date (read only)"
        self.CALC.append(f)

        f = Field()
        f.name = "PKG_VERSION"
        f.block = 0
        f.bit_len = 4
        f.type = f"uint:{f.bit_len}"
        f.category = "identity"
        f.class_type = "pkg"
        f.description = (
            "calc Chip package = CHIP_PACKAGE_4BIT << 3 + CHIP_PACKAGE (read only)"
        )
        self.CALC.append(f)

        for efuse in self.ALL_EFUSES:
            if efuse is not None:
                self.EFUSES.append(efuse)

        self.ALL_EFUSES = []
