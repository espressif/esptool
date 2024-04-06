# This file describes eFuses controller for ESP32-H2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import reedsolo

from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters
from ..emulate_efuse_controller_base import EmulateEfuseControllerBase, FatalError


class EmulateEfuseController(EmulateEfuseControllerBase):
    """The class for virtual efuse operation. Using for HOST_TEST."""

    CHIP_NAME = "ESP32-H2(beta1)"
    mem = None
    debug = False

    def __init__(self, efuse_file=None, debug=False):
        self.Blocks = EfuseDefineBlocks
        self.Fields = EfuseDefineFields(None)
        self.REGS = EfuseDefineRegisters
        super(EmulateEfuseController, self).__init__(efuse_file, debug)
        self.write_reg(self.REGS.EFUSE_CMD_REG, 0)

    """ esptool method start >>"""

    def get_major_chip_version(self):
        return 0

    def get_minor_chip_version(self):
        return 0

    def get_crystal_freq(self):
        return 32  # MHz (common for all chips)

    def get_security_info(self):
        return {
            "flags": 0,
            "flash_crypt_cnt": 0,
            "key_purposes": 0,
            "chip_id": 0,
            "api_version": 0,
        }

    """ << esptool method end """

    def handle_writing_event(self, addr, value):
        if addr == self.REGS.EFUSE_CMD_REG:
            if value & self.REGS.EFUSE_PGM_CMD:
                self.copy_blocks_wr_regs_to_rd_regs(updated_block=(value >> 2) & 0xF)
                self.clean_blocks_wr_regs()
                self.check_rd_protection_area()
                self.write_reg(addr, 0)
                self.write_reg(self.REGS.EFUSE_CMD_REG, 0)
            elif value == self.REGS.EFUSE_READ_CMD:
                self.write_reg(addr, 0)
                self.write_reg(self.REGS.EFUSE_CMD_REG, 0)
                self.save_to_file()

    def get_bitlen_of_block(self, blk, wr=False):
        if blk.id == 0:
            if wr:
                return 32 * 8
            else:
                return 32 * blk.len
        else:
            if wr:
                rs_coding = 32 * 3
                return 32 * 8 + rs_coding
            else:
                return 32 * blk.len

    def handle_coding_scheme(self, blk, data):
        if blk.id != 0:
            # CODING_SCHEME RS applied only for all blocks except BLK0.
            coded_bytes = 12
            data.pos = coded_bytes * 8
            plain_data = data.readlist("32*uint:8")[::-1]
            # takes 32 bytes
            # apply RS encoding
            rs = reedsolo.RSCodec(coded_bytes)
            # 32 byte of data + 12 bytes RS
            calc_encoded_data = list(rs.encode([x for x in plain_data]))
            data.pos = 0
            if calc_encoded_data != data.readlist("44*uint:8")[::-1]:
                raise FatalError("Error in coding scheme data")
            data = data[coded_bytes * 8 :]
        if blk.len < 8:
            data = data[(8 - blk.len) * 32 :]
        return data
