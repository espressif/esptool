#!/usr/bin/env python
# This file describes eFuses controller for ESP32 chip
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

import time

from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters
from ..emulate_efuse_controller_base import EmulateEfuseControllerBase, FatalError


class EmulateEfuseController(EmulateEfuseControllerBase):
    """ The class for virtual efuse operations. Using for HOST_TEST.
    """
    CHIP_NAME = "ESP32"
    mem = None
    debug = False
    Blocks  = EfuseDefineBlocks
    Fields  = EfuseDefineFields
    REGS    = EfuseDefineRegisters

    def __init__(self, efuse_file=None, debug=False):
        super(EmulateEfuseController, self).__init__(efuse_file, debug)

    """ esptool method start >> """

    def get_chip_description(self):
        return "revision 3"

    def get_crystal_freq(self):
        return 40  # MHz (common for all chips)

    """ << esptool method end """

    def send_burn_cmd(self):
        def wait_idle():
            deadline = time.time() + self.REGS.EFUSE_BURN_TIMEOUT
            while time.time() < deadline:
                if self.read_reg(self.REGS.EFUSE_REG_CMD) == 0:
                    return
            raise FatalError("Timed out waiting for Efuse controller command to complete")
        self.write_reg(self.REGS.EFUSE_REG_CMD, self.REGS.EFUSE_CMD_WRITE)
        wait_idle()
        self.write_reg(self.REGS.EFUSE_REG_CONF, self.REGS.EFUSE_CONF_READ)
        self.write_reg(self.REGS.EFUSE_REG_CMD, self.REGS.EFUSE_CMD_READ)
        wait_idle()

    def handle_writing_event(self, addr, value):
        if addr == self.REGS.EFUSE_REG_CMD:
            if value == self.REGS.EFUSE_CMD_WRITE:
                self.write_reg(addr, 0)
            elif value == self.REGS.EFUSE_CMD_READ:
                self.copy_blocks_wr_regs_to_rd_regs()
                self.clean_blocks_wr_regs()
                self.check_rd_protection_area()
                self.write_reg(addr, 0)
                self.save_to_file()

    def read_raw_coding_scheme(self):
        return self.read_efuse(self.REGS.EFUSE_CODING_SCHEME_WORD) & self.REGS.EFUSE_CODING_SCHEME_MASK

    def write_raw_coding_scheme(self, value):
        self.write_efuse(self.REGS.EFUSE_CODING_SCHEME_WORD, value & self.REGS.EFUSE_CODING_SCHEME_MASK)
        self.send_burn_cmd()
        if value != self.read_raw_coding_scheme():
            raise FatalError("Error during a burning process to set the new coding scheme")
        print("Set coding scheme = %d" % self.read_raw_coding_scheme())

    def get_bitlen_of_block(self, blk, wr=False):
        if blk.id == 0:
            return 32 * blk.len
        else:
            coding_scheme = self.read_raw_coding_scheme()
            if coding_scheme == self.REGS.CODING_SCHEME_NONE:
                return 32 * blk.len
            elif coding_scheme == self.REGS.CODING_SCHEME_34:
                if wr:
                    return 32 * 8
                else:
                    return 32 * blk.len * 3 // 4
            else:
                raise FatalError("The {} coding scheme is not supported".format(coding_scheme))

    def handle_coding_scheme(self, blk, data):
        # it verifies the coding scheme part of data and returns just data
        if blk.id != 0 and self.read_raw_coding_scheme() == self.REGS.CODING_SCHEME_34:
            # CODING_SCHEME 3/4 applied only for BLK1..3
            # Takes 24 byte sequence to be represented in 3/4 encoding,
            # returns 8 words suitable for writing "encoded" to an efuse block
            data.pos = 0
            for _ in range(0, 4):
                xor_res = 0
                mul_res = 0
                chunk_data = data.readlist('8*uint:8')
                chunk_data = chunk_data[::-1]
                for i in range(0, 6):
                    byte_data = chunk_data[i]
                    xor_res ^= byte_data
                    mul_res += (i + 1) * bin(byte_data).count('1')
                if xor_res != chunk_data[6] or mul_res != chunk_data[7]:
                    print("xor_res ", xor_res, chunk_data[6], "mul_res", mul_res, chunk_data[7])
                    raise FatalError("Error in coding scheme data")
            # cut the coded data
            for i in range(0, 4):
                del data[i * 6 * 8: (i * 6 * 8) + 16]
        return data
