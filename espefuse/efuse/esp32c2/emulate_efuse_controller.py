# This file describes eFuses controller for ESP32-C2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from bitstring import BitStream

import reedsolo

from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters
from ..emulate_efuse_controller_base import EmulateEfuseControllerBase, FatalError


class EmulateEfuseController(EmulateEfuseControllerBase):
    """The class for virtual efuse operation. Using for HOST_TEST."""

    CHIP_NAME = "ESP32-C2"
    mem = None
    debug = False

    def __init__(self, efuse_file=None, debug=False):
        self.Blocks = EfuseDefineBlocks
        self.Fields = EfuseDefineFields()
        self.REGS = EfuseDefineRegisters
        super(EmulateEfuseController, self).__init__(efuse_file, debug)
        self.write_reg(self.REGS.EFUSE_CMD_REG, 0)

    """ esptool method start >>"""

    def get_major_chip_version(self):
        return 1

    def get_minor_chip_version(self):
        return 0

    def get_crystal_freq(self):
        return 40  # MHz

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

    def check_rd_protection_area(self):
        # checks fields which have the read protection bits.
        # if the read protection bit is set then we need to reset this field to 0.

        def get_read_disable_mask(blk):
            mask = 0
            if isinstance(blk.read_disable_bit, list):
                for i in blk.read_disable_bit:
                    mask |= 1 << i
            else:
                mask = 1 << blk.read_disable_bit
            return mask

        read_disable_bit = self.read_field("RD_DIS", bitstring=False)
        for b in self.Blocks.BLOCKS:
            blk = self.Blocks.get(b)
            block = self.read_block(blk.id)
            if (
                blk.read_disable_bit is not None
                and read_disable_bit & get_read_disable_mask(blk)
            ):
                if isinstance(blk.read_disable_bit, list):
                    if read_disable_bit & (1 << blk.read_disable_bit[0]):
                        block.set(
                            0, [i for i in range(blk.len * 32 // 2, blk.len * 32)]
                        )
                    if read_disable_bit & (1 << blk.read_disable_bit[1]):
                        block.set(0, [i for i in range(0, blk.len * 32 // 2)])
                else:
                    block.set(0)
            else:
                for field in self.Fields.EFUSES:
                    if (
                        blk.id == field.block
                        and field.read_disable_bit is not None
                        and read_disable_bit & get_read_disable_mask(field)
                    ):
                        raw_data = self.read_field(field.name)
                        raw_data.set(0)
                        block.pos = block.length - (
                            field.word * 32 + field.pos + raw_data.length
                        )
                        block.overwrite(BitStream(raw_data.length))
            self.overwrite_mem_from_block(blk, block)
