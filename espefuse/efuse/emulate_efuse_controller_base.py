#!/usr/bin/env python
#
# This file describes eFuses controller for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import re

from bitstring import BitString


class EmulateEfuseControllerBase(object):
    """The class for virtual efuse operations. Using for HOST_TEST."""

    CHIP_NAME = ""
    mem = None
    debug = False
    Blocks = None
    Fields = None
    REGS = None

    def __init__(self, efuse_file=None, debug=False):
        self.debug = debug
        self.efuse_file = efuse_file
        if self.efuse_file:
            try:
                self.mem = BitString(
                    open(self.efuse_file, "a+b"), length=self.REGS.EFUSE_MEM_SIZE * 8
                )
            except ValueError:
                # the file is empty or does not fit the length.
                self.mem = BitString(length=self.REGS.EFUSE_MEM_SIZE * 8)
                self.mem.set(0)
                self.mem.tofile(open(self.efuse_file, "a+b"))
        else:
            # efuse_file is not provided
            #  it means we do not want to keep the result of efuse operations
            self.mem = BitString(self.REGS.EFUSE_MEM_SIZE * 8)
            self.mem.set(0)

    """ esptool method start >> """

    def get_chip_description(self):
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{self.CHIP_NAME} (revision v{major_rev}.{minor_rev})"

    def get_chip_revision(self):
        return self.get_major_chip_version() * 100 + self.get_minor_chip_version()

    def read_efuse(self, n, block=0):
        """Read the nth word of the ESP3x EFUSE region."""
        blk = self.Blocks.get(self.Blocks.BLOCKS[block])
        return self.read_reg(blk.rd_addr + (4 * n))

    def read_reg(self, addr):
        self.mem.pos = self.mem.length - ((addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + 32)
        return self.mem.read("uint:32")

    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0, delay_after_us=0):
        self.mem.pos = self.mem.length - ((addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + 32)
        self.mem.overwrite("uint:32={}".format(value & mask))
        self.handle_writing_event(addr, value)

    def update_reg(self, addr, mask, new_val):
        position = self.mem.length - ((addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + 32)
        self.mem.pos = position
        cur_val = self.mem.read("uint:32")
        self.mem.pos = position
        self.mem.overwrite("uint:32={}".format(cur_val | (new_val & mask)))

    def write_efuse(self, n, value, block=0):
        """Write the nth word of the ESP3x EFUSE region."""
        blk = self.Blocks.get(self.Blocks.BLOCKS[block])
        self.write_reg(blk.wr_addr + (4 * n), value)

    """ << esptool method end """

    def handle_writing_event(self, addr, value):
        self.save_to_file()

    def save_to_file(self):
        if self.efuse_file:
            with open(self.efuse_file, "wb") as f:
                self.mem.tofile(f)

    def handle_coding_scheme(self, blk, data):
        return data

    def copy_blocks_wr_regs_to_rd_regs(self, updated_block=None):
        for b in reversed(self.Blocks.BLOCKS):
            blk = self.Blocks.get(b)
            if updated_block is not None:
                if blk.id != updated_block:
                    continue
            data = self.read_block(blk.id, wr_regs=True)
            if self.debug:
                print(blk.name, data.hex)
            plain_data = self.handle_coding_scheme(blk, data)
            plain_data = self.check_wr_protection_area(blk.id, plain_data)
            self.update_block(blk, plain_data)

    def clean_blocks_wr_regs(self):
        for b in self.Blocks.BLOCKS:
            blk = self.Blocks.get(b)
            for offset in range(0, blk.len * 4, 4):
                wr_addr = blk.wr_addr + offset
                self.write_reg(wr_addr, 0)

    def read_field(self, name, bitstring=True):
        for e in self.Fields.EFUSES:
            field = self.Fields.get(e)
            if field.name == name:
                self.read_block(field.block)
                block = self.read_block(field.block)
                if field.type.startswith("bool"):
                    field_len = 1
                else:
                    field_len = int(re.search(r"\d+", field.type).group())
                    if field.type.startswith("bytes"):
                        field_len *= 8
                block.pos = block.length - (field.word * 32 + field.pos + field_len)
                if bitstring:
                    return block.read(field_len)
                else:
                    return block.read(field.type)
        return None

    def get_bitlen_of_block(self, blk, wr=False):
        return 32 * blk.len

    def read_block(self, idx, wr_regs=False):
        block = None
        for b in self.Blocks.BLOCKS:
            blk = self.Blocks.get(b)
            if blk.id == idx:
                blk_len_bits = self.get_bitlen_of_block(blk, wr=wr_regs)
                addr = blk.wr_addr if wr_regs else blk.rd_addr
                self.mem.pos = self.mem.length - (
                    (addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + blk_len_bits
                )
                block = self.mem.read(blk_len_bits)
                break
        return block

    def update_block(self, blk, wr_data):
        wr_data = self.read_block(blk.id) | wr_data
        self.overwrite_mem_from_block(blk, wr_data)

    def overwrite_mem_from_block(self, blk, wr_data):
        self.mem.pos = self.mem.length - (
            (blk.rd_addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + wr_data.len
        )
        self.mem.overwrite(wr_data)

    def check_wr_protection_area(self, num_blk, wr_data):
        # checks fields which have the write protection bit.
        # if the write protection bit is set, we need to protect that area from changes.
        write_disable_bit = self.read_field("WR_DIS", bitstring=False)
        mask_wr_data = BitString(len(wr_data))
        mask_wr_data.set(0)
        blk = self.Blocks.get(self.Blocks.BLOCKS[num_blk])
        if blk.write_disable_bit is not None and write_disable_bit & (
            1 << blk.write_disable_bit
        ):
            mask_wr_data.set(1)
        else:
            for e in self.Fields.EFUSES:
                field = self.Fields.get(e)
                if blk.id == field.block and field.block == num_blk:
                    if field.write_disable_bit is not None and write_disable_bit & (
                        1 << field.write_disable_bit
                    ):
                        data = self.read_field(field.name)
                        data.set(1)
                        mask_wr_data.pos = mask_wr_data.length - (
                            field.word * 32 + field.pos + data.len
                        )
                        mask_wr_data.overwrite(data)
        mask_wr_data.invert()
        return wr_data & mask_wr_data

    def check_rd_protection_area(self):
        # checks fields which have the read protection bits.
        # if the read protection bit is set then we need to reset this field to 0.
        read_disable_bit = self.read_field("RD_DIS", bitstring=False)
        for b in self.Blocks.BLOCKS:
            blk = self.Blocks.get(b)
            block = self.read_block(blk.id)
            if blk.read_disable_bit is not None and read_disable_bit & (
                1 << blk.read_disable_bit
            ):
                block.set(0)
            else:
                for e in self.Fields.EFUSES:
                    field = self.Fields.get(e)
                    if (
                        blk.id == field.block
                        and field.read_disable_bit is not None
                        and read_disable_bit & (1 << field.read_disable_bit)
                    ):
                        raw_data = self.read_field(field.name)
                        raw_data.set(0)
                        block.pos = block.length - (
                            field.word * 32 + field.pos + raw_data.length
                        )
                        block.overwrite(BitString(raw_data.length))
            self.overwrite_mem_from_block(blk, block)

    def clean_mem(self):
        self.mem.set(0)
        if self.efuse_file:
            with open(self.efuse_file, "wb") as f:
                self.mem.tofile(f)


class FatalError(RuntimeError):
    """
    Wrapper class for runtime errors that aren't caused by internal bugs
    """

    def __init__(self, message):
        RuntimeError.__init__(self, message)

    @staticmethod
    def WithResult(message, result):
        return FatalError(result)
