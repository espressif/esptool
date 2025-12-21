# This file describes eFuses controller for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import abstractmethod
import re
from typing import Any

from bitstring import BitStream
from espefuse.efuse.mem_definition_base import (
    BlockDefinition,
    EfuseBlocksBase,
    EfuseFieldsBase,
    EfuseRegistersBase,
    Field,
)
from esptool.logger import log


class EmulateEfuseControllerBase:
    """The class for virtual efuse operations. Using for HOST_TEST."""

    CHIP_NAME: str = ""
    mem: BitStream
    debug: bool = False
    Blocks: type[EfuseBlocksBase]
    Fields: EfuseFieldsBase
    REGS: type[EfuseRegistersBase]
    USB_JTAG_SERIAL_PID: int = 0x1001

    def __init__(self, efuse_file: str | None = None, debug: bool = False):
        self.debug = debug
        self.efuse_file = efuse_file
        if self.efuse_file:
            try:
                self.mem = BitStream(
                    bytes=open(self.efuse_file, "rb").read(),
                    length=self.REGS.EFUSE_MEM_SIZE * 8,
                )
            except (ValueError, FileNotFoundError):
                # the file is empty or does not fit the length.
                self.mem = BitStream(length=self.REGS.EFUSE_MEM_SIZE * 8)
                self.mem.set(0)
                self.mem.tofile(open(self.efuse_file, "a+b"))
        else:
            # efuse_file is not provided
            #  it means we do not want to keep the result of efuse operations
            self.mem = BitStream(self.REGS.EFUSE_MEM_SIZE * 8)
            self.mem.set(0)

    """ esptool method start >> """

    @abstractmethod
    def get_major_chip_version(self) -> int:
        pass

    @abstractmethod
    def get_minor_chip_version(self) -> int:
        pass

    def get_chip_description(self) -> str:
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        return f"{self.CHIP_NAME} (revision v{major_rev}.{minor_rev})"

    def get_chip_revision(self) -> int:
        return self.get_major_chip_version() * 100 + self.get_minor_chip_version()

    def read_efuse(self, n: int, block: int = 0) -> int:
        """Read the nth word of the ESP3x EFUSE region."""
        blk = self.Blocks.get(self.Blocks.BLOCKS[block])
        return self.read_reg(blk.rd_addr + (4 * n))

    def read_reg(self, addr: int) -> int:
        self.mem.pos = self.mem.length - ((addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + 32)
        return int(self.mem.read("uint:32"))

    def write_reg(
        self,
        addr: int,
        value: int,
        mask: int = 0xFFFFFFFF,
        delay_us: int = 0,
        delay_after_us: int = 0,
    ) -> None:
        self.mem.pos = self.mem.length - ((addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + 32)
        self.mem.overwrite("uint:32={}".format(value & mask))
        self.handle_writing_event(addr, value)

    def update_reg(self, addr: int, mask: int, new_val: int) -> None:
        position = self.mem.length - ((addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + 32)
        self.mem.pos = position
        cur_val = self.mem.read("uint:32")
        self.mem.pos = position
        self.mem.overwrite("uint:32={}".format(cur_val | (new_val & mask)))

    def write_efuse(self, n: int, value: int, block: int = 0) -> None:
        """Write the nth word of the ESP3x EFUSE region."""
        blk = self.Blocks.get(self.Blocks.BLOCKS[block])
        self.write_reg(blk.wr_addr + (4 * n), value)

    def _get_pid(self) -> int:
        return -1

    """ << esptool method end """

    def handle_writing_event(self, addr: int, value: int) -> None:
        self.save_to_file()

    def save_to_file(self) -> None:
        if self.efuse_file:
            with open(self.efuse_file, "wb") as f:
                self.mem.tofile(f)

    def handle_coding_scheme(self, blk: BlockDefinition, data: BitStream) -> BitStream:
        return data

    def copy_blocks_wr_regs_to_rd_regs(self, updated_block: int | None = None) -> None:
        for b in reversed(self.Blocks.BLOCKS):
            blk = self.Blocks.get(b)
            if updated_block is not None:
                if blk.id != updated_block:
                    continue
            data = self.read_block(blk.id, wr_regs=True)
            if self.debug:
                log.print(blk.name, data.hex)
            plain_data = self.handle_coding_scheme(blk, data)
            plain_data = self.check_wr_protection_area(blk.id, plain_data)
            self.update_block(blk, plain_data)

    def clean_blocks_wr_regs(self) -> None:
        for b in self.Blocks.BLOCKS:
            blk = self.Blocks.get(b)
            for offset in range(0, blk.len * 4, 4):
                wr_addr = blk.wr_addr + offset
                self.write_reg(wr_addr, 0)

    def read_field(self, name: str, bitstring: bool = True) -> Any:
        for field in self.Fields.EFUSES:
            if field.name == name:
                block = self.read_block(field.block)
                if field.type.startswith("bool"):
                    field_len = 1
                else:
                    match = re.search(r"\d+", field.type)
                    if match:
                        field_len = int(match.group())
                    else:
                        raise ValueError(f"Invalid field type: {field.type}")
                    if field.type.startswith("bytes"):
                        field_len *= 8
                block.pos = block.length - (field.word * 32 + field.pos + field_len)  # type: ignore
                if bitstring:
                    return block.read(field_len)
                else:
                    return block.read(field.type)
        raise ValueError(f"Field {name} not found")

    def get_bitlen_of_block(self, blk: BlockDefinition, wr: bool = False) -> int:
        return 32 * blk.len

    def read_block(self, idx: int, wr_regs: bool = False) -> BitStream:
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
        else:
            raise ValueError(f"Block {idx} not found")
        return block

    def update_block(self, blk: BlockDefinition, wr_data: BitStream) -> None:
        wr_data = self.read_block(blk.id) | wr_data
        self.overwrite_mem_from_block(blk, wr_data)

    def overwrite_mem_from_block(
        self, blk: BlockDefinition, wr_data: BitStream
    ) -> None:
        self.mem.pos = self.mem.length - (
            (blk.rd_addr - self.REGS.DR_REG_EFUSE_BASE) * 8 + wr_data.len
        )
        self.mem.overwrite(wr_data)

    def check_wr_protection_area(self, num_blk: int, wr_data: BitStream) -> BitStream:
        # checks fields which have the write protection bit.
        # if the write protection bit is set, we need to protect that area from changes.
        write_disable_bit = self.read_field("WR_DIS", bitstring=False)
        mask_wr_data = BitStream(len(wr_data))
        mask_wr_data.set(0)
        blk = self.Blocks.get(self.Blocks.BLOCKS[num_blk])
        if blk.write_disable_bit is not None and write_disable_bit & (
            1 << blk.write_disable_bit
        ):
            mask_wr_data.set(1)
        else:
            for field in self.Fields.EFUSES:
                if blk.id == field.block and field.block == num_blk:
                    if field.write_disable_bit is not None and write_disable_bit & (
                        1 << field.write_disable_bit
                    ):
                        data: BitStream = self.read_field(field.name)
                        data.set(1)
                        mask_wr_data.pos = mask_wr_data.length - (
                            field.word * 32 + field.pos + data.len  # type: ignore
                        )
                        mask_wr_data.overwrite(data)
        mask_wr_data.invert()
        return wr_data & mask_wr_data

    @staticmethod
    def get_read_disable_mask(blk: BlockDefinition | Field) -> int:
        mask = 0
        if isinstance(blk.read_disable_bit, list):
            for i in blk.read_disable_bit:
                mask |= 1 << i
        elif blk.read_disable_bit is not None:
            mask = 1 << blk.read_disable_bit
        return mask

    def set_read_disable_bits(
        self,
        block: BitStream,
        read_disable_bit: int,
        blk: BlockDefinition,
    ) -> None:
        block.set(0)

    def check_rd_protection_area(self) -> None:
        # checks fields which have the read protection bits.
        # if the read protection bit is set then we need to reset this field to 0.
        read_disable_bit = self.read_field("RD_DIS", bitstring=False)
        for b in self.Blocks.BLOCKS:
            blk = self.Blocks.get(b)
            block = self.read_block(blk.id)
            if (
                blk.read_disable_bit is not None
                and read_disable_bit & self.get_read_disable_mask(blk)
            ):
                self.set_read_disable_bits(block, read_disable_bit, blk)
            else:
                for field in self.Fields.EFUSES:
                    if (
                        blk.id == field.block
                        and field.read_disable_bit is not None
                        and read_disable_bit & self.get_read_disable_mask(field)
                    ):
                        raw_data: BitStream = self.read_field(field.name)
                        raw_data.set(0)
                        block.pos = block.length - (
                            field.word * 32 + field.pos + raw_data.length  # type: ignore
                        )
                        block.overwrite(BitStream(raw_data.length))
            self.overwrite_mem_from_block(blk, block)

    def clean_mem(self) -> None:
        self.mem.set(0)
        if self.efuse_file:
            with open(self.efuse_file, "wb") as f:
                self.mem.tofile(f)
