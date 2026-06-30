# This file describes eFuses controller for ESP32-S3 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import reedsolo
from bitstring import BitStream

from espefuse.efuse.mem_definition_base import BlockDefinition
from esptool import FatalError

from ..emulate_efuse_controller_base import EmulateEfuseControllerBase
from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters


class EmulateEfuseController(EmulateEfuseControllerBase):
    """The class for virtual efuse operation. Using for HOST_TEST."""

    CHIP_NAME = "ESP32-S3"
    Blocks: type[EfuseDefineBlocks]
    Fields: EfuseDefineFields
    REGS: type[EfuseDefineRegisters]

    def __init__(
        self,
        efuse_file: str | None = None,
        debug: bool = False,
        token_dump: str | None = None,
    ):
        self.Blocks = EfuseDefineBlocks
        self.Fields = EfuseDefineFields(None)
        self.REGS = EfuseDefineRegisters
        super().__init__(efuse_file, debug, token_dump=token_dump)
        self.write_reg(self.REGS.EFUSE_CMD_REG, 0)

    def set_major_chip_version(self, version):
        version &= 0x3
        if version:
            self.direct_write_efuse(5, version << 24, block=1)

    def set_minor_chip_version(self, version):
        version &= 0xF
        hi = (version >> 3) & 0x01
        low = version & 0x07
        if low:
            self.direct_write_efuse(3, low << 18, block=1)
        if hi:
            self.direct_write_efuse(5, hi << 23, block=1)

    """ esptool method start >>"""

    def is_eco0(self, minor_raw):
        # Workaround: The major version field was allocated to other purposes
        # when block version is v1.1.
        # Luckily only chip v0.0 have this kind of block version and efuse usage.
        return (
            (minor_raw & 0x7) == 0
            and self.get_blk_version_major() == 1
            and self.get_blk_version_minor() == 1
        )

    def get_blk_version_major(self):
        return (self.read_efuse(4, block=2) >> 0) & 0x03

    def get_blk_version_minor(self):
        return (self.read_efuse(3, block=1) >> 24) & 0x07

    def get_minor_chip_version(self):
        minor_raw = self.get_raw_minor_chip_version()
        if self.is_eco0(minor_raw):
            return 0
        return minor_raw

    def get_raw_minor_chip_version(self):
        hi = (self.read_efuse(5, block=1) >> 23) & 0x01
        low = (self.read_efuse(3, block=1) >> 18) & 0x07
        return (hi << 3) + low

    def get_major_chip_version(self):
        minor_raw = self.get_raw_minor_chip_version()
        if self.is_eco0(minor_raw):
            return 0
        return self.get_raw_major_chip_version()

    def get_raw_major_chip_version(self):
        return (self.read_efuse(5, block=1) >> 24) & 0x03

    def get_crystal_freq(self) -> int:
        return 40  # MHz (common for all chips)

    def get_security_info(self) -> dict[str, int]:
        return {
            "flags": 0,
            "flash_crypt_cnt": 0,
            "key_purposes": 0,
            "chip_id": 0,
            "api_version": 0,
        }

    """ << esptool method end """

    def handle_writing_event(self, addr: int, value: int) -> None:
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

    def get_bitlen_of_block(self, blk: BlockDefinition, wr: bool = False) -> int:
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

    def handle_coding_scheme(self, blk: BlockDefinition, data: BitStream) -> BitStream:
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
