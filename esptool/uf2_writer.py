# SPDX-FileCopyrightText: 2020-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later
# Code was originally licensed under Apache 2.0 before the release of ESP-IDF v5.2

import hashlib
import os
import struct
from typing import List

from esptool.util import div_roundup


class UF2Writer(object):
    # The UF2 format is described here: https://github.com/microsoft/uf2
    UF2_BLOCK_SIZE = 512
    # max value of CHUNK_SIZE reduced by optional parts. Currently, MD5_PART only.
    UF2_DATA_SIZE = 476
    UF2_MD5_PART_SIZE = 24
    UF2_FIRST_MAGIC = 0x0A324655
    UF2_SECOND_MAGIC = 0x9E5D5157
    UF2_FINAL_MAGIC = 0x0AB16F30
    UF2_FLAG_FAMILYID_PRESENT = 0x00002000
    UF2_FLAG_MD5_PRESENT = 0x00004000

    def __init__(
        self,
        chip_id: int,
        output_file: os.PathLike,
        chunk_size: int,
        md5_enabled: bool = True,
    ) -> None:
        if not md5_enabled:
            self.UF2_MD5_PART_SIZE = 0
            self.UF2_FLAG_MD5_PRESENT = 0x00000000
        self.md5_enabled = md5_enabled
        self.chip_id = chip_id
        self.CHUNK_SIZE = (
            self.UF2_DATA_SIZE - self.UF2_MD5_PART_SIZE
            if chunk_size is None
            else chunk_size
        )
        self.f = open(output_file, "wb")

    def __enter__(self) -> "UF2Writer":
        return self

    def __exit__(self, exc_type: str, exc_val: int, exc_tb: List) -> None:
        if self.f:
            self.f.close()

    @staticmethod
    def _to_uint32(num: int) -> bytes:
        return struct.pack("<I", num)

    def _write_block(
        self, addr: int, chunk: bytes, len_chunk: int, block_no: int, blocks: int
    ) -> None:
        assert len_chunk > 0
        assert len_chunk <= self.CHUNK_SIZE
        assert block_no < blocks
        block = struct.pack(
            "<IIIIIIII",
            self.UF2_FIRST_MAGIC,
            self.UF2_SECOND_MAGIC,
            self.UF2_FLAG_FAMILYID_PRESENT | self.UF2_FLAG_MD5_PRESENT,
            addr,
            len_chunk,
            block_no,
            blocks,
            self.chip_id,
        )
        block += chunk

        if self.md5_enabled:
            md5_part = struct.pack("<II", addr, len_chunk)
            md5_part += hashlib.md5(chunk).digest()
            assert len(md5_part) == self.UF2_MD5_PART_SIZE

            block += md5_part
        block += b"\x00" * (self.UF2_DATA_SIZE - self.UF2_MD5_PART_SIZE - len_chunk)
        block += self._to_uint32(self.UF2_FINAL_MAGIC)
        assert len(block) == self.UF2_BLOCK_SIZE
        self.f.write(block)

    def add_file(self, addr: int, image: bytes) -> None:
        blocks = div_roundup(len(image), self.CHUNK_SIZE)
        chunks = [
            image[i : i + self.CHUNK_SIZE]
            for i in range(0, len(image), self.CHUNK_SIZE)
        ]
        for i, chunk in enumerate(chunks):
            len_chunk = len(chunk)
            self._write_block(addr, chunk, len_chunk, i, blocks)
            addr += len_chunk
