# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
from zlib import crc32

from espefuse.efuse.base_fields import EfuseBlockBase
from espefuse.efuse.mem_definition_base import EfuseBlocksBase
from esptool import FatalError


# Single-class coder/decoder for the EFSxx efuse dump format.
#
# Format (UNPADDED Base64URL):
#   EFSxx:<chip_name>:chip_version:<b64_blocks>:<b64_cerr>:<b64_crc>
#
# CRC32 details:
#   - Computed over the ASCII *prefix* INCLUDING the trailing colon before the CRC:
#       crc("EFSxx:<chip>:<version>:<b64_blocks>:<b64_cerr>:")
#
# Notes:
#   - <b64_blocks> and <b64_cerr> may be empty, yielding a double colon "::"
#   - <b64_blocks> is the raw concatenation of 32-bit little-endian words
#     for BLK0..BLK(N-1).
class EfsToken:
    @classmethod
    def build(
        cls,
        chip: str,
        version: int,
        blocks: list[EfuseBlockBase],
        error_regs: list[int] | None = None,
        token_format: str = "EFSR",
    ) -> str:
        """Return EFSxx token string.

        Produces colon-separated per-block base64url pieces. Empty blocks (all-zero)
        are represented by empty pieces (i.e., consecutive colons).
        """
        # Normalize chip and version
        chip = chip.lower().replace("esp-", "esp").replace("-", "")
        str_version = f"{version:03d}"

        block_pieces: list[bytes] = []
        for b in blocks:
            b_block = b.get_bitstring(token_format == "EFSR").copy()
            b_block.byteswap()
            block_pieces.append(bytes(b_block.bytes))

        def _is_all_zero(b: bytes) -> bool:
            return all(x == 0 for x in b)

        b64_blocks_pieces = [
            "" if _is_all_zero(piece) else cls._b64url_encode_unpadded(piece)
            for piece in block_pieces
        ]
        b64_blocks = ":".join(b64_blocks_pieces)

        b64_cerr = ""
        # Only include error registers if the list exists
        # and contains any non-zero value
        if error_regs and any((val != 0) for val in error_regs):
            cerr = b""
            for val in error_regs:
                cerr += val.to_bytes(4, "little")
            b64_cerr = cls._b64url_encode_unpadded(cerr) if cerr else ""
        prefix = f"{token_format}:{chip}:{str_version}:{b64_blocks}:{b64_cerr}:"
        crc = crc32(prefix.encode("ascii")) & 0xFFFFFFFF
        b64_crc = cls._b64url_encode_unpadded(crc.to_bytes(4, "little"))
        return prefix + b64_crc

    @classmethod
    def verify_format(cls, token: str) -> tuple[str, str, str, str, str, str]:
        parts = token.strip().split(":")
        if len(parts) < 6:
            raise FatalError(
                f"Invalid efuse token: expected 6 colon-separated fields ({token})"
            )
        magic = parts[0]
        chip = parts[1]
        version = parts[2]
        # The blocks field may itself contain colon-separated block entries
        # (including empty entries represented by consecutive "::"), so the token can
        # have >6 parts. Treat the last part as CRC, the second-last as cerr, and
        # everything between parts[3]..parts[-3] as the blocks field pieces which we
        # rejoin with ":" to preserve empty block entries.
        b64_crc = parts[-1]
        b64_cerr = parts[-2]
        b64_compressed_blocks = ":".join(parts[3:-2])
        if magic not in ("EFSR", "EFSW", "EFSRW"):
            raise FatalError(
                f"Bad magic '{magic}', expected one of ('EFSR', 'EFSW', 'EFSRW')"
            )
        if len(b64_crc) != 6:
            raise FatalError(
                "CRC field must be exactly 6 characters, "
                f"got {len(b64_crc)}: '{b64_crc}'. "
                "Please ensure you copied the entire efuse token dump string."
            )
        return (magic, chip, version, b64_compressed_blocks, b64_cerr, b64_crc)

    @classmethod
    def decode(
        cls, mem_def_blocks: EfuseBlocksBase, token: str, verify_crc: bool = True
    ) -> tuple[str, int, bytes, bytes]:
        """
        Decode an EFSxx token string into its components.
        If verify_crc=True, recompute and compare CRC.
        """
        magic, chip, version, b64_compressed_blocks, b64_cerr, b64_crc = (
            cls.verify_format(token)
        )

        blocks = cls.decompress_blocks(mem_def_blocks, b64_compressed_blocks)
        cerr = cls._b64url_decode_unpadded(b64_cerr)
        crc_bytes = cls._b64url_decode_unpadded(b64_crc)
        if len(crc_bytes) < 4:
            raise FatalError("CRC field must decode to >=4 bytes")
        crc_le = int.from_bytes(crc_bytes[:4], "little")

        if verify_crc:
            data_token = f"{magic}:{chip}:{version}:{b64_compressed_blocks}:{b64_cerr}:"
            computed = crc32(data_token.encode("ascii")) & 0xFFFFFFFF
            b64_computed_crc = cls._b64url_encode_unpadded(
                computed.to_bytes(4, "little")
            )
            if computed != crc_le:
                raise FatalError(
                    f"CRC mismatch: token=0x{crc_le:08x}, computed=0x{computed:08x}, "
                    f"b64_crc={b64_computed_crc}"
                )

        return (chip, int(version), blocks, cerr)

    @classmethod
    def decompress_blocks(
        cls, mem_def_blocks: EfuseBlocksBase, b64_compressed: str
    ) -> bytes:
        pieces = b64_compressed.split(":")
        expected = len(mem_def_blocks.BLOCKS)
        if len(pieces) != expected:
            raise FatalError(
                "Compressed blocks count "
                f"{len(pieces)} doesn't match expected {expected}"
            )

        combined = bytearray()
        for i, b in enumerate(mem_def_blocks.BLOCKS):
            blk = mem_def_blocks.get(b)
            piece = pieces[i]
            if len(piece) == 0:
                combined.extend(b"\x00" * (blk.len * 4))
                continue

            try:
                decoded = cls._b64url_decode_unpadded(piece)
            except Exception as e:
                raise FatalError(f"Failed to decode block {b}: {e}")

            if len(decoded) != blk.len * 4:
                raise FatalError(
                    f"Decoded block {b} length {len(decoded)} != expected {blk.len * 4}"
                )

            combined.extend(decoded)

        return bytes(combined)

    @staticmethod
    def _b64url_encode_unpadded(raw: bytes) -> str:
        s = base64.urlsafe_b64encode(raw).decode("ascii")
        return s.rstrip("=")

    @staticmethod
    def _b64url_decode_unpadded(s: str) -> bytes:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.urlsafe_b64decode(s + pad)
