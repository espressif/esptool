# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Host-level unit tests for NAND flash command logic (no hardware required)."""

import os
import struct
from unittest.mock import MagicMock, patch

import pytest

from esptool.loader import ESPLoader
from esptool.util import FatalError, NANDEraseFailed, NANDProgramFailed


def _make_esp():
    """Return a minimal MagicMock ESPLoader suitable for cmds.py NAND functions."""
    esp = MagicMock(spec=ESPLoader)
    esp.IS_STUB = True
    esp.FLASH_WRITE_SIZE = 2048
    esp.FLASH_SECTOR_SIZE = 4096
    esp.CHIP_NAME = "ESP32-S3"
    esp.CHIP_DETECT_MAGIC_REG_ADDR = 0x40001000
    esp.ESP_CMDS = ESPLoader.ESP_CMDS
    esp.checksum.return_value = 0
    return esp


@pytest.mark.host_test
class TestReadFlashNandWithSkip:
    """Exercise _read_flash_nand_with_skip without hardware."""

    def test_linear_no_bad_blocks(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _read_flash_nand_with_skip

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        block_data = b"\xaa" * NAND_BLOCK_SIZE
        esp.read_flash_nand.return_value = block_data

        result = _read_flash_nand_with_skip(esp, 0, NAND_BLOCK_SIZE)
        assert result == block_data

    def test_bad_block_skipped(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _read_flash_nand_with_skip

        esp = _make_esp()
        # Block 0: bad (0x00), block 1: good (0xFF)
        esp.read_nand_spare.side_effect = [0x00, 0xFF]
        block_data = b"\xbb" * NAND_BLOCK_SIZE
        esp.read_flash_nand.return_value = block_data

        result = _read_flash_nand_with_skip(
            esp, 0, NAND_BLOCK_SIZE, nand_end_address=2 * NAND_BLOCK_SIZE
        )
        assert result == block_data
        assert esp.read_flash_nand.call_args[0][0] == NAND_BLOCK_SIZE

    def test_end_address_exhausted_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _read_flash_nand_with_skip

        esp = _make_esp()
        # All blocks bad
        esp.read_nand_spare.return_value = 0x00

        with pytest.raises(FatalError, match="end address"):
            _read_flash_nand_with_skip(
                esp, 0, NAND_BLOCK_SIZE, nand_end_address=2 * NAND_BLOCK_SIZE
            )

    def test_exact_slice_to_size(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _read_flash_nand_with_skip

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        block_data = b"\xcc" * NAND_BLOCK_SIZE
        esp.read_flash_nand.return_value = block_data

        size = 100
        result = _read_flash_nand_with_skip(esp, 0, size)
        assert len(result) == size
        assert result == block_data[:size]

    def test_progress_callback_invoked(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _read_flash_nand_with_skip

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        esp.read_flash_nand.return_value = b"\xdd" * NAND_BLOCK_SIZE

        calls = []
        _read_flash_nand_with_skip(
            esp, 0, NAND_BLOCK_SIZE, progress_fn=lambda *a: calls.append(a)
        )
        assert len(calls) == 1


@pytest.mark.host_test
class TestWriteFlashNandValidation:
    """Input-validation paths in _write_flash_nand."""

    def test_unaligned_address_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _write_flash_nand

        esp = _make_esp()
        with pytest.raises(FatalError, match="block size"):
            _write_flash_nand(esp, [(NAND_BLOCK_SIZE + 1, b"\x00" * NAND_BLOCK_SIZE)])

    def test_overlapping_images_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, _write_flash_nand

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        esp.write_flash_nand_begin.return_value = None
        esp.write_flash_nand_finish.return_value = None
        esp.write_flash_nand_block.return_value = None
        esp.read_flash_nand.return_value = b"\x00" * esp.FLASH_WRITE_SIZE

        data = b"\x00" * NAND_BLOCK_SIZE
        # Two images at same address — after first write, image_write_block_address
        # advances, making the second address (0) appear to come before it.
        with pytest.raises(FatalError, match="overlap"):
            _write_flash_nand(esp, [(0, data), (0, data)])

    def test_not_enough_good_blocks_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, NAND_TOTAL_SIZE, _write_flash_nand

        esp = _make_esp()
        # All blocks bad → pre-scan finds zero good blocks
        esp.read_nand_spare.return_value = 0x00

        with pytest.raises(FatalError, match="Not enough good blocks"):
            _write_flash_nand(
                esp,
                [(0, b"\x00" * NAND_BLOCK_SIZE)],
                nand_end_address=NAND_TOTAL_SIZE,
            )


@pytest.mark.host_test
class TestWriteFlashNandRecovery:
    """Error-recovery branches in _write_flash_nand."""

    def _setup_basic_esp(self, write_size):
        esp = _make_esp()
        esp.FLASH_WRITE_SIZE = write_size
        esp.write_flash_nand_begin.return_value = None
        esp.write_flash_nand_finish.return_value = None
        return esp

    def test_program_failed_marks_bad_retries_next_block(self):
        from esptool.cmds import (
            NAND_BLOCK_SIZE,
            NAND_PAGES_PER_BLOCK,
            _write_flash_nand,
        )

        esp = self._setup_basic_esp(2048)
        # spare: all blocks good for pre-scan (3 calls) + write loop spare checks
        # We make all spare reads return good (0xFF)
        esp.read_nand_spare.return_value = 0xFF

        # First write_flash_nand_block raises NANDProgramFailed, second succeeds
        call_count = [0]

        def block_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise NANDProgramFailed("P_FAIL")

        esp.write_flash_nand_block.side_effect = block_side_effect

        # After failed write, re-read returns correct data (second physical block)
        page_data = b"\xaa" * esp.FLASH_WRITE_SIZE
        esp.read_flash_nand.return_value = page_data

        data = page_data + b"\xff" * (NAND_BLOCK_SIZE - esp.FLASH_WRITE_SIZE)
        _write_flash_nand(esp, [(0, data)])

        # write_nand_spare called at least once to mark bad block
        esp.write_nand_spare.assert_called()
        first_call = esp.write_nand_spare.call_args_list[0]
        assert first_call[0][0] == 0 * NAND_PAGES_PER_BLOCK  # page 0 marked bad
        assert first_call[0][1] == 1

    def test_verify_mismatch_clears_on_reread(self):
        """Second read matches → no bad-block mark, advances to next logical block."""
        from esptool.cmds import NAND_BLOCK_SIZE, _write_flash_nand

        esp = self._setup_basic_esp(2048)
        esp.read_nand_spare.return_value = 0xFF
        esp.write_flash_nand_block.return_value = None

        page_data = b"\xbb" * esp.FLASH_WRITE_SIZE
        # first read: mismatch (wrong data), second read: correct
        esp.read_flash_nand.side_effect = [
            b"\x00" * esp.FLASH_WRITE_SIZE,  # first verify: mismatch
            page_data,  # second verify (re-read): match
        ]

        data = page_data + b"\xff" * (NAND_BLOCK_SIZE - esp.FLASH_WRITE_SIZE)
        _write_flash_nand(esp, [(0, data)])

        # No bad-block mark should have been written
        esp.write_nand_spare.assert_not_called()

    def test_verify_mismatch_persists_marks_bad(self):
        """Both reads mismatch → block marked bad and chunk retried on next block."""
        from esptool.cmds import (
            NAND_BLOCK_SIZE,
            NAND_PAGES_PER_BLOCK,
            _write_flash_nand,
        )

        esp = self._setup_basic_esp(2048)
        esp.read_nand_spare.return_value = 0xFF
        esp.write_flash_nand_block.return_value = None

        page_data = b"\xcc" * esp.FLASH_WRITE_SIZE
        # First block: both verify reads mismatch
        # Second block: verify reads match
        esp.read_flash_nand.side_effect = [
            b"\x00" * esp.FLASH_WRITE_SIZE,  # first verify: mismatch
            b"\x00" * esp.FLASH_WRITE_SIZE,  # re-read: still mismatch → mark bad
            page_data,  # second block verify: match
        ]

        data = page_data + b"\xff" * (NAND_BLOCK_SIZE - esp.FLASH_WRITE_SIZE)
        _write_flash_nand(esp, [(0, data)])

        # write_nand_spare called once to mark first block bad
        esp.write_nand_spare.assert_called()
        assert esp.write_nand_spare.call_args_list[0][0][0] == 0 * NAND_PAGES_PER_BLOCK

    def test_mark_bad_failure_swallowed(self):
        """write_nand_spare raising after P_FAIL must not propagate."""
        from esptool.cmds import NAND_BLOCK_SIZE, _write_flash_nand

        esp = self._setup_basic_esp(2048)
        esp.read_nand_spare.return_value = 0xFF

        call_count = [0]

        def block_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise NANDProgramFailed("P_FAIL")

        esp.write_flash_nand_block.side_effect = block_side_effect
        esp.write_nand_spare.side_effect = FatalError("mark failed")

        page_data = b"\xdd" * esp.FLASH_WRITE_SIZE
        esp.read_flash_nand.return_value = page_data

        data = page_data + b"\xff" * (NAND_BLOCK_SIZE - esp.FLASH_WRITE_SIZE)
        # Must not raise even though write_nand_spare raises
        _write_flash_nand(esp, [(0, data)])


@pytest.mark.host_test
class TestEraseFlashNand:
    """erase_flash(flash_type='nand') iterates all blocks and marks bad on E_FAIL."""

    def test_efail_marks_block_bad(self):
        from esptool.cmds import NAND_PAGES_PER_BLOCK, erase_flash

        esp = _make_esp()

        def erase_side_effect(addr, _size):
            if addr == 0:
                raise NANDEraseFailed("E_FAIL")

        esp.erase_nand_region.side_effect = erase_side_effect

        erase_flash(esp, flash_type="nand")

        esp.write_nand_spare.assert_any_call(0 * NAND_PAGES_PER_BLOCK, 1)

    def test_mark_bad_failure_swallowed(self):
        from esptool.cmds import erase_flash

        esp = _make_esp()
        esp.erase_nand_region.side_effect = NANDEraseFailed("E_FAIL")
        esp.write_nand_spare.side_effect = FatalError("mark failed")

        # Should complete without raising
        erase_flash(esp, flash_type="nand")

    def test_all_blocks_iterated(self):
        from esptool.cmds import NAND_BLOCK_COUNT, erase_flash

        esp = _make_esp()
        erase_flash(esp, flash_type="nand")
        assert esp.erase_nand_region.call_count == NAND_BLOCK_COUNT


@pytest.mark.host_test
class TestEraseRegionNand:
    """erase_region(flash_type='nand') alignment checks and block-count."""

    def test_unaligned_address_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, erase_region

        esp = _make_esp()
        with pytest.raises(FatalError, match="multiple"):
            erase_region(esp, 1, NAND_BLOCK_SIZE, flash_type="nand")

    def test_unaligned_size_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, erase_region

        esp = _make_esp()
        with pytest.raises(FatalError, match="multiple"):
            erase_region(esp, 0, NAND_BLOCK_SIZE + 1, flash_type="nand")

    def test_aligned_range_erases_correct_block_count(self):
        from esptool.cmds import NAND_BLOCK_SIZE, erase_region

        esp = _make_esp()
        erase_region(esp, 0, 3 * NAND_BLOCK_SIZE, flash_type="nand")
        assert esp.erase_nand_region.call_count == 3


@pytest.mark.host_test
class TestVerifyFlashNand:
    """verify_flash(flash_type='nand') alignment, bad-block skip, mismatch."""

    def test_unaligned_address_raises(self):
        from esptool.cmds import NAND_BLOCK_SIZE, verify_flash

        esp = _make_esp()
        with pytest.raises(FatalError, match="multiple"):
            verify_flash(esp, [(1, b"\x00" * NAND_BLOCK_SIZE)], flash_type="nand")

    def test_good_data_no_mismatch(self):
        from esptool.cmds import NAND_BLOCK_SIZE, verify_flash

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        data = b"\xaa" * NAND_BLOCK_SIZE
        esp.read_flash_nand.return_value = data

        # Should not raise
        verify_flash(esp, [(0, data)], flash_type="nand")

    def test_bad_block_skipped_during_verify(self):
        from esptool.cmds import NAND_BLOCK_SIZE, verify_flash

        esp = _make_esp()
        # Block at 0: bad; block at NAND_BLOCK_SIZE: good
        esp.read_nand_spare.side_effect = [0x00, 0xFF]
        data = b"\xbb" * NAND_BLOCK_SIZE
        esp.read_flash_nand.return_value = data

        verify_flash(esp, [(0, data)], flash_type="nand")
        # read was done on the second (good) block
        assert esp.read_flash_nand.call_args[0][0] == NAND_BLOCK_SIZE

    def test_mismatch_raises_fatalerror(self):
        from esptool.cmds import NAND_BLOCK_SIZE, verify_flash

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        esp.read_flash_nand.return_value = b"\x00" * NAND_BLOCK_SIZE

        with pytest.raises(FatalError, match="Verification failed"):
            verify_flash(esp, [(0, b"\xff" * NAND_BLOCK_SIZE)], flash_type="nand")

    def test_mismatch_with_diff_logs_differences(self):
        from esptool.cmds import NAND_BLOCK_SIZE, verify_flash

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        flash_data = b"\x00" * NAND_BLOCK_SIZE
        image_data = b"\xff" * NAND_BLOCK_SIZE
        esp.read_flash_nand.return_value = flash_data

        with pytest.raises(FatalError):
            verify_flash(esp, [(0, image_data)], diff=True, flash_type="nand")


@pytest.mark.host_test
class TestFlashSpiNandAttach:
    """ESPLoader.flash_spi_nand_attach — known/unknown JEDEC, error paths."""

    def _val_for(self, status_reg, mfr_id, dev_id):
        return (status_reg << 24) | (mfr_id << 16) | dev_id

    def test_known_winbond_w25n01gv(self):
        esp = _make_esp()
        val = self._val_for(0x00, 0xEF, 0xAA21)
        # data[0] = prot_reg, data[1:3] = status bytes (both 0)
        esp.command.return_value = (val, bytes([0x00, 0x00, 0x00]))

        ESPLoader.flash_spi_nand_attach(esp, 0)

        esp.command.assert_called_once()

    def test_unknown_jedec_raises(self):
        esp = _make_esp()
        val = self._val_for(0x00, 0x01, 0x0001)  # unknown
        esp.command.return_value = (val, bytes([0x00, 0x00, 0x00]))

        with pytest.raises(FatalError, match="Unrecognized NAND JEDEC ID"):
            ESPLoader.flash_spi_nand_attach(esp, 0)

    def test_short_response_raises(self):
        esp = _make_esp()
        esp.command.return_value = (0, bytes([0x00, 0x00]))  # only 2 bytes

        with pytest.raises(FatalError):
            ESPLoader.flash_spi_nand_attach(esp, 0)

    def test_nonzero_status_byte_raises(self):
        esp = _make_esp()
        val = self._val_for(0x00, 0xEF, 0xAA21)
        # data[1] (status_bytes[0]) non-zero → FatalError.WithResult
        esp.command.return_value = (val, bytes([0x00, 0x01, 0x00]))

        with pytest.raises(FatalError):
            ESPLoader.flash_spi_nand_attach(esp, 0)

    def test_nonzero_prot_reg_warns(self):
        esp = _make_esp()
        val = self._val_for(0x00, 0xEF, 0xAA21)
        # prot_reg (data[0]) = 0x08 → should warn
        esp.command.return_value = (val, bytes([0x08, 0x00, 0x00]))

        warnings = []
        with patch("esptool.loader.log") as mock_log:
            mock_log.warning.side_effect = warnings.append
            ESPLoader.flash_spi_nand_attach(esp, 0)

        assert any("prot" in w.lower() for w in warnings)


@pytest.mark.host_test
class TestDumpBbm:
    """dump_bbm writes a correctly-sized file with correct good/bad encoding."""

    def test_file_length_equals_block_count(self, tmp_path):
        from esptool.cmds import dump_bbm

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF

        out = str(tmp_path / "bbm.bin")
        dump_bbm(esp, out, block_count=16)

        assert os.path.getsize(out) == 16

    def test_good_block_encodes_as_zero(self, tmp_path):
        from esptool.cmds import dump_bbm

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF  # good

        out = str(tmp_path / "bbm.bin")
        dump_bbm(esp, out, block_count=4)

        with open(out, "rb") as f:
            data = f.read()
        assert all(b == 0x00 for b in data)

    def test_bad_block_encodes_as_one(self, tmp_path):
        from esptool.cmds import dump_bbm

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0x00  # bad

        out = str(tmp_path / "bbm.bin")
        dump_bbm(esp, out, block_count=4)

        with open(out, "rb") as f:
            data = f.read()
        assert all(b == 0x01 for b in data)

    def test_page_numbers_are_block_times_pages_per_block(self, tmp_path):
        from esptool.cmds import NAND_PAGES_PER_BLOCK, dump_bbm

        esp = _make_esp()
        esp.read_nand_spare.return_value = 0xFF
        block_count = 8

        out = str(tmp_path / "bbm.bin")
        dump_bbm(esp, out, block_count=block_count)

        page_args = [c[0][0] for c in esp.read_nand_spare.call_args_list]
        for blk in range(block_count):
            assert page_args[blk] == blk * NAND_PAGES_PER_BLOCK


@pytest.mark.host_test
class TestReadFlashNandLoader:
    """ESPLoader.read_flash_nand — IS_STUB guard, short frame, MD5 mismatch."""

    def test_not_stub_raises(self):
        esp = _make_esp()
        esp.IS_STUB = False

        with pytest.raises(FatalError, match="stub"):
            ESPLoader.read_flash_nand(esp, 0, 4096)

    def test_md5_mismatch_raises(self):

        esp = _make_esp()
        esp.IS_STUB = True

        page = b"\xaa" * esp.FLASH_SECTOR_SIZE
        wrong_digest = bytes.fromhex("deadbeef" * 4)  # 16 bytes, wrong

        port = MagicMock()
        port.timeout = 5
        esp._port = port

        esp.check_command.return_value = None
        esp.read.side_effect = [page, wrong_digest]
        esp.write.return_value = None

        with pytest.raises(FatalError, match="[Dd]igest"):
            ESPLoader.read_flash_nand(esp, 0, esp.FLASH_SECTOR_SIZE)

    def test_short_digest_frame_raises(self):
        esp = _make_esp()
        esp.IS_STUB = True

        page = b"\xbb" * esp.FLASH_SECTOR_SIZE
        short_digest = b"\x00" * 8  # only 8 bytes, not 16

        port = MagicMock()
        port.timeout = 5
        esp._port = port

        esp.check_command.return_value = None
        esp.read.side_effect = [page, short_digest]
        esp.write.return_value = None

        with pytest.raises(FatalError, match="digest"):
            ESPLoader.read_flash_nand(esp, 0, esp.FLASH_SECTOR_SIZE)


@pytest.mark.host_test
class TestNandSpareLoader:
    """ESPLoader.read_nand_spare / write_nand_spare — opcode + struct packing."""

    def test_read_nand_spare_correct_opcode_and_pack(self):
        esp = _make_esp()
        esp.check_command.return_value = 0xFFFFFFFF

        result = ESPLoader.read_nand_spare(esp, 42)

        call_args = esp.check_command.call_args
        assert call_args[0][1] == ESPLoader.ESP_CMDS["SPI_NAND_READ_SPARE"]
        assert call_args[0][2] == struct.pack("<I", 42)
        assert result == 0xFFFFFFFF

    def test_write_nand_spare_correct_opcode_and_pack(self):
        esp = _make_esp()
        esp.check_command.return_value = 0x00000000

        result = ESPLoader.write_nand_spare(esp, 7, 1)

        call_args = esp.check_command.call_args
        assert call_args[0][1] == ESPLoader.ESP_CMDS["SPI_NAND_WRITE_SPARE"]
        assert call_args[0][2] == struct.pack("<IB", 7, 1)
        assert result == 0x00000000


@pytest.mark.host_test
class TestCliValidation:
    """_require_spi_connection_for_nand rejects nand flash-type without connection."""

    def _run(self, args):
        from click.testing import CliRunner

        from esptool import cli

        cli._esp = None  # required by Group.parse_args when not called via cli(esp=...)
        runner = CliRunner()
        return runner.invoke(cli, args, catch_exceptions=False)

    def test_read_flash_nand_missing_spi_connection(self, tmp_path):
        out = str(tmp_path / "out.bin")
        result = self._run(
            ["--chip", "esp32s3", "read-flash", "--flash-type", "nand", "0", "128", out]
        )
        assert result.exit_code != 0
        assert "--spi-connection" in result.output

    def test_write_flash_nand_missing_spi_connection(self, tmp_path):
        dummy = tmp_path / "fw.bin"
        dummy.write_bytes(b"\xff" * 4)
        result = self._run(
            [
                "--chip",
                "esp32s3",
                "write-flash",
                "--flash-type",
                "nand",
                "0",
                str(dummy),
            ]
        )
        assert result.exit_code != 0
        assert "--spi-connection" in result.output

    def test_erase_flash_nand_missing_spi_connection(self):
        result = self._run(["--chip", "esp32s3", "erase-flash", "--flash-type", "nand"])
        assert result.exit_code != 0
        assert "--spi-connection" in result.output

    def test_erase_region_nand_missing_spi_connection(self):
        result = self._run(
            [
                "--chip",
                "esp32s3",
                "erase-region",
                "--flash-type",
                "nand",
                "0",
                "131072",
            ]
        )
        assert result.exit_code != 0
        assert "--spi-connection" in result.output

    def test_verify_flash_nand_missing_spi_connection(self, tmp_path):
        dummy = tmp_path / "fw.bin"
        dummy.write_bytes(b"\xff" * 4)
        result = self._run(
            [
                "--chip",
                "esp32s3",
                "verify-flash",
                "--flash-type",
                "nand",
                "0",
                str(dummy),
            ]
        )
        assert result.exit_code != 0
        assert "--spi-connection" in result.output

    def test_read_nand_spare_missing_spi_connection(self):
        result = self._run(["--chip", "esp32s3", "read-nand-spare", "0"])
        assert result.exit_code != 0
        assert "--spi-connection" in result.output
