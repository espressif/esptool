# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Unit tests for StubFlasher plugin mechanism (no hardware required)."""

import base64
import json
import os
import struct
import types
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.linux_host_test

from esptool.loader import StubFlasher

STUB_DIR = os.path.join(
    os.path.dirname(__file__), "..", "esptool", "targets", "stub_flasher"
)
ESP32S3_JSON_V2 = os.path.join(STUB_DIR, "2", "esp32s3.json")


def _make_target(json_name, chip_name="ESP32-S3"):
    """Return a minimal mock target accepted by StubFlasher.__init__."""
    stub_class = MagicMock()
    stub_class.stub_json_name.return_value = json_name
    target = MagicMock()
    target.STUB_CLASS = stub_class
    target.CHIP_NAME = chip_name
    return target


@pytest.fixture
def stub_v2_env(monkeypatch):
    """Patch StubFlasher to prefer v2 stubs (auto-restored after each test)."""
    monkeypatch.setattr(StubFlasher, "STUB_SUBDIRS", ["2", "1"])
    monkeypatch.setattr(StubFlasher, "STUB_VERSION_EXPLICIT", False)


def _load_stub_v2():
    """Load StubFlasher with stub v2 (no plugins) for esp32s3."""
    return StubFlasher(_make_target("esp32s3.json"))


def _load_stub_v2_with_nand():
    """Load StubFlasher with stub v2 + nand plugin for esp32s3."""
    return StubFlasher(_make_target("esp32s3.json"), plugins=["nand"])


@pytest.mark.host_test
class TestStubFlasherWithoutPlugin:
    """Verify StubFlasher loads correctly without any plugin."""

    def test_stub_unchanged(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        stub = _load_stub_v2()
        assert stub.plugin_segments == []
        assert stub.data == base64.b64decode(raw["data"])


@pytest.mark.host_test
class TestStubFlasherWithNandPlugin:
    """Verify StubFlasher correctly applies the NAND plugin."""

    def test_nand_loaded(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        nand = raw["plugins"]["nand"]
        start_offset = raw["plugin_start_offset"]
        raw_data = base64.b64decode(raw["data"])
        stub = _load_stub_v2_with_nand()

        assert struct.unpack_from("<I", stub.data, start_offset)[0] == nand["entry"]
        # Only the first slot may change
        assert stub.data[:start_offset] == raw_data[:start_offset]
        assert stub.data[start_offset + 4 :] == raw_data[start_offset + 4 :]
        assert stub.plugin_segments == [
            (nand["text_start"], base64.b64decode(nand["text"]))
        ]

    def test_plugin_data_uploaded(self, stub_v2_env):
        """A plugin with .data gets a second segment at its data_start."""
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        spi = raw["plugins"]["spi"]
        stub = StubFlasher(_make_target("esp32s3.json"), plugins=["spi"])
        assert stub.plugin_segments == [
            (spi["text_start"], base64.b64decode(spi["text"])),
            (spi["data_start"], base64.b64decode(spi["data"])),
        ]

    def test_unknown_plugin_raises(self, stub_v2_env):
        from esptool.util import FatalError

        with pytest.raises(FatalError, match="not found in.*stub"):
            StubFlasher(_make_target("esp32s3.json"), plugins=["no_such_plugin"])

    def test_v1_stub_with_plugin_raises(self, monkeypatch):
        """v1 stub has no plugin_start_offset → requesting plugins raises error."""
        monkeypatch.setattr(StubFlasher, "STUB_SUBDIRS", ["1"])
        monkeypatch.setattr(StubFlasher, "STUB_VERSION_EXPLICIT", False)
        from esptool.util import FatalError

        with pytest.raises(FatalError, match="does not support plugins"):
            StubFlasher(_make_target("esp32s3.json"), plugins=["nand"])


@pytest.mark.host_test
class TestCustomStubCompatibility:
    """run_stub() must not fail when passed a custom stub without plugin_segments."""

    def test_custom_stub_no_plugin_segments(self):
        custom_stub = types.SimpleNamespace(
            text=b"\x00" * 4,
            text_start=0x40000000,
            data=b"\x00" * 4,
            data_start=0x3FFB0000,
            entry=0x40000000,
        )
        assert not hasattr(custom_stub, "plugin_segments")

        # Build a mock ESPLoader that has enough state for run_stub() to proceed
        esp = MagicMock()
        esp.sync_stub_detected = False
        esp.CHIP_NAME = "ESP32"
        esp.get_secure_boot_enabled.return_value = False
        esp.STUB_CLASS = MagicMock()
        esp.read.return_value = b"OHAI"

        # Call run_stub as an unbound method, passing our mock as self
        from esptool.loader import ESPLoader

        ESPLoader.run_stub(esp, stub=custom_stub)

        # If we get here without AttributeError, the fix works
        esp._upload_segment.assert_called()
        esp.mem_finish.assert_called_once_with(custom_stub.entry)


@pytest.mark.host_test
class TestNANDFailureCodeDecoding:
    """Status-byte decoding for the new NAND P_FAIL / E_FAIL response codes."""

    def test_program_failed_decodes_to_subclass(self):
        from esptool.util import FatalError, NANDProgramFailed

        exc = FatalError.WithResult("write failed", b"\xca\x00")
        assert isinstance(exc, NANDProgramFailed)
        assert isinstance(exc, FatalError)
        assert "NAND program failed" in str(exc)

    def test_erase_failed_decodes_to_subclass(self):
        from esptool.util import FatalError, NANDEraseFailed

        exc = FatalError.WithResult("erase failed", b"\xcb\x00")
        assert isinstance(exc, NANDEraseFailed)
        assert isinstance(exc, FatalError)
        assert "NAND erase failed" in str(exc)

    def test_transport_error_stays_plain_fatalerror(self):
        from esptool.util import FatalError, NANDEraseFailed, NANDProgramFailed

        exc = FatalError.WithResult("oops", b"\xc4\x00")  # RESPONSE_FAILED_SPI_OP
        assert isinstance(exc, FatalError)
        assert not isinstance(exc, NANDProgramFailed)
        assert not isinstance(exc, NANDEraseFailed)


@pytest.mark.host_test
class TestNANDBadBlockPolicy:
    """Bad-block marking must trigger only on chip-reported P_FAIL / E_FAIL.

    Transport-class errors (RESPONSE_FAILED_SPI_OP, timeouts, SLIP corruption)
    must NOT condemn the block.
    """

    def _fake_esp(self, erase_side_effect):
        """Minimal mock acceptable to cmds.erase_region's NAND branch."""
        esp = MagicMock()
        esp.read_nand_spare.return_value = 0xFF  # all blocks look good
        esp.erase_nand_region.side_effect = erase_side_effect
        return esp

    def test_transport_error_does_not_mark_bad(self):
        from esptool.cmds import NAND_BLOCK_SIZE, erase_region
        from esptool.util import FatalError

        def erase_glitch(addr, size):
            raise FatalError.WithResult("transport boom", b"\xc4\x00")

        esp = self._fake_esp(erase_side_effect=erase_glitch)

        # Transport-class FatalError must propagate (not be silently swallowed)
        # AND must NOT trigger a bad-block mark.
        with pytest.raises(FatalError):
            erase_region(esp, 0, NAND_BLOCK_SIZE, flash_type="nand")
        esp.write_nand_spare.assert_not_called()

    def test_chip_erase_failed_marks_bad(self):
        from esptool.cmds import (
            NAND_BLOCK_SIZE,
            NAND_PAGES_PER_BLOCK,
            erase_region,
        )
        from esptool.util import FatalError

        def erase_efail(addr, size):
            raise FatalError.WithResult("E_FAIL", b"\xcb\x00")

        esp = self._fake_esp(erase_side_effect=erase_efail)
        erase_region(esp, 0, NAND_BLOCK_SIZE, flash_type="nand")

        # The chip said E_FAIL → block 0, page 0 must be marked bad.
        esp.write_nand_spare.assert_called_once_with(0 * NAND_PAGES_PER_BLOCK, 1)

    def test_chip_pfail_bypasses_loader_retry(self):
        """write_flash_nand_block retries transport errors but NANDProgramFailed
        must bypass the retry entirely (chip says cell is bad — no point retrying)."""
        from esptool.loader import WRITE_BLOCK_ATTEMPTS, ESPLoader
        from esptool.util import FatalError, NANDProgramFailed

        # NANDProgramFailed: must surface on the very first attempt.
        esp = MagicMock(spec=ESPLoader)
        esp.ESP_CMDS = {"SPI_NAND_WRITE_FLASH_DATA": 0xDA}
        esp.checksum.return_value = 0
        esp.check_command.side_effect = FatalError.WithResult("P_FAIL", b"\xca\x00")

        with pytest.raises(NANDProgramFailed):
            ESPLoader.write_flash_nand_block(esp, b"\x00" * 4, 0)
        assert esp.check_command.call_count == 1

        # Plain transport FatalError: retried up to WRITE_BLOCK_ATTEMPTS times.
        esp2 = MagicMock(spec=ESPLoader)
        esp2.ESP_CMDS = {"SPI_NAND_WRITE_FLASH_DATA": 0xDA}
        esp2.checksum.return_value = 0
        esp2.check_command.side_effect = FatalError.WithResult("glitch", b"\xc4\x00")
        with pytest.raises(FatalError):
            ESPLoader.write_flash_nand_block(esp2, b"\x00" * 4, 0)
        assert esp2.check_command.call_count == WRITE_BLOCK_ATTEMPTS

    def test_chip_efail_bypasses_loader_retry(self):
        """NANDEraseFailed must also bypass the retry loop immediately."""
        from esptool.loader import ESPLoader
        from esptool.util import FatalError, NANDEraseFailed

        esp = MagicMock(spec=ESPLoader)
        esp.ESP_CMDS = {"SPI_NAND_WRITE_FLASH_DATA": 0xDA}
        esp.checksum.return_value = 0
        esp.check_command.side_effect = FatalError.WithResult("E_FAIL", b"\xcb\x00")

        with pytest.raises(NANDEraseFailed):
            ESPLoader.write_flash_nand_block(esp, b"\x00" * 4, 0)
        assert esp.check_command.call_count == 1
