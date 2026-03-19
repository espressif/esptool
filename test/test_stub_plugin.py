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

from esptool.loader import StubFlasher

STUB_DIR = os.path.join(
    os.path.dirname(__file__), "..", "esptool", "targets", "stub_flasher"
)
ESP32S3_JSON_V2 = os.path.join(STUB_DIR, "2", "esp32s3.json")
ESP32S3_JSON_V1 = os.path.join(STUB_DIR, "1", "esp32s3.json")


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

    def test_v2_json_exists(self):
        assert os.path.exists(ESP32S3_JSON_V2), "esp32s3 v2 JSON missing"

    def test_no_plugin_segments(self, stub_v2_env):
        stub = _load_stub_v2()
        assert stub.plugin_segments == []

    def test_text_and_data_decoded(self, stub_v2_env):
        stub = _load_stub_v2()
        assert len(stub.text) > 0
        assert stub.text_start > 0
        assert stub.data is not None
        assert len(stub.data) > 0

    def test_data_size_unchanged_without_plugin(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        expected_len = len(base64.b64decode(raw["data"]))
        stub = _load_stub_v2()
        assert len(stub.data) == expected_len


@pytest.mark.host_test
class TestStubFlasherWithNandPlugin:
    """Verify StubFlasher correctly applies the NAND plugin."""

    def test_plugin_segment_added(self, stub_v2_env):
        stub = _load_stub_v2_with_nand()
        assert len(stub.plugin_segments) == 1

    def test_plugin_segment_address(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        expected_addr = raw["plugins"]["nand"]["text_start"]
        stub = _load_stub_v2_with_nand()
        load_addr, _ = stub.plugin_segments[0]
        assert load_addr == expected_addr

    def test_plugin_text_4byte_aligned(self, stub_v2_env):
        """Plugin text must be padded to 4-byte boundary (Xtensa IRAM constraint)."""
        stub = _load_stub_v2_with_nand()
        _, seg_bytes = stub.plugin_segments[0]
        assert len(seg_bytes) % 4 == 0, (
            f"Plugin text is {len(seg_bytes)} bytes — not 4-byte aligned"
        )

    def test_data_extended_by_bss_size(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        base_data_len = len(base64.b64decode(raw["data"]))
        bss_size = raw["plugins"]["nand"]["bss_size"]
        stub = _load_stub_v2_with_nand()
        assert len(stub.data) == base_data_len + bss_size

    def test_plugin_bss_zeros(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        base_data_len = len(base64.b64decode(raw["data"]))
        stub = _load_stub_v2_with_nand()
        # The appended BSS region must be all zeros
        appended = stub.data[base_data_len:]
        assert all(b == 0 for b in appended), "Plugin BSS zeros not zeroed"

    def test_fpt_entries_patched(self, stub_v2_env):
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        fpt_offset = raw["plugin_table_offset"]
        first_opcode = raw.get("plugin_first_opcode", 0xD5)
        nand = raw["plugins"]["nand"]
        text_start = nand["text_start"]

        stub = _load_stub_v2_with_nand()

        for opcode_str, handler_offset in nand["handlers"].items():
            opcode = int(opcode_str, 16)
            idx = opcode - first_opcode
            entry_off = fpt_offset + idx * 4
            expected_addr = text_start + handler_offset
            actual_addr = struct.unpack_from("<I", stub.data, entry_off)[0]
            assert actual_addr == expected_addr, (
                f"FPT[{idx}] (opcode {opcode_str}): "
                f"expected 0x{expected_addr:08x}, got 0x{actual_addr:08x}"
            )

    def test_unpatched_fpt_slots_unchanged(self, stub_v2_env):
        """FPT slots not covered by the nand plugin must retain the default value."""
        with open(ESP32S3_JSON_V2) as f:
            raw = json.load(f)
        fpt_offset = raw["plugin_table_offset"]
        first_opcode = raw.get("plugin_first_opcode", 0xD5)
        n_entries = raw.get("plugin_table_entries", 27)
        patched_indices = {
            int(op, 16) - first_opcode for op in raw["plugins"]["nand"]["handlers"]
        }

        # Read the default FPT value from the raw data (before plugin patching)
        raw_data = bytearray(base64.b64decode(raw["data"]))
        # All unpatched slots should share the same default (s_plugin_unsupported addr)
        default_values = set()
        for i in range(n_entries):
            if i not in patched_indices:
                off = fpt_offset + i * 4
                default_values.add(struct.unpack_from("<I", raw_data, off)[0])
        # Expect at most one unique default value
        assert len(default_values) == 1, (
            f"Multiple default FPT values found: {default_values}"
        )
        default_val = default_values.pop()

        # In stub with plugin, unpatched slots must still have the default value
        stub = _load_stub_v2_with_nand()
        for i in range(n_entries):
            if i not in patched_indices:
                off = fpt_offset + i * 4
                actual = struct.unpack_from("<I", stub.data, off)[0]
                assert actual == default_val, (
                    f"FPT slot {i} was unexpectedly modified: "
                    f"expected 0x{default_val:08x}, got 0x{actual:08x}"
                )

    def test_unknown_plugin_raises(self, stub_v2_env):
        from esptool.util import FatalError

        with pytest.raises(FatalError, match="not found in.*stub"):
            StubFlasher(_make_target("esp32s3.json"), plugins=["no_such_plugin"])

    def test_v1_stub_with_plugin_raises(self, monkeypatch):
        """v1 stub has no plugin_table_offset → requesting plugins raises error."""
        with open(ESP32S3_JSON_V1) as f:
            raw = json.load(f)
        assert "plugin_table_offset" not in raw, (
            "v1 JSON should not have plugin_table_offset"
        )
        monkeypatch.setattr(StubFlasher, "STUB_SUBDIRS", ["1"])
        monkeypatch.setattr(StubFlasher, "STUB_VERSION_EXPLICIT", False)
        from esptool.util import FatalError

        with pytest.raises(FatalError, match="does not support plugins"):
            StubFlasher(_make_target("esp32s3.json"), plugins=["nand"])


@pytest.mark.host_test
class TestPluginChipSupport:
    """Verify plugin errors for unsupported chips (no hardware needed)."""

    @pytest.mark.parametrize(
        "json_name,chip_name",
        [
            ("esp32.json", "ESP32"),
            ("esp32s2.json", "ESP32-S2"),
            ("esp32c3.json", "ESP32-C3"),
            ("esp32c6.json", "ESP32-C6"),
            ("esp32h2.json", "ESP32-H2"),
        ],
    )
    def test_non_esp32s3_with_nand_raises(self, stub_v2_env, json_name, chip_name):
        """Requesting NAND on a non-ESP32-S3 chip gives a clear error."""
        from esptool.util import FatalError

        with pytest.raises(FatalError, match="does not support plugins"):
            StubFlasher(_make_target(json_name, chip_name=chip_name), plugins=["nand"])

    def test_esp32s3_nand_succeeds(self, stub_v2_env):
        """ESP32-S3 with NAND plugin loads without error (sanity check)."""
        stub = _load_stub_v2_with_nand()
        assert len(stub.plugin_segments) == 1

    def test_no_plugins_loads_fine_on_any_chip(self, stub_v2_env):
        """Without plugins, v2 stubs for any chip load without error."""
        for json_name, chip_name in [
            ("esp32.json", "ESP32"),
            ("esp32s3.json", "ESP32-S3"),
            ("esp32c3.json", "ESP32-C3"),
        ]:
            stub = StubFlasher(_make_target(json_name, chip_name=chip_name))
            assert stub.plugin_segments == []


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
