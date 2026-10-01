# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Host-level unit tests for write-flash (no hardware required)."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from esptool.loader import ESPLoader

SECTOR = 0x1000


def _stub_esp(flash: bytearray):
    """A MagicMock stub-flasher ESPLoader writing into `flash` (mapped at 0)."""
    esp = MagicMock(spec=ESPLoader)
    esp.IS_STUB = True
    esp.CHIP_NAME = "ESP32-S3"
    esp.FLASH_SECTOR_SIZE = SECTOR
    esp.FLASH_WRITE_SIZE = 0x400
    esp.WRITE_FLASH_ATTEMPTS = 2
    esp.BOOTLOADER_FLASH_OFFSET = 0x0
    esp.secure_download_mode = False
    esp.get_secure_boot_enabled.return_value = False
    esp.get_secure_boot_v1_enabled.return_value = False
    esp.get_flash_encryption_enabled.return_value = False
    state = {}

    def begin(size, offset, **_):
        state["offset"] = offset

    def block(data, seq, **_):
        start = state["offset"] + seq * esp.FLASH_WRITE_SIZE
        flash[start : start + len(data)] = data

    esp.flash_begin.side_effect = begin
    esp.flash_block.side_effect = block
    esp.flash_md5sum.side_effect = lambda address, size: hashlib.md5(
        bytes(flash[address : address + size])
    ).hexdigest()
    return esp


@pytest.mark.host_test
class TestFastReflashProgress:
    def test_regions_share_one_bar_and_one_summary(self, capsys):
        from esptool import cmds

        old = b"\xaa" * 16 * SECTOR
        new = bytearray(old)
        new[1 * SECTOR] = new[8 * SECTOR] = 0x55  # two regions, far apart
        flash = bytearray(old)
        esp = _stub_esp(flash)
        bars = []
        real_progress = cmds.log.progress

        def progress(total, **kwargs):
            bars.append(total)
            return real_progress(total, **kwargs)

        with (
            patch.object(cmds, "_set_flash_parameters", return_value="4MB"),
            patch.object(cmds, "detect_flash_size", return_value="4MB"),
            patch.object(cmds.log, "progress", side_effect=progress),
        ):
            cmds.write_flash(esp, [(0, bytes(new))], diff_with=[old], no_compress=True)

        assert flash == new
        assert bars == [2 * SECTOR]
        out = capsys.readouterr().out
        assert "Wrote 8192 bytes in 2 regions" in out
        assert "Reflashing" not in out
