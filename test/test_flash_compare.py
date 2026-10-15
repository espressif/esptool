# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Host-level unit tests for write-flash helpers (no hardware required)."""

import hashlib
from unittest.mock import MagicMock

import pytest

from esptool.loader import ESPLoader


def _flash_esp(flash: bytes, base: int = 0):
    """A MagicMock ESPLoader whose flash_md5sum hashes `flash`, mapped at `base`."""
    esp = MagicMock(spec=ESPLoader)
    esp.FLASH_SECTOR_SIZE = 0x1000

    def md5(address, size):
        return hashlib.md5(flash[address - base : address - base + size]).hexdigest()

    esp.flash_md5sum.side_effect = md5
    return esp


@pytest.mark.host_test
class TestFlashMatches:
    def test_match_hashes_every_chunk(self):
        from esptool.cmds import _flash_matches

        data = bytes(range(256)) * 0x200  # 128 KB
        esp = _flash_esp(data, base=0x10000)
        assert _flash_matches(esp, 0x10000, data)
        sizes = [c.args[1] for c in esp.flash_md5sum.call_args_list]
        assert sizes == [0x10000, 0x10000]

    def test_mismatch_in_first_chunk_stops_at_once(self):
        from esptool.cmds import _flash_matches

        data = b"\xaa" * 0x20000
        esp = _flash_esp(b"\x55" + data[1:])
        assert not _flash_matches(esp, 0, data)
        assert esp.flash_md5sum.call_count == 1

    def test_mismatch_later_stops_at_that_chunk(self):
        from esptool.cmds import _flash_matches

        data = b"\xaa" * 0x30000
        flash = bytearray(data)
        flash[0x12000] ^= 0xFF
        esp = _flash_esp(bytes(flash))
        assert not _flash_matches(esp, 0, data)
        assert esp.flash_md5sum.call_count == 2
