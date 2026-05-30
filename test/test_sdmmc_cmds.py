# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Host-only unit tests for the SDMMC plugin command path."""

import struct
from unittest.mock import MagicMock

import pytest

from esptool.loader import (
    SDMMC_ERROR_NAMES,
    SDMMC_SECTOR_SIZE,
    _decode_sdmmc_diag,
)
from esptool.util import FatalError


@pytest.mark.host_test
class TestDecodeSdmmcDiag:
    """The packed {stage, err, rintsts} diagnostic word from a failed attach."""

    def test_known_error_with_cmd_stage(self):
        # stage=CMD8, err=-3 (TIMEOUT), RINTSTS=0x0100 (RTO)
        val = (8 << 24) | ((-3 & 0xFF) << 16) | 0x0100
        signed, name, stage_str, rintsts_str = _decode_sdmmc_diag(val)
        assert signed == -3
        assert name == "SDMMC_ERR_TIMEOUT"
        assert stage_str == "CMD8"
        assert "RTO" in rintsts_str

    def test_stage_sentinel_update_clk(self):
        val = (0xFE << 24) | ((-3 & 0xFF) << 16)
        _, _, stage_str, _ = _decode_sdmmc_diag(val)
        assert "update_clk_reg" in stage_str

    def test_stage_sentinel_pre_command(self):
        val = (0xFF << 24) | ((-3 & 0xFF) << 16)
        _, _, stage_str, _ = _decode_sdmmc_diag(val)
        assert "pre-command" in stage_str

    def test_unknown_error_code(self):
        val = (0 << 24) | ((-99 & 0xFF) << 16)
        signed, name, _, _ = _decode_sdmmc_diag(val)
        assert signed == -99
        assert name is None

    def test_zero_rintsts_text(self):
        val = (8 << 24) | ((-3 & 0xFF) << 16) | 0
        _, _, _, rintsts_str = _decode_sdmmc_diag(val)
        assert "RINTSTS=0" in rintsts_str

    def test_all_named_errors_resolve(self):
        for code in SDMMC_ERROR_NAMES:
            val = (0xFF << 24) | ((code & 0xFF) << 16)
            signed, name, _, _ = _decode_sdmmc_diag(val)
            assert signed == code
            assert name == SDMMC_ERROR_NAMES[code]


def _make_stub_esp():
    """Minimal ESPLoader mock that satisfies the SDMMC method validation paths."""
    esp = MagicMock()
    esp.IS_STUB = True
    esp.ESP_CMDS = {
        "SPI_SDMMC_ATTACH": 0xDF,
        "SPI_SDMMC_READ_FLASH": 0xE0,
        "SPI_SDMMC_WRITE_FLASH_BEGIN": 0xE1,
        "SPI_SDMMC_WRITE_FLASH_DATA": 0xE2,
        "SPI_SDMMC_WRITE_FLASH_END": 0xE3,
        "SPI_SDMMC_ERASE_REGION": 0xE4,
        "SPI_SDMMC_GET_INFO": 0xE5,
    }
    esp.FLASH_SECTOR_SIZE = 0x1000
    esp.FLASH_WRITE_SIZE = 0x4000
    return esp


@pytest.mark.host_test
class TestSdmmcAttachPayload:
    """Verify the on-wire layout of the attach payload."""

    def test_payload_is_16_bytes(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        esp.command = MagicMock(
            # value=1024 (capacity_sectors), data = 12 bytes of info + 2 status bytes
            return_value=(1024, b"\x00" * 12 + b"\x00\x00"),
        )
        ESPLoader.sdmmc_attach(esp)
        sent_payload = esp.command.call_args[0][1]
        assert len(sent_payload) == 16

    def test_payload_packs_pins_in_order(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        esp.command = MagicMock(return_value=(0, b"\x00" * 14))
        ESPLoader.sdmmc_attach(
            esp,
            slot=0,
            width=4,
            freq_khz=20000,
            cd_pin=0xFF,
            wp_pin=0xFF,
            pin_clk=14,
            pin_cmd=15,
            pin_d=(2, 4, 12, 13, 33, 34, 35, 36),
        )
        sent = esp.command.call_args[0][1]
        slot, width, freq, cd, wp, clk, cmd = struct.unpack("<BBHBBBB", sent[:8])
        d = list(sent[8:16])
        assert slot == 0 and width == 4 and freq == 20000
        assert cd == 0xFF and wp == 0xFF and clk == 14 and cmd == 15
        assert d == [2, 4, 12, 13, 33, 34, 35, 36]

    def test_invalid_width_rejected(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="bus width"):
            ESPLoader.sdmmc_attach(esp, width=2)

    def test_invalid_pin_d_length_rejected(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="pin_d"):
            ESPLoader.sdmmc_attach(esp, pin_d=(0, 0, 0, 0))


@pytest.mark.host_test
class TestSdmmcRwAlignment:
    """Validation paths in read/write/erase that reject unaligned offsets."""

    def test_read_unaligned_offset_raises(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="must be a multiple of"):
            ESPLoader.read_flash_sdmmc(esp, offset=1, length=SDMMC_SECTOR_SIZE)

    def test_read_unaligned_length_raises(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="must be a multiple of"):
            ESPLoader.read_flash_sdmmc(esp, offset=0, length=SDMMC_SECTOR_SIZE - 1)

    def test_write_begin_unaligned_offset_raises(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="must be a multiple of"):
            ESPLoader.write_flash_sdmmc_begin(
                esp, size=SDMMC_SECTOR_SIZE, offset=SDMMC_SECTOR_SIZE - 1
            )

    def test_write_begin_unaligned_size_raises(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="must be a multiple of"):
            ESPLoader.write_flash_sdmmc_begin(esp, size=1, offset=0)

    def test_erase_unaligned_offset_raises(self):
        from esptool.loader import ESPLoader

        esp = _make_stub_esp()
        with pytest.raises(FatalError, match="must be a multiple of"):
            ESPLoader.erase_sdmmc_region(esp, offset=1, size=SDMMC_SECTOR_SIZE)
