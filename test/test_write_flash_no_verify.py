# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Host-level unit tests for write-flash (no hardware required)."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from esptool.loader import ESPLoader


def _stub_esp():
    """A MagicMock stub-flasher ESPLoader with an in-memory flash."""
    esp = MagicMock(spec=ESPLoader)
    esp.IS_STUB = True
    esp.CHIP_NAME = "ESP32-S3"
    esp.FLASH_SECTOR_SIZE = 0x1000
    esp.FLASH_WRITE_SIZE = 0x4000
    esp.WRITE_FLASH_ATTEMPTS = 2
    esp.BOOTLOADER_FLASH_OFFSET = 0x0
    esp.secure_download_mode = False
    esp.get_secure_boot_enabled.return_value = False
    esp.get_secure_boot_v1_enabled.return_value = False
    esp.get_flash_encryption_enabled.return_value = False
    esp.flash_md5sum.side_effect = lambda address, size: hashlib.md5(
        b"\xff" * size
    ).hexdigest()
    return esp


@pytest.mark.host_test
class TestNoVerify:
    def _write(self, esp, **kwargs):
        from esptool import cmds

        with (
            patch.object(cmds, "_set_flash_parameters", return_value="4MB"),
            patch.object(cmds, "detect_flash_size", return_value="4MB"),
        ):
            cmds.write_flash(
                esp, [(0x10000, b"\xa5" * 0x2000)], no_compress=True, **kwargs
            )

    def test_verifies_by_default(self):
        esp = _stub_esp()
        esp.flash_md5sum.side_effect = lambda address, size: hashlib.md5(
            b"\xa5" * size
        ).hexdigest()
        self._write(esp)
        esp.flash_md5sum.assert_called_once_with(0x10000, 0x2000)

    def test_no_verify_skips_the_md5(self):
        esp = _stub_esp()  # flash would not match: verifying would fail
        self._write(esp, no_verify=True)
        esp.flash_md5sum.assert_not_called()
        assert esp.flash_block.call_count == 1

    def test_no_verify_does_not_warn(self, capsys):
        self._write(_stub_esp(), no_verify=True)
        assert "without verification" not in capsys.readouterr().err

    def test_no_verify_with_diff_with_warns(self, capsys):
        esp = _stub_esp()
        self._write(esp, no_verify=True, diff_with=[b"\xff" * 0x2000])
        assert "without verification" in capsys.readouterr().err
        esp.flash_md5sum.assert_not_called()


@pytest.mark.host_test
class TestNoVerifyCli:
    def _run(self, tmp_path, *extra):
        from click.testing import CliRunner

        import esptool
        from esptool import cli

        fw = tmp_path / "fw.bin"
        fw.write_bytes(b"\xa5" * 0x2000)
        cli._esp = None  # required by Group.parse_args when not called via cli(esp=...)
        with (
            patch.object(esptool, "prepare_esp_object"),
            patch.object(esptool, "attach_flash"),
            patch.object(esptool, "write_flash") as write_flash,
        ):
            result = CliRunner().invoke(
                cli,
                ["--chip", "esp32s3", "write-flash", *extra, "0x10000", str(fw)],
                catch_exceptions=False,
            )
        assert result.exit_code == 0
        return result, write_flash

    def test_no_verify_warns(self, tmp_path):
        result, write_flash = self._run(tmp_path, "--no-verify")
        assert "--no-verify" in result.output
        assert write_flash.call_args.kwargs["no_verify"] is True

    def test_default_does_not_warn(self, tmp_path):
        result, write_flash = self._run(tmp_path)
        assert "--no-verify" not in result.output
        assert write_flash.call_args.kwargs["no_verify"] is False
