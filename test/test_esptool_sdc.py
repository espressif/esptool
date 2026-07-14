# Host-only unit tests for the esptool-side Secure Debug Controller (SDC) support.
#
# These cover the code added on top of the espsecure SDC support, i.e. the
# device-facing commands and protocol helpers:
#   - esptool.cmds.verify_sdc_certificate / read_sdc_chip_info
#   - esptool.loader.ESPLoader.sdc_verify_* / sdc_gen_* command packing
#   - esptool.util.UnsupportedCommandError messaging
#
# They do NOT talk to a real chip - the ESPLoader is replaced by a mock, so the
# tests only validate esptool's framing/file handling, not whether the device
# actually (un)locks the SDC. Run with: `pytest test/test_esptool_sdc.py`
# (also picked up by `pytest -m host_test`).

import os
import struct
import tempfile
from unittest.mock import MagicMock

import pytest
from conftest import need_to_install_package_err

try:
    from esptool.cmds import read_sdc_chip_info, verify_sdc_certificate
    from esptool.loader import DEFAULT_TIMEOUT, ESPLoader
    from esptool.util import FatalError, UnsupportedCommandError
except ImportError:
    need_to_install_package_err()


@pytest.mark.host_test
class TestVerifySdcCertificate:
    def test_verify_sdc_certificate_flow(self):
        """verify_sdc_certificate streams the file through begin/data/end."""
        cert = os.urandom(468)  # header(20) + body(416) + nonce(32)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(cert)
            cert_path = f.name
        try:
            esp = MagicMock()
            verify_sdc_certificate(esp, cert_path)

            # begin is told whether a nonce is enabled (1) and the cert length
            esp.sdc_verify_begin.assert_called_once_with(1, len(cert))
            # the full certificate is sent verbatim
            esp.sdc_verify_data.assert_called_once_with(cert)
            # end is what makes the ROM accept/reject - it must be called
            esp.sdc_verify_end.assert_called_once_with()
        finally:
            os.unlink(cert_path)

    def test_verify_sdc_certificate_rejected(self):
        """A ROM rejection in sdc_verify_end must propagate, not be swallowed."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(os.urandom(64))
            cert_path = f.name
        try:
            esp = MagicMock()
            esp.sdc_verify_end.side_effect = FatalError("certificate rejected by ROM")
            with pytest.raises(FatalError, match="rejected"):
                verify_sdc_certificate(esp, cert_path)
        finally:
            os.unlink(cert_path)


@pytest.mark.host_test
class TestReadSdcChipInfo:
    def test_read_sdc_chip_info_layout(self):
        """Output is chip_info(32) + the nonce(32) that was sent to the device."""
        chip_info = bytes(range(32))
        esp = MagicMock()
        esp.sdc_gen_end.return_value = chip_info

        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "chip_info.bin")
            read_sdc_chip_info(esp, out)

            assert os.path.getsize(out) == 64
            with open(out, "rb") as f:
                data = f.read()

        # the nonce written to the file is exactly the one sent to sdc_gen_data
        nonce_sent = esp.sdc_gen_data.call_args.args[0]
        assert len(nonce_sent) == 32
        assert data[:32] == chip_info
        assert data[32:] == nonce_sent
        esp.sdc_gen_begin.assert_called_once_with()
        esp.sdc_gen_end.assert_called_once_with()

    def test_read_sdc_chip_info_random_nonce(self):
        """Each invocation uses a fresh random nonce."""
        esp = MagicMock()
        esp.sdc_gen_end.return_value = bytes(32)
        with tempfile.TemporaryDirectory() as d:
            read_sdc_chip_info(esp, os.path.join(d, "a.bin"))
            read_sdc_chip_info(esp, os.path.join(d, "b.bin"))
        first = esp.sdc_gen_data.call_args_list[0].args[0]
        second = esp.sdc_gen_data.call_args_list[1].args[0]
        assert first != second

    @pytest.mark.parametrize("bad", [None, b"too-short", bytes(31), bytes(33)])
    def test_read_sdc_chip_info_invalid_size(self, bad):
        """A missing or wrong-sized chip_info from the ROM is an error."""
        esp = MagicMock()
        esp.sdc_gen_end.return_value = bad
        with tempfile.TemporaryDirectory() as d:
            with pytest.raises(FatalError, match="chip info"):
                read_sdc_chip_info(esp, os.path.join(d, "chip_info.bin"))


def _loader_mock(is_stub=False):
    """A stand-in `self` for calling unbound ESPLoader SDC methods.

    Keeps the real ESP_CMDS opcode table and checksum so the framing under test
    is exercised, while check_command is mocked out (no serial I/O).
    """
    esp = MagicMock()
    esp.ESP_CMDS = ESPLoader.ESP_CMDS
    esp.checksum = ESPLoader.checksum
    esp.IS_STUB = is_stub
    return esp


@pytest.mark.host_test
class TestSdcLoaderFraming:
    def test_sdc_opcodes_registered(self):
        # Opcodes must match the ROM SDC command IDs (0x19-0x1E).
        assert ESPLoader.ESP_CMDS["SDC_VERIF_BEGIN"] == 0x19
        assert ESPLoader.ESP_CMDS["SDC_VERIF_DATA"] == 0x1A
        assert ESPLoader.ESP_CMDS["SDC_VERIF_END"] == 0x1B
        assert ESPLoader.ESP_CMDS["SDC_GEN_BEGIN"] == 0x1C
        assert ESPLoader.ESP_CMDS["SDC_GEN_DATA"] == 0x1D
        assert ESPLoader.ESP_CMDS["SDC_GEN_END"] == 0x1E

    def test_verify_begin_packs_nonce_and_size(self):
        esp = _loader_mock()
        ESPLoader.sdc_verify_begin(esp, 1, 468)
        args, kwargs = esp.check_command.call_args
        assert args[1] == 0x19  # SDC_VERIF_BEGIN
        assert args[2] == struct.pack("<II", 1, 468)
        assert kwargs["timeout"] == DEFAULT_TIMEOUT

    def test_verify_data_packs_length_and_checksum(self):
        esp = _loader_mock()
        payload = os.urandom(100)
        ESPLoader.sdc_verify_data(esp, payload)
        args, _ = esp.check_command.call_args
        assert args[1] == 0x1A  # SDC_VERIF_DATA
        assert args[2] == struct.pack("<I", len(payload)) + payload
        assert args[3] == ESPLoader.checksum(payload)  # chk

    def test_gen_data_packs_length_and_checksum(self):
        esp = _loader_mock()
        nonce = os.urandom(32)
        ESPLoader.sdc_gen_data(esp, nonce)
        args, _ = esp.check_command.call_args
        assert args[1] == 0x1D  # SDC_GEN_DATA
        assert args[2] == struct.pack("<I", len(nonce)) + nonce
        assert args[3] == ESPLoader.checksum(nonce)

    def test_gen_end_returns_first_32_bytes(self):
        esp = _loader_mock()
        esp.check_command.return_value = bytes(range(40))
        assert ESPLoader.sdc_gen_end(esp) == bytes(range(32))

    def test_gen_end_handles_empty_result(self):
        esp = _loader_mock()
        esp.check_command.return_value = b""
        assert ESPLoader.sdc_gen_end(esp) is None

    def test_gen_begin_swallows_fatalerror_in_rom(self):
        # In ROM mode the begin/data steps may legitimately error; this is
        # tolerated. With the stub it must propagate.
        esp = _loader_mock(is_stub=False)
        esp.check_command.side_effect = FatalError("rom rejected")
        assert ESPLoader.sdc_gen_begin(esp) is None  # no raise

        esp_stub = _loader_mock(is_stub=True)
        esp_stub.check_command.side_effect = FatalError("rom rejected")
        with pytest.raises(FatalError):
            ESPLoader.sdc_gen_begin(esp_stub)

    def test_gen_data_swallows_fatalerror_in_rom(self):
        esp = _loader_mock(is_stub=False)
        esp.check_command.side_effect = FatalError("rom rejected")
        assert ESPLoader.sdc_gen_data(esp, os.urandom(32)) is None

        esp_stub = _loader_mock(is_stub=True)
        esp_stub.check_command.side_effect = FatalError("rom rejected")
        with pytest.raises(FatalError):
            ESPLoader.sdc_gen_data(esp_stub, os.urandom(32))


@pytest.mark.host_test
class TestUnsupportedCommandError:
    def test_is_fatalerror_subclass(self):
        # Changed from RuntimeError to FatalError so the CLI handles it cleanly.
        assert issubclass(UnsupportedCommandError, FatalError)

    def test_secure_download_mode_message(self):
        esp = MagicMock()
        esp.secure_download_mode = True
        err = UnsupportedCommandError(esp, 0x05)
        assert "Secure Download Mode" in str(err)
        assert "0x5" in str(err)

    def test_restricted_mode_message_points_to_sdc_on_s31(self):
        esp = MagicMock()
        esp.secure_download_mode = False
        esp.CHIP_NAME = "ESP32-S31"
        err = UnsupportedCommandError(esp, 0x19)
        msg = str(err)
        # On the SDC-capable chip the guidance tells the user how to re-open
        # download mode.
        assert "verify-sdc-certificate" in msg
        assert "no-reset" in msg
        assert "0x19" in msg

    def test_restricted_mode_message_generic_on_other_chips(self):
        # SDC only exists on ESP32-S31; other chips must not see the SDC hint.
        esp = MagicMock()
        esp.secure_download_mode = False
        esp.CHIP_NAME = "ESP32-C3"
        msg = str(UnsupportedCommandError(esp, 0x19))
        assert "current download mode" in msg
        assert "SDC" not in msg
        assert "verify-sdc-certificate" not in msg
