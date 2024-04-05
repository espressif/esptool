# Unit tests (really integration tests) for esptool.py using the pytest framework
# Uses a device in the Secure Download Mode connected to the serial port.
#
# RUNNING THIS WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS
#
# How to use:
#
# Run with a physical connection to a chip:
#  - `pytest test_esptool_sdm.py --chip esp32 --port /dev/ttyUSB0 --baud 115200`
#
# where  - --port       - a serial port for esptool.py operation
#        - --chip       - ESP chip name
#        - --baud       - baud rate
#        - --with-trace - trace all interactions (True or False)

from test_esptool import EsptoolTestCase, arg_chip, esptool, pytest


@pytest.mark.skipif(
    arg_chip == "esp8266", reason="ESP8266 does not support Secure Download Mode"
)
class TestSecureDownloadMode(EsptoolTestCase):
    expected_chip_name = esptool.util.expand_chip_name(arg_chip)

    def test_auto_detect(self):
        output = self.run_esptool_error("flash_id", chip="auto")

        if arg_chip in ["esp32", "esp32s2"]:  # no autodetection with get_security_info
            assert "Secure Download Mode is enabled" in output
            assert "Unsupported detection protocol" in output
        else:
            assert "Unsupported detection protocol" not in output
            assert f"Detecting chip type... {self.expected_chip_name}" in output
            assert "Stub loader is not supported in Secure Download Mode" in output
            assert (
                f"Chip is {self.expected_chip_name} in Secure Download Mode" in output
            )

    # Commands not supported in SDM
    def test_sdm_incompatible_commands(self):
        output = self.run_esptool_error("flash_id")  # flash_id
        assert "This command (0xa) is not supported in Secure Download Mode" in output

        output = self.run_esptool_error("read_flash 0 10 out.bin")  # read_flash
        assert "This command (0xe) is not supported in Secure Download Mode" in output

        output = self.run_esptool_error("erase_flash")  # erase_flash
        assert (
            f"{self.expected_chip_name} ROM does not support function erase_flash"
            in output
        )

    # Commands supported in SDM
    def test_sdm_compatible_commands(self):
        output = self.run_esptool("write_flash 0x0 images/one_kb.bin")  # write_flash
        assert "Security features enabled, so not changing any flash settings" in output
        assert "Wrote 1024 bytes" in output
        assert "Hash of data verified." not in output  # Verification not supported

        output = self.run_esptool_error(
            "write_flash --flash_size detect 0x0 images/one_kb.bin"
        )
        assert (
            "Detecting flash size is not supported in secure download mode." in output
        )

        if arg_chip != "esp32":  # esp32 does not support get_security_info
            output = self.run_esptool("get_security_info")  # get_security_info
            assert "Security Information:" in output
