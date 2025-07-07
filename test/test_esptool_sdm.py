# Unit tests (really integration tests) for esptool using the pytest framework
# Uses a device in the Secure Download Mode connected to the serial port.
#
# RUNNING THIS WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS
#
# How to use:
#
# Run with a physical connection to a chip (ESP8266 and ESP32 do not support
# secure download mode):
#  - `pytest test_esptool_sdm.py --chip esp32s2 --port /dev/ttyUSB0 --baud 115200`
#
# where  - --port       - a serial port for esptool operation
#        - --chip       - ESP chip name
#        - --baud       - baud rate
#        - --with-trace - trace all interactions (True or False)

from test_esptool import EsptoolTestCase, arg_chip, esptool, pytest


@pytest.mark.skipif(
    arg_chip in ("esp8266", "esp32"),
    reason="ESP8266 and ESP32 do not support secure download mode",
)
class TestSecureDownloadMode(EsptoolTestCase):
    expected_chip_name = esptool.util.expand_chip_name(arg_chip)

    def test_auto_detect(self):
        output = self.run_esptool("get-security-info", chip="auto")

        assert f"Detecting chip type... {self.expected_chip_name}" in output
        assert (
            f"{'Chip type:':<20}{self.expected_chip_name} "
            "in Secure Download Mode" in output
        )

    # Commands not supported in SDM
    def test_sdm_incompatible_commands(self):
        output = self.run_esptool_error("flash-id")  # flash-id
        assert "The 'flash-id' command is not available" in output

        output = self.run_esptool_error("read-flash 0 10 out.bin")  # read-flash
        assert "The 'read-flash' command is not available" in output

    # Commands supported in SDM
    def test_sdm_compatible_commands(self):
        output = self.run_esptool("write-flash 0x0 images/one_kb.bin")  # write-flash
        assert "Security features enabled, so not changing any flash settings" in output
        assert "Wrote 1024 bytes" in output
        assert "Hash of data verified." not in output  # Verification not supported

        output = self.run_esptool_error(
            "write-flash --flash-size detect 0x0 images/one_kb.bin"
        )
        assert (
            "Detecting flash size is not supported in secure download mode." in output
        )

        output = self.run_esptool("erase-region 0 4096")  # erase-region
        assert "Stub flasher is not supported in Secure Download Mode" in output
        assert "Flash memory region erased successfully" in output

        output = self.run_esptool("get-security-info")
        assert "Security Information:" in output
